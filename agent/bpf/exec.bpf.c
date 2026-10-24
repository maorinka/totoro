// SPDX-License-Identifier: GPL-2.0
/* Wisp exec sensor (eBPF).
 *
 * Captures every successful program execution in the kernel and pushes a
 * complete record (pid, ppid, start times, uid, comm, parent comm, tty,
 * filename, argv) into a ring buffer. Because the data is captured in-kernel
 * at exec time, userspace can drain the ring buffer lazily and in batches
 * without ever racing a short-lived process that has already exited -- the
 * flaw that makes a /proc-reading sensor miss fast processes when it batches.
 *
 * The hook is the sched_process_exec tracepoint, which fires once per
 * successful exec whatever the entry point: execve, execveat, fexecve (glibc
 * execveat with AT_EMPTY_PATH) and memfd-backed programs alike. It runs in the
 * new program's context after the kernel has copied argv onto its stack, so
 * the command line is read in one piece from mm->arg_start..arg_end -- exactly
 * what the program received, not a copy of user memory taken at syscall entry
 * that the caller could still change. Failed exec attempts (for example
 * execvp walking $PATH) are not events.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define ARGSZ      4096   /* bytes of argv captured (NUL-separated) */
#define COMM_LEN   16
#define FNAME_LEN  256
#define NAME_LEN   64
#ifndef AF_INET
#define AF_INET 2
#endif

/* exec_event.flags */
#define EV_TTY        1   /* the process has a controlling terminal */
#define EV_ARGS_TRUNC 2   /* argv was longer than ARGSZ */
#define EV_FDPATH     4   /* executed through a file descriptor (/dev/fd/N) */
#define EV_ARGS_FAULT 8   /* argv could not be read in-kernel (page not present) */

/* Set by userspace before load: the sensor's own tgid, whose outbound
 * connections (to the console) are never policy-checked; and a random
 * 128-bit key for the exec-context hash. The key makes the hash unforgeable
 * to anyone who cannot read BPF state (that needs CAP_BPF/root): a crafted
 * command line cannot be made to collide with a proven-benign one. */
const volatile __u32 self_tgid = 0;
const volatile __u64 sip_k0 = 0, sip_k1 = 0;

/* Variable-length record: userspace receives the header plus arg_len bytes
 * of args. Layout is shared with proc_bpf.c. */
struct exec_event {
	__u32 pid;
	__u32 ppid;
	__u32 uid;
	__u32 arg_len;
	__u64 key;                  /* hash of the whole exec context (see below) */
	__u32 flags;                /* EV_* */
	__u32 pad;
	__u64 start_ns;             /* process start, ns since boot (see task_start_ns) */
	__u64 pstart_ns;            /* the parent's */
	char  comm[COMM_LEN];       /* the kernel's comm for the new program */
	char  pcomm[COMM_LEN];      /* parent's comm */
	char  exe_name[NAME_LEN];   /* executable's dentry name (EV_FDPATH only) */
	char  filename[FNAME_LEN];
	char  args[ARGSZ];          /* argv joined by '\0' -> rendered as spaces by userspace */
};

/* 4 MiB. Records are variable-length: about 400 bytes plus the command line,
 * up to ~4.4 KB with a full 4 KB argv (long compiler command lines in a
 * parallel build). Userspace drains on a coalescing timer and shortens the
 * window when a drain finds the ring filling up (main.c); a record that still
 * does not fit is counted in settings[SET_LOST], never lost silently. */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 22);
} events SEC(".maps");

/* Per-CPU scratch so we don't blow the 512-byte BPF stack. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct exec_event);
} scratch SEC(".maps");

/* settings[0] = sampling divisor N set by the userspace CPU governor (0/1 =
 * forward every exec, the default; N>1 = forward 1-in-N of proven-benign
 * repeats only). settings[1] counts execs dropped by sampling. settings[2] is
 * the current benign generation: bumping it expires every benign entry.
 * settings[3] counts exec records lost because the ring buffer was full. */
#define SET_SAMPLE_N 0
#define SET_DROPS    1
#define SET_GEN      2
#define SET_LOST     3
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 4);
	__type(key, __u32);
	__type(value, __u64);
} settings SEC(".maps");

/* benign[key] = generation marks an exec CONTEXT -- the same program path,
 * the same full argv, uid, tty, parent and grandparent comm -- that userspace
 * has evaluated many times without it ever alerting. Rule verdicts depend on
 * those inputs, so a repeat of such a context is a repeat of a known-benign
 * verdict, and only those repeats are eligible for sampling under load. A
 * command line that differs in any byte is a different key and is always
 * forwarded. Entries expire when the generation is bumped (policy reload,
 * periodic re-validation); LRU eviction bounds the table. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, __u64);
	__type(value, __u64);
} benign SEC(".maps");

/* SipHash-2-4, keyed with sip_k0/sip_k1, absorbed one 64-bit word at a
 * time. Partial words are zero-masked: bytes past a string's end in the
 * per-CPU scratch buffer are left over from earlier events. */
struct sip { __u64 v0, v1, v2, v3; };
#define ROTL(x, b) (((x) << (b)) | ((x) >> (64 - (b))))
static __always_inline void sip_round(struct sip *s)
{
	s->v0 += s->v1; s->v1 = ROTL(s->v1, 13); s->v1 ^= s->v0; s->v0 = ROTL(s->v0, 32);
	s->v2 += s->v3; s->v3 = ROTL(s->v3, 16); s->v3 ^= s->v2;
	s->v0 += s->v3; s->v3 = ROTL(s->v3, 21); s->v3 ^= s->v0;
	s->v2 += s->v1; s->v1 = ROTL(s->v1, 17); s->v1 ^= s->v2; s->v2 = ROTL(s->v2, 32);
}
static __always_inline void sip_block(struct sip *s, __u64 m)
{
	s->v3 ^= m;
	sip_round(s);
	sip_round(s);
	s->v0 ^= m;
}
static __always_inline __u64 sip_final(struct sip *s)
{
	s->v2 ^= 0xff;
	sip_round(s);
	sip_round(s);
	sip_round(s);
	sip_round(s);
	return s->v0 ^ s->v1 ^ s->v2 ^ s->v3;
}
static __always_inline __u64 tail_mask(__u32 rem)
{
	return rem >= 8 ? ~0ULL : (1ULL << (rem * 8)) - 1;
}

/* Kernels before 5.5 call the boot-based start time real_start_time. */
struct task_struct___old {
	__u64 real_start_time;
} __attribute__((preserve_access_index));

/* A process's start time in ns since boot (suspend included) -- the value
 * /proc/<pid>/stat field 22 is derived from (ns / (1e9 / USER_HZ)). It never
 * changes for a process and no two processes that held one pid share it, so
 * userspace re-checks it before signalling a pid taken from this event. */
static __always_inline __u64 task_start_ns(struct task_struct *t)
{
	struct task_struct *g = BPF_CORE_READ(t, group_leader);
	if (bpf_core_field_exists(g->start_boottime))
		return BPF_CORE_READ(g, start_boottime);
	return BPF_CORE_READ((struct task_struct___old *)g, real_start_time);
}

SEC("tracepoint/sched/sched_process_exec")
int wisp_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	__u32 zero = 0;
	struct exec_event *e = bpf_map_lookup_elem(&scratch, &zero);
	if (!e)
		return 0;

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct task_struct *parent = BPF_CORE_READ(task, real_parent);
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->uid = (__u32)bpf_get_current_uid_gid();
	e->ppid = BPF_CORE_READ(parent, tgid);
	e->flags = BPF_CORE_READ(task, signal, tty) ? EV_TTY : 0;
	e->pad = 0;
	e->start_ns = task_start_ns(task);
	e->pstart_ns = task_start_ns(parent);
	__builtin_memset(e->comm, 0, sizeof e->comm);
	bpf_get_current_comm(e->comm, sizeof e->comm);
	__builtin_memset(e->pcomm, 0, sizeof e->pcomm);
	bpf_probe_read_kernel_str(e->pcomm, sizeof e->pcomm, &parent->comm);
	__u64 gcomm[COMM_LEN / 8] = {};   /* word-aligned for the hash below */
	struct task_struct *gparent = BPF_CORE_READ(parent, real_parent);
	bpf_probe_read_kernel_str(gcomm, sizeof gcomm, &gparent->comm);

	/* bprm->filename, as recorded by the tracepoint */
	unsigned int loc = ctx->__data_loc_filename & 0xFFFF;
	long fl = bpf_probe_read_kernel_str(e->filename, sizeof e->filename, (void *)ctx + loc);
	if (fl < 1) {
		e->filename[0] = 0;
		fl = 1;
	}
	e->exe_name[0] = 0;
	if (fl > 8 && e->filename[0] == '/' && e->filename[1] == 'd' && e->filename[2] == 'e' &&
	    e->filename[3] == 'v' && e->filename[4] == '/' && e->filename[5] == 'f' &&
	    e->filename[6] == 'd' && e->filename[7] == '/') {
		/* execveat(fd, "", AT_EMPTY_PATH) / fexecve / memfd: the kernel names
		 * the program /dev/fd/N; keep the file's own name too. */
		const unsigned char *nm = BPF_CORE_READ(task, mm, exe_file, f_path.dentry, d_name.name);
		bpf_probe_read_kernel_str(e->exe_name, sizeof e->exe_name, nm);
		e->flags |= EV_FDPATH;
	}

	/* argv, from the new program's own stack */
	unsigned long as = BPF_CORE_READ(task, mm, arg_start);
	unsigned long ae = BPF_CORE_READ(task, mm, arg_end);
	__u32 len = 0;
	if (ae > as) {
		unsigned long l = ae - as;
		if (l > ARGSZ) {
			l = ARGSZ;
			e->flags |= EV_ARGS_TRUNC;
		}
		len = (__u32)l;
	}
	asm volatile("" : "+r"(len)); /* keep the bound check visible to the verifier */
	if (len > ARGSZ)
		len = ARGSZ;
	if (len && bpf_probe_read_user(e->args, len, (const void *)as) != 0) {
		len = 0;          /* userspace falls back to /proc/<pid>/cmdline */
		e->flags |= EV_ARGS_FAULT;
	}
	e->arg_len = len;

	/* Context key: keyed hash over everything a rule can see about this
	 * exec except the inherited actor -- filename, argv, uid, tty, comm,
	 * parent comm -- plus the grandparent's comm, which separates the same command
	 * run under different launchers (a login shell vs an agent's shell).
	 * Lengths are absorbed too, so field boundaries are unambiguous. */
	struct sip st = {
		.v0 = sip_k0 ^ 0x736f6d6570736575ULL, .v1 = sip_k1 ^ 0x646f72616e646f6dULL,
		.v2 = sip_k0 ^ 0x6c7967656e657261ULL, .v3 = sip_k1 ^ 0x7465646279746573ULL,
	};
	__u32 fn = (__u32)(fl - 1); /* string bytes, without the NUL */
	for (__u32 i = 0; i < FNAME_LEN / 8; i++) {
		__u32 off = i * 8;
		if (off >= fn)
			break;
		sip_block(&st, *(__u64 *)&e->filename[off] & tail_mask(fn - off));
	}
	sip_block(&st, fn);
	for (__u32 i = 0; i < ARGSZ / 8; i++) {
		__u32 off = i * 8;
		if (off >= len)
			break;
		sip_block(&st, *(__u64 *)&e->args[off] & tail_mask(len - off));
	}
	sip_block(&st, len);
	sip_block(&st, (__u64)e->uid | (__u64)(e->flags & (EV_TTY | EV_ARGS_TRUNC | EV_ARGS_FAULT)) << 32);
	sip_block(&st, *(__u64 *)&e->comm[0]);
	sip_block(&st, *(__u64 *)&e->comm[8]);
	sip_block(&st, *(__u64 *)&e->pcomm[0]);
	sip_block(&st, *(__u64 *)&e->pcomm[8]);
	sip_block(&st, gcomm[0]);
	sip_block(&st, gcomm[1]);
	__u64 h = sip_final(&st);
	e->key = h;

	/* Governor sampling: only proven-benign repeats of an exact context are
	 * eligible; any novel context is always forwarded regardless of load. */
	__u32 k_n = SET_SAMPLE_N, k_gen = SET_GEN;
	__u64 *sn = bpf_map_lookup_elem(&settings, &k_n);
	if (sn && *sn > 1) {
		__u64 *gen = bpf_map_lookup_elem(&settings, &k_gen);
		__u64 *b = bpf_map_lookup_elem(&benign, &h);
		if (gen && b && *b == *gen && (bpf_get_prandom_u32() % *sn) != 0) {
			__u32 k_d = SET_DROPS;
			__u64 *dropped = bpf_map_lookup_elem(&settings, &k_d);
			if (dropped)
				__sync_fetch_and_add(dropped, 1);
			return 0;
		}
	}

	__u64 sz = __builtin_offsetof(struct exec_event, args) + len;
	if (sz > sizeof(*e))
		sz = sizeof(*e);
	if (bpf_ringbuf_output(&events, e, sz, 0) != 0) {
		__u32 k_l = SET_LOST;
		__u64 *lost = bpf_map_lookup_elem(&settings, &k_l);
		if (lost)
			__sync_fetch_and_add(lost, 1);
	}
	return 0;
}

/* ---- outbound network connection monitoring (data-flow / API egress) ----
 * A tracepoint on inet_sock_set_state fires on every TCP state change; we
 * capture the transition into SYN_SENT (an outbound connect) with the pid,
 * comm and destination, and push it to a second ring buffer. Userspace
 * applies network policy and attributes the flow to the same actor model as
 * execs. The sensor's own connections (to the console) are skipped here, so
 * a network policy can never make the sensor act against itself.
 */
struct conn_event {
	__u32 pid;
	__u32 uid;
	__u64 start_ns;             /* the connecting process's start (task_start_ns) */
	__u16 dport;
	__u16 family;
	__u32 daddr4;
	__u8  daddr6[16];
	char  comm[COMM_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 18);
} conns SEC(".maps");

SEC("tracepoint/sock/inet_sock_set_state")
int wisp_connect(struct trace_event_raw_inet_sock_set_state *ctx)
{
	/* Only outbound TCP connects: oldstate CLOSE -> newstate SYN_SENT. */
	if (ctx->protocol != IPPROTO_TCP || ctx->newstate != TCP_SYN_SENT)
		return 0;
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	if (self_tgid && tgid == self_tgid)
		return 0;

	struct conn_event *e = bpf_ringbuf_reserve(&conns, sizeof *e, 0);
	if (!e)
		return 0;
	e->pid = tgid;
	e->uid = bpf_get_current_uid_gid();
	e->start_ns = task_start_ns((struct task_struct *)bpf_get_current_task());
	e->dport = ctx->dport;
	e->family = ctx->family;
	if (ctx->family == AF_INET)
		bpf_probe_read_kernel(&e->daddr4, 4, ctx->daddr);
	else
		bpf_probe_read_kernel(e->daddr6, 16, ctx->daddr_v6);
	bpf_get_current_comm(&e->comm, sizeof e->comm);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

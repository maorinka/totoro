/* eBPF-backed exec sensor (primary).
 *
 * Replaces the netlink proc connector with the sched_process_exec
 * tracepoint, which captures the full event -- pid, ppid, uid, parent comm,
 * tty, filename, argv -- in the kernel for every successful exec (execve,
 * execveat, fexecve, memfd programs) and pushes it to a ring buffer.
 * Userspace drains the ring buffer; the data is already captured, so draining
 * lazily/in batches never races a process that has already exited. This is
 * what lets Wisp coalesce wakeups under load (one wakeup drains many events)
 * without the missed-short-lived-process bug a /proc-reading sensor has.
 *
 * No /proc read happens for the exec'ing process itself in the common case,
 * so the per-event syscall count is near zero -- only the ring-buffer consume.
 */
#include "wisp.h"

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "bpf/exec.skel.h"

#define ARGSZ 4096
#define FNAME_LEN 256
#define NAME_LEN 64
#define EV_TTY        1
#define EV_ARGS_TRUNC 2
#define EV_FDPATH     4
#define EV_ARGS_FAULT 8

/* Mirrors struct exec_event in bpf/exec.bpf.c. Records are variable-length:
 * only arg_len bytes of args follow the header. */
struct exec_event {
	uint32_t pid;
	uint32_t ppid;
	uint32_t uid;
	uint32_t arg_len;
	uint64_t key;
	uint32_t flags;
	uint32_t pad;
	char pcomm[16];
	char exe_name[NAME_LEN];
	char filename[FNAME_LEN];
	char args[ARGSZ];
};
#define EV_HDR offsetof(struct exec_event, args)

struct conn_event {
	uint32_t pid;
	uint32_t uid;
	uint16_t dport;
	uint16_t family;
	uint32_t daddr4;
	uint8_t  daddr6[16];
	char comm[16];
};

/* Frequency table: how often each exec CONTEXT key (path + full argv + uid +
 * tty + parent/grandparent comm, hashed in the kernel) has been evaluated and
 * whether it ever alerted. A context seen BENIGN_PROMOTE times with no alert
 * is published to the kernel's benign map so the governor may sample its
 * repeats under load; a context that ever alerts is demoted and pinned out,
 * so it is always forwarded. Any exec whose command line differs from a
 * proven-benign one in a single byte is a different context and is never
 * sampled. The whole set is re-proven after a policy reload and every
 * BENIGN_TTL_S seconds. */
#define FREQ_BITS 14
#define FREQ_SIZE (1u << FREQ_BITS)
#define BENIGN_PROMOTE 12
#define BENIGN_TTL_S 1800
struct freq {
	uint64_t h;
	uint32_t count;
	uint8_t flags;   /* 1=promoted to benign map, 2=ever alerted (pinned) */
};
static struct freq freq_tab[FREQ_SIZE];
static uint64_t benign_gen = 1, benign_since;

static struct exec_bpf *skel;
static struct ring_buffer *rb;
static uint64_t n_conn, n_bad;
static uint64_t n_exec, n_rb;
static pid_t self_pid;
/* Exec-ring bytes consumed by the current drain, and the ring's size: the
 * main loop shortens its coalescing window when a drain finds the ring
 * filling up, so a storm of long command lines cannot overflow it. */
static uint64_t drain_bytes, ring_size;

uint64_t proc_events(void) { return n_exec; }

static int quiet_libbpf(enum libbpf_print_level lvl, const char *f, va_list ap)
{
	if (lvl == LIBBPF_WARN)
		return vfprintf(stderr, f, ap);
	return 0;
}

/* Copy at most srclen bytes of src (stopping at a NUL) into dst[cap]. */
static void ncopy(char *dst, size_t cap, const char *src, size_t srclen)
{
	size_t n = strnlen(src, srclen);
	if (n > cap - 1)
		n = cap - 1;
	memcpy(dst, src, n);
	dst[n] = 0;
}

static void set_setting(uint32_t k, uint64_t v)
{
	if (skel)
		bpf_map__update_elem(skel->maps.settings, &k, sizeof k, &v, sizeof v, 0);
}

/* Forget every proven-benign context: bump the generation the kernel checks
 * (one map write expires them all) and clear the userspace counts. */
void proc_benign_reset(const char *why)
{
	benign_gen++;
	set_setting(2, benign_gen);
	memset(freq_tab, 0, sizeof freq_tab);
	benign_since = now_ms();
	if (why)
		logmsg("bpf: benign-context set cleared (%s); repeats must be re-proven", why);
}

/* Housekeeping: periodic re-validation of the benign set. */
void proc_benign_tick(void)
{
	if (now_ms() - benign_since >= (uint64_t)BENIGN_TTL_S * 1000)
		proc_benign_reset(NULL);
}

/* Does a /proc/<pid>/exe target name the file the kernel saw executed
 * (dentry name `name`, cut at NAME_LEN-1 bytes)? Its basename must be that
 * name, optionally followed by " (deleted)". */
static int exe_matches(const char *target, const char *name)
{
	const char *b = base_name(target);
	size_t l = strlen(name);
	if (!l || strncmp(b, name, l))
		return 0;
	return !b[l] || !strcmp(b + l, " (deleted)") || l == NAME_LEN - 1;
}

/* fexecve/execveat(AT_EMPTY_PATH)/memfd: the kernel calls the program
 * /dev/fd/N. comm is the file's own name (from the kernel). For exe:
 *  - a memfd program has no path of its own: name it exactly as
 *    /proc/<pid>/exe shows it, "/memfd:NAME (deleted)", from the kernel's
 *    record -- deterministic, however soon the process exits or re-execs;
 *  - otherwise use /proc/<pid>/exe while the process still runs that file
 *    (its basename matches the kernel's name), else keep /dev/fd/N. The check
 *    stops a program that re-execs at once from being recorded as the next
 *    program's path. */
static void resolve_fdpath(const struct exec_event *ev, struct proc *p)
{
	char name[NAME_LEN], path[40], buf[MAX_PATH];
	ncopy(name, sizeof name, ev->exe_name, sizeof ev->exe_name);
	if (!strncmp(name, "memfd:", 6)) {
		snprintf(p->exe, sizeof p->exe, "/%s (deleted)", name);
	} else {
		snprintf(path, sizeof path, "/proc/%u/exe", ev->pid);
		ssize_t n = readlink(path, buf, sizeof buf - 1);
		if (n > 0) {
			buf[n] = 0;
			if (!name[0] || exe_matches(buf, name))
				scopy(p->exe, sizeof p->exe, buf);
		}
	}
	if (name[0])
		scopy(p->comm, sizeof p->comm, name);
}

/* One ring-buffer record -> struct proc -> detection pipeline. */
static int on_rb(void *cctx, void *data, size_t sz)
{
	struct exec_event *ev = data;
	struct proc p;
	if (sz < EV_HDR) {
		n_bad++;
		return 0;
	}
	n_exec++;
	drain_bytes += (sz + 8 + 7) & ~(size_t)7; /* record header + 8-byte alignment */

	/* Set every field explicitly instead of a multi-KB memset per event.
	 * scopy NUL-terminates exe/comm; actor_src must start empty (filled by
	 * actor_resolve). */
	p.pid = ev->pid;
	p.ppid = ev->ppid;
	p.uid = ev->uid;
	p.has_tty = (ev->flags & EV_TTY) != 0;
	p.self_classified = 0;
	p.actor = ACTOR_UNKNOWN;
	p.actor_src[0] = 0;
	p.cmd_truncated = (ev->flags & EV_ARGS_TRUNC) != 0;
	/* The ring is mapped read-only: copy with explicit bounds instead of
	 * trusting the kernel's NUL terminators. */
	ncopy(p.pcomm, sizeof p.pcomm, ev->pcomm, sizeof ev->pcomm);
	if (!p.pcomm[0])
		scopy(p.pcomm, sizeof p.pcomm, "?");
	ncopy(p.exe, sizeof p.exe, ev->filename, sizeof ev->filename);
	/* The meaningful "what is running" name is the basename of the program
	 * being executed, matching the connector sensor's semantics. */
	scopy(p.comm, sizeof p.comm, base_name(p.exe));
	if (ev->flags & EV_FDPATH)
		resolve_fdpath(ev, &p);

	/* argv entries are NUL-separated in ev->args; join with spaces. Never
	 * read past what the kernel actually delivered. */
	uint32_t n = ev->arg_len;
	if (n > sz - EV_HDR)
		n = (uint32_t)(sz - EV_HDR);
	if (n > ARGSZ)
		n = ARGSZ;
	size_t out = 0;
	for (uint32_t i = 0; i < n && out < sizeof p.cmd - 1; i++) {
		char c = ev->args[i];
		p.cmd[out++] = c ? c : ' ';
	}
	if (n > sizeof p.cmd - 1)
		p.cmd_truncated = 1;
	if (ev->flags & EV_ARGS_FAULT) {
		/* Rare: the kernel could not read argv in place. Read it from /proc
		 * while the process still exists, and never treat the event as a
		 * provable repeat. */
		char path[40];
		snprintf(path, sizeof path, "/proc/%u/cmdline", ev->pid);
		ssize_t r = read_small(AT_FDCWD, path, p.cmd, sizeof p.cmd);
		out = r > 0 ? (size_t)r : 0;
		for (size_t i = 0; i < out; i++)
			if (!p.cmd[i])
				p.cmd[i] = ' ';
		p.cmd_truncated = 1;
	}
	while (out && p.cmd[out - 1] == ' ')
		out--;
	p.cmd[out] = 0;
	p.cmdlen = out;

	uint64_t before = out_alert_count();
	pipeline_run(&p);
	int alerted = out_alert_count() != before;

	/* Maintain the frequency filter so the governor only ever samples
	 * repeatedly-benign exec contexts. */
	struct freq *f = &freq_tab[(ev->key ^ (ev->key >> 32)) & (FREQ_SIZE - 1)];
	if (f->h != ev->key) {           /* new/evicted slot */
		f->h = ev->key;
		f->count = 0;
		f->flags = 0;
	}
	/* Never provable as a repeat: a context that alerted; argv that was cut
	 * or read from /proc; and a program run through a descriptor
	 * (fexecve/memfd), whose exe and comm -- both rule inputs -- are resolved
	 * here, not hashed in the kernel, so different payloads share the key. */
	if (alerted || p.cmd_truncated || (ev->flags & EV_FDPATH)) {
		if (alerted && !(f->flags & 2)) {
			/* First alert for this slot. The context may still be in the
			 * kernel's benign map even though this slot does not remember
			 * promoting it (the slot was reused by another key since), so
			 * delete unconditionally; repeats of an alert skip this. */
			bpf_map__delete_elem(skel->maps.benign, &ev->key, sizeof ev->key, 0);
			f->flags &= ~1;
		}
		f->flags |= 2;                 /* pin out of benign for this generation */
	} else if (!(f->flags & 2)) {
		if (f->count < BENIGN_PROMOTE) {
			f->count++;
		} else if (!(f->flags & 1)) {
			bpf_map__update_elem(skel->maps.benign, &ev->key, sizeof ev->key,
			                     &benign_gen, sizeof benign_gen, 0);
			f->flags |= 1;
		}
	}
	return 0;
}

/* libbpf resolves the tracepoint's perf id through tracefs. It is mounted by
 * default on real systems; mount it if a minimal container left it out. */
static void ensure_tracefs(void)
{
	struct stat st;
	if (stat("/sys/kernel/tracing/events/sched/sched_process_exec/id", &st) == 0)
		return;
	mount("nodev", "/sys/kernel/tracing", "tracefs", 0, NULL);
}

/* One outbound-connection record -> actor attribution -> network policy. */
static int on_conn(void *cctx, void *data, size_t sz)
{
	struct conn_event *ev = data;
	if (sz < sizeof *ev)
		return 0;
	/* The sensor's own connections (the console link) are never subject to
	 * network policy: a deny that happens to match them must not make the
	 * sensor kill itself. The kernel side filters them too. */
	if ((pid_t)ev->pid == self_pid)
		return 0;
	n_conn++;
	char src[40];
	enum actor a = actor_cached(ev->pid, src, sizeof src);
	int is_v6 = ev->family != 2; /* AF_INET == 2 */
	uint32_t daddr = ntohl(ev->daddr4);
	int dport = ev->dport; /* tracepoint stores host order */

	char ipstr[INET6_ADDRSTRLEN] = "";
	if (is_v6)
		inet_ntop(AF_INET6, ev->daddr6, ipstr, sizeof ipstr);
	else
		inet_ntop(AF_INET, &ev->daddr4, ipstr, sizeof ipstr);

	int verdict = netpolicy_check(daddr, dport, (int)a, is_v6, ev->pid);
	if (telemetry_on)
		out_flow(ev->pid, ev->uid, ev->comm, a, src, ipstr, dport,
		         verdict == NP_DENY ? "deny" : verdict == NP_RATE ? "rate" : "allow");
	if (verdict != NP_ALLOW) {
		struct proc p;
		memset(&p, 0, offsetof(struct proc, cmd));
		p.pid = ev->pid; p.uid = ev->uid; p.actor = a; p.cmd[0] = 0; p.cmdlen = 0;
		ncopy(p.comm, sizeof p.comm, ev->comm, sizeof ev->comm);
		snprintf(p.actor_src, sizeof p.actor_src, "%s", src);
		char extra[128];
		snprintf(extra, sizeof extra, "\"dest\":\"%s\",\"dport\":%d", ipstr, dport);
		int rate = verdict == NP_RATE;
		const char *act = rate ? "would-throttle" : "would-block";
		if (cfg.mode == MODE_ENFORCE) {
			respond_kill(ev->pid, rate ? "net-rate" : "net-policy"); /* inline correction */
			act = "blocked";
		}
		if (rate)
			out_alert("NET-RATE", "T1498", "Outbound connection rate over API limit",
			          SEV_MEDIUM, act, &p, extra);
		else
			out_alert("NET-POLICY", "T1071", "Outbound connection denied by data-flow policy",
			          SEV_HIGH, act, &p, extra);
	}
	return 0;
}

int proc_open(void)
{
	libbpf_set_print(quiet_libbpf);
	ensure_tracefs();
	self_pid = getpid();
	skel = exec_bpf__open();
	if (!skel) {
		logmsg("bpf: open failed: %s", strerror(errno));
		return -1;
	}
	skel->rodata->self_tgid = (uint32_t)self_pid;
	/* Random key for the in-kernel exec-context hash (see exec.bpf.c). */
	uint64_t k[2];
	if (getrandom(k, sizeof k, 0) != sizeof k) {
		logmsg("bpf: getrandom failed: %s", strerror(errno));
		goto fail;
	}
	skel->rodata->sip_k0 = k[0];
	skel->rodata->sip_k1 = k[1];
	if (exec_bpf__load(skel)) {
		logmsg("bpf: load/verify failed: %s", strerror(errno));
		goto fail;
	}
	if (exec_bpf__attach(skel)) {
		logmsg("bpf: attach failed: %s", strerror(errno));
		goto fail;
	}
	rb = ring_buffer__new(bpf_map__fd(skel->maps.events), on_rb, NULL, NULL);
	if (!rb) {
		logmsg("bpf: ring buffer setup failed");
		goto fail;
	}
	/* Add the outbound-connection ring to the same manager so one epoll fd
	 * and one consume() drain both exec and network-flow events. */
	if (ring_buffer__add(rb, bpf_map__fd(skel->maps.conns), on_conn, NULL))
		logmsg("bpf: connection ring not added (network monitoring off)");
	else
		logmsg("bpf: outbound-connection monitoring active");
	set_setting(2, benign_gen);
	benign_since = now_ms();
	ring_size = bpf_map__max_entries(skel->maps.events);
	logmsg("bpf: exec tracepoint attached, ring buffer ready");
	return ring_buffer__epoll_fd(rb);
fail:
	exec_bpf__destroy(skel);
	skel = NULL;
	return -1;
}

/* Governor hook: set the in-kernel sampling divisor (1 = forward all). */
void proc_set_sampling(unsigned n)
{
	set_setting(0, n);
}

static uint64_t get_setting(uint32_t k)
{
	__u64 v = 0;
	if (skel)
		bpf_map__lookup_elem(skel->maps.settings, &k, sizeof k, &v, sizeof v, 0);
	return v;
}

/* Number of execs the kernel dropped due to governor sampling. */
uint64_t proc_sampled_drops(void) { return get_setting(1); }

/* Number of exec records the kernel could not queue: the ring was full. */
uint64_t proc_ring_lost(void) { return get_setting(3); }

/* Fraction of the exec ring the last proc_handle() drained (0..1). */
double proc_ring_fill(void)
{
	return ring_size ? (double)drain_bytes / (double)ring_size : 0;
}

/* Drain everything currently in the ring buffer. Non-blocking; returns the
 * number of records consumed so the caller can tell active from idle. */
int proc_handle(int fd)
{
	(void)fd;
	uint64_t before = n_exec;
	drain_bytes = 0;
	int rc = ring_buffer__consume(rb);
	if (rc < 0)
		return 0;
	n_rb++;
	return (int)(n_exec - before);
}

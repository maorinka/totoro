/* Process telemetry via the netlink proc connector.
 *
 * The proc connector multicasts fork/exec/exit/uid/... events for every
 * task on the system. We attach a classic BPF filter to the socket so the
 * kernel drops everything except PROC_EVENT_EXEC before it is queued: a
 * fork storm or thread churn never wakes the agent.
 */
#include "wisp.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/cn_proc.h>
#include <linux/connector.h>
#include <linux/filter.h>
#include <linux/netlink.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

static uint64_t n_exec, n_lost, n_gone;

uint64_t proc_events(void) { return n_exec; }

/* Offsets inside one datagram: nlmsghdr | cn_msg | proc_event */
#define OFF_WHAT (NLMSG_HDRLEN + sizeof(struct cn_msg) + offsetof(struct proc_event, what))

int proc_open(void)
{
	int fd = socket(AF_NETLINK, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, NETLINK_CONNECTOR);
	if (fd < 0)
		return -1;

	struct sock_filter code[] = {
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF_WHAT),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, htonl(PROC_EVENT_EXEC), 0, 1),
		BPF_STMT(BPF_RET | BPF_K, 0xffffffff),
		BPF_STMT(BPF_RET | BPF_K, 0),
	};
	struct sock_fprog prog = { .len = sizeof code / sizeof code[0], .filter = code };
	if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof prog) < 0)
		logmsg("proc: BPF filter not attached (%s); filtering in userspace", strerror(errno));

	int rcv = 4 << 20;
	setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &rcv, sizeof rcv);

	struct sockaddr_nl sa = { .nl_family = AF_NETLINK, .nl_groups = CN_IDX_PROC, .nl_pid = 0 };
	if (bind(fd, (struct sockaddr *)&sa, sizeof sa) < 0)
		goto fail;

	struct {
		struct nlmsghdr nl;
		struct cn_msg cn;
		enum proc_cn_mcast_op op;
	} __attribute__((packed)) req = {
		.nl = { .nlmsg_len = sizeof req, .nlmsg_type = NLMSG_DONE, .nlmsg_pid = getpid() },
		.cn = { .id = { .idx = CN_IDX_PROC, .val = CN_VAL_PROC }, .len = sizeof(enum proc_cn_mcast_op) },
		.op = PROC_CN_MCAST_LISTEN,
	};
	if (send(fd, &req, sizeof req, 0) < 0)
		goto fail;
	return fd;
fail:
	close(fd);
	return -1;
}

/* Read the handful of /proc files we need for one process.
 *
 * Kept deliberately lean: open /proc/<pid>/stat once, take the process
 * uid from fstat() on that very fd (no separate directory open), then one
 * readlink for exe and one open/read for cmdline. ~8 syscalls total.
 */
int proc_fill(pid_t pid, struct proc *p)
{
	char path[40], buf[1024];
	memset(p, 0, offsetof(struct proc, cmd));
	p->cmd[0] = 0;
	p->cmdlen = 0;
	p->pid = pid;

	/* stat: pid (comm) state ppid pgrp session tty_nr ... */
	snprintf(path, sizeof path, "/proc/%d/stat", pid);
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	struct stat st;
	if (fstat(fd, &st) == 0)
		p->uid = st.st_uid;      /* owner of /proc/<pid>/stat == process uid */
	ssize_t n = read(fd, buf, sizeof buf - 1);
	close(fd);
	if (n <= 0)
		return -1;
	buf[n] = 0;
	char *l = strchr(buf, '('), *r = strrchr(buf, ')');
	if (l && r && r > l) {
		size_t cn = r - l - 1;
		if (cn > 16)
			cn = 16;
		memcpy(p->comm, l + 1, cn);
		p->comm[cn] = 0;
		int ppid = 0, tty = 0;
		char state;
		if (sscanf(r + 2, "%c %d %*d %*d %d", &state, &ppid, &tty) == 3) {
			p->ppid = ppid;
			p->has_tty = tty != 0;
		}
	}

	snprintf(path, sizeof path, "/proc/%d/exe", pid);
	n = readlink(path, p->exe, sizeof p->exe - 1);
	p->exe[n > 0 ? n : 0] = 0;

	snprintf(path, sizeof path, "/proc/%d/cmdline", pid);
	n = read_small(AT_FDCWD, path, p->cmd, sizeof p->cmd);
	if (n > 0) {
		while (n > 0 && p->cmd[n - 1] == 0)
			n--;
		for (ssize_t i = 0; i < n; i++)
			if (!p->cmd[i])
				p->cmd[i] = ' ';
		p->cmd[n] = 0;
		p->cmdlen = n;
	}
	return p->comm[0] ? 0 : -1;
}

static void on_exec(pid_t pid)
{
	struct proc p;
	n_exec++;
	if (proc_fill(pid, &p) < 0) {
		n_gone++;      /* exited before we looked: nothing left to read */
		return;
	}
	pipeline_run(&p);
}

/* Drain all currently-queued datagrams. Returns the number of exec events
 * processed, so the caller can tell an active window from an empty one. */
/* The connector sensor has no in-kernel sampling; the governor falls back to
 * telemetry-shedding and coalescing only. */
void proc_set_sampling(unsigned n) { (void)n; }
uint64_t proc_sampled_drops(void) { return 0; }

int proc_handle(int fd)
{
	char buf[8192] __attribute__((aligned(NLMSG_ALIGNTO)));
	int handled = 0;
	for (;;) {
		ssize_t len = recv(fd, buf, sizeof buf, 0);
		if (len < 0) {
			if (errno == ENOBUFS) {
				n_lost++;
				continue;
			}
			return handled; /* EAGAIN: socket drained */
		}
		for (struct nlmsghdr *nh = (struct nlmsghdr *)buf; NLMSG_OK(nh, (size_t)len);
		     nh = NLMSG_NEXT(nh, len)) {
			struct cn_msg *cn = NLMSG_DATA(nh);
			struct proc_event *ev = (struct proc_event *)cn->data;
			if (ev->what == PROC_EVENT_EXEC) {
				on_exec(ev->event_data.exec.process_tgid);
				handled++;
			}
		}
	}
}

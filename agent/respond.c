/* Response actions: kill a process tree, quarantine a binary.
 * Userspace only -- SIGKILL, and a copy of the executable into a 0700
 * quarantine dir followed by removal of the original. No kernel module,
 * nothing that would upset an OS integrity control.
 *
 * Both actions treat everything the exec event reported as untrusted: the
 * path is whatever string the process passed to execve, and the process can
 * rename, replace or symlink it before the sensor gets to it. So:
 *  - the process (and every descendant) is frozen with SIGSTOP before it is
 *    killed, so its tree can be enumerated before children are reparented;
 *  - the file to quarantine is identified by the kernel's own reference to
 *    the running program (/proc/<pid>/exe) while the process is frozen, and
 *    located through the process's own root directory (its mount namespace:
 *    containers, PrivateTmp), walking every path component with O_NOFOLLOW;
 *  - only a regular file owned by the user who ran it (or anything root ran)
 *    is ever touched, never a root-owned file in a directory only root can
 *    write (an OS binary), and the original is unlinked only after its directory
 *    entry is re-checked to be that same inode. Nothing is ever chmod'ed,
 *    renamed or read through a path string that could be a symlink.
 */
#include "wisp.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

/* A file larger than this is not copied (the copy runs on the event loop);
 * the process is still killed and the alert says why. */
#define QUARANTINE_MAX ((off_t)256 << 20)

/* ---- process tree ------------------------------------------------------- */

static int pidfd_open_(pid_t pid)
{
#ifdef SYS_pidfd_open
	return (int)syscall(SYS_pidfd_open, pid, 0);
#else
	(void)pid;
	errno = ENOSYS;
	return -1;
#endif
}

/* Signal through the pidfd when there is one: it names one process, so a
 * recycled pid can never receive the signal meant for the original. */
static int sig_send(int pfd, pid_t pid, int sig)
{
#ifdef SYS_pidfd_send_signal
	if (pfd >= 0)
		return (int)syscall(SYS_pidfd_send_signal, pfd, sig, NULL, 0);
#endif
	return kill(pid, sig);
}

/* Small open-addressing set of pids. */
struct pidset {
	pid_t *v;
	size_t cap, n;
};

static int ps_has(const struct pidset *s, pid_t p)
{
	if (!s->cap)
		return 0;
	for (size_t i = ((uint32_t)p * 2654435761u) & (s->cap - 1);; i = (i + 1) & (s->cap - 1)) {
		if (!s->v[i])
			return 0;
		if (s->v[i] == p)
			return 1;
	}
}

static int ps_add(struct pidset *s, pid_t p)
{
	if ((s->n + 1) * 2 > s->cap) {
		size_t nc = s->cap ? s->cap * 2 : 64;
		pid_t *nv = calloc(nc, sizeof *nv);
		if (!nv)
			return -1;
		for (size_t i = 0; i < s->cap; i++)
			if (s->v[i]) {
				size_t j = ((uint32_t)s->v[i] * 2654435761u) & (nc - 1);
				while (nv[j])
					j = (j + 1) & (nc - 1);
				nv[j] = s->v[i];
			}
		free(s->v);
		s->v = nv;
		s->cap = nc;
	}
	size_t i = ((uint32_t)p * 2654435761u) & (s->cap - 1);
	while (s->v[i]) {
		if (s->v[i] == p)
			return 0;
		i = (i + 1) & (s->cap - 1);
	}
	s->v[i] = p;
	s->n++;
	return 1;
}

/* Field 22 of /proc/<pid>/stat: start time in clock ticks since boot. It
 * survives exec and is the same for no two processes that held a pid. */
static unsigned long long start_ticks(pid_t pid)
{
	char path[48], buf[1024];
	snprintf(path, sizeof path, "/proc/%d/stat", pid);
	if (read_small(AT_FDCWD, path, buf, sizeof buf) <= 0)
		return 0;
	char *r = strrchr(buf, ')');
	unsigned long long st = 0;
	if (!r || sscanf(r + 2, "%*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %*u %*u %*d %*d %*d %*d %*d %*d %llu",
	                 &st) != 1)
		return 0;
	return st;
}

struct ktree {
	pid_t root;
	int pfd;              /* pidfd of root, or -1 (kernel without pidfd) */
	struct pidset m;      /* root + every descendant found, all stopped */
};

/* One /proc sweep: add (and SIGSTOP) every process whose parent is already
 * in the set. Returns how many were added. The sensor itself, init and
 * kernel threads are never members. */
static size_t tree_sweep(struct ktree *t)
{
	DIR *d = opendir("/proc");
	if (!d)
		return 0;
	pid_t self = getpid();
	size_t n = 0, cap = 0;
	pid_t (*tab)[2] = NULL;
	struct dirent *de;
	char path[48], buf[512];
	while ((de = readdir(d))) {
		if (de->d_name[0] < '1' || de->d_name[0] > '9')
			continue;
		pid_t c = (pid_t)atoi(de->d_name);
		if (c <= 1 || c == self || ps_has(&t->m, c))
			continue;
		snprintf(path, sizeof path, "/proc/%d/stat", c);
		if (read_small(AT_FDCWD, path, buf, sizeof buf) <= 0)
			continue;
		char *r = strrchr(buf, ')');
		int ppid = 0;
		if (!r || sscanf(r + 2, "%*c %d", &ppid) != 1 || ppid <= 0)
			continue;
		if (n == cap) {
			size_t nc = cap ? cap * 2 : 256;
			void *nt = realloc(tab, nc * sizeof *tab);
			if (!nt)
				break;
			tab = nt;
			cap = nc;
		}
		tab[n][0] = c;
		tab[n][1] = (pid_t)ppid;
		n++;
	}
	closedir(d);
	/* Fixed point over the snapshot: a grandchild may be listed before its
	 * parent. */
	size_t added = 0;
	for (int changed = 1; changed;) {
		changed = 0;
		for (size_t i = 0; i < n; i++) {
			if (!tab[i][0] || !ps_has(&t->m, tab[i][1]))
				continue;
			if (ps_add(&t->m, tab[i][0]) > 0) {
				kill(tab[i][0], SIGSTOP); /* no more forks from it */
				added++;
				changed = 1;
			}
			tab[i][0] = 0;
		}
	}
	free(tab);
	return added;
}

/* Freeze pid and its whole tree. expect_start, when non-zero, is the start
 * time the caller saw for this pid (field 22 of /proc/<pid>/stat); a pid now
 * held by another process is left alone. Returns 0, or -1 with errno set. */
static int tree_begin(struct ktree *t, pid_t pid, unsigned long long expect_start)
{
	memset(t, 0, sizeof *t);
	t->root = pid;
	t->pfd = -1;
	if (pid <= 1 || pid == getpid()) {
		errno = EPERM; /* never init, never the sensor itself */
		return -1;
	}
	t->pfd = pidfd_open_(pid);
	if (t->pfd < 0 && errno == ESRCH)
		return -1;
	if (expect_start && start_ticks(pid) != expect_start) {
		if (t->pfd >= 0)
			close(t->pfd);
		t->pfd = -1;
		errno = ESRCH; /* the process exited and its pid was reused */
		return -1;
	}
	if (sig_send(t->pfd, pid, SIGSTOP) < 0) {
		int e = errno;
		if (t->pfd >= 0)
			close(t->pfd);
		t->pfd = -1;
		errno = e;
		return -1;
	}
	if (ps_add(&t->m, pid) < 0) {
		sig_send(t->pfd, pid, SIGKILL);
		if (t->pfd >= 0)
			close(t->pfd);
		t->pfd = -1;
		errno = ENOMEM;
		return -1;
	}
	/* Repeat until a sweep finds nobody new: a child forked between two
	 * sweeps is caught (and stopped) by the next one. */
	for (int round = 0; round < 16 && tree_sweep(t); round++)
		;
	return 0;
}

/* SIGKILL everything tree_begin froze. Returns the root's kill result. */
static int tree_finish(struct ktree *t, const char *why)
{
	int rc = sig_send(t->pfd, t->root, SIGKILL), e = errno;
	size_t kids = 0;
	for (size_t i = 0; i < t->m.cap; i++) {
		pid_t c = t->m.v[i];
		if (c && c != t->root) {
			kill(c, SIGKILL);
			kids++;
		}
	}
	if (rc == 0)
		logmsg("kill pid=%d (%s): ok, %zu descendant(s)", t->root, why, kids);
	else
		logmsg("kill pid=%d (%s): %s", t->root, why, strerror(e));
	if (t->pfd >= 0)
		close(t->pfd);
	free(t->m.v);
	memset(t, 0, sizeof *t);
	t->pfd = -1;
	errno = e;
	return rc;
}

int respond_kill_if(pid_t pid, unsigned long long expect_start, const char *why)
{
	struct ktree t;
	if (tree_begin(&t, pid, expect_start) < 0) {
		logmsg("kill pid=%d (%s): %s", pid, why,
		       errno == EPERM && (pid <= 1 || pid == getpid()) ? "refused (init or the sensor itself)"
		                                                       : strerror(errno));
		return -1;
	}
	return tree_finish(&t, why);
}

/* Kill pid and every process descended from it. */
int respond_kill(pid_t pid, const char *why) { return respond_kill_if(pid, 0, why); }

/* ---- quarantine ----------------------------------------------------------- */

/* Strip a trailing " (deleted)" (as /proc/<pid>/exe shows an unlinked file)
 * and return the last path component. */
static void exe_name(const char *path, char *out, size_t cap)
{
	scopy(out, cap, base_name(path));
	size_t l = strlen(out), dl = sizeof " (deleted)" - 1;
	if (l > dl && !strcmp(out + l - dl, " (deleted)"))
		out[l - dl] = 0;
}

/* Open the directory holding path's last component, starting at dirfd
 * (absolute paths) and refusing symlinks, "..", and anything that is not a
 * directory along the way. The last component is copied to base. Returns
 * an O_PATH directory fd, or -1 with errno set. */
static int walk_parent(int startfd, const char *path, char *base, size_t basecap)
{
	char tmp[MAX_PATH];
	if (strlen(path) >= sizeof tmp) {
		errno = ENAMETOOLONG;
		return -1;
	}
	scopy(tmp, sizeof tmp, path);
	char *last = strrchr(tmp, '/');
	const char *leaf = last ? last + 1 : tmp;
	if (!*leaf || !strcmp(leaf, ".") || !strcmp(leaf, "..") || strlen(leaf) >= basecap) {
		errno = EINVAL;
		return -1;
	}
	scopy(base, basecap, leaf);
	int fd = fcntl(startfd, F_DUPFD_CLOEXEC, 0);
	if (fd < 0 || !last)
		return fd;
	*last = 0;
	char *save = NULL;
	for (char *c = strtok_r(tmp, "/", &save); c; c = strtok_r(NULL, "/", &save)) {
		if (!strcmp(c, "."))
			continue;
		if (!strcmp(c, "..")) { /* could climb out of the process's root */
			close(fd);
			errno = EINVAL;
			return -1;
		}
		int nfd = openat(fd, c, O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
		int e = errno;
		close(fd);
		if (nfd < 0) {
			errno = e;
			return -1;
		}
		fd = nfd;
	}
	return fd;
}

static int same_file(const struct stat *a, const struct stat *b)
{
	return a->st_dev == b->st_dev && a->st_ino == b->st_ino;
}

/* Does dirfd/base (not following a symlink) name the inode st describes? */
static int entry_is(int dirfd, const char *base, const struct stat *st)
{
	struct stat cur;
	return fstatat(dirfd, base, &cur, AT_SYMLINK_NOFOLLOW) == 0 && same_file(&cur, st);
}

/* The real uid of a running process (the event's uid is the one at exec
 * time; for the connector sensor it is the effective one). */
static int real_uid(pid_t pid, uid_t *out)
{
	char path[48], buf[2048];
	snprintf(path, sizeof path, "/proc/%d/status", pid);
	if (read_small(AT_FDCWD, path, buf, sizeof buf) <= 0)
		return -1;
	char *u = strstr(buf, "\nUid:");
	unsigned v;
	if (!u || sscanf(u + 5, "%u", &v) != 1)
		return -1;
	*out = (uid_t)v;
	return 0;
}

struct qsrc {
	int fd;                 /* open for reading: the file to quarantine */
	int dirfd;              /* its directory, -1 when it has no entry left */
	char base[NAME_MAX + 1];
	struct stat st;
	char path[MAX_PATH];    /* for messages */
};

static void qsrc_close(struct qsrc *q)
{
	if (q->fd >= 0)
		close(q->fd);
	if (q->dirfd >= 0)
		close(q->dirfd);
	q->fd = q->dirfd = -1;
}

/* Find the file the process is running (or, when that cannot be tied to the
 * event, the regular file at the event's path). alive: the process is
 * frozen, so its /proc entries are usable. */
static int find_source(const struct proc *p, int alive, struct qsrc *q, char *err, size_t errlen)
{
	char path[64], xpath[MAX_PATH] = "", ename[NAME_MAX + 1];
	int rootfd = -1, cwdfd = -1, rc = -1;
	q->fd = q->dirfd = -1;
	q->path[0] = 0;

	/* The kernel names a process after the file it was started from (its
	 * comm, cut at 15 bytes). When that is not the executable's name, the
	 * program was a script run through an interpreter (and the connector
	 * sensor reports the interpreter as exe), or it renamed itself: either
	 * way the file to quarantine cannot be told apart from its interpreter. */
	exe_name(p->exe, ename, sizeof ename);
	if (strncmp(p->comm, ename, 15)) {
		snprintf(err, errlen, "cannot tell which file '%s' was started from (exe %s)", p->comm, p->exe);
		return -1;
	}

	if (alive) {
		snprintf(path, sizeof path, "/proc/%d/root", p->pid);
		rootfd = open(path, O_PATH | O_DIRECTORY | O_CLOEXEC);
		snprintf(path, sizeof path, "/proc/%d/cwd", p->pid);
		cwdfd = open(path, O_PATH | O_DIRECTORY | O_CLOEXEC);
	}
	if (rootfd < 0)
		rootfd = open("/", O_PATH | O_DIRECTORY | O_CLOEXEC);
	if (rootfd < 0) {
		snprintf(err, errlen, "cannot open the root directory: %s", strerror(errno));
		goto out;
	}

	/* 1. The running program itself, when it is the file the event named:
	 *    the same name, or the event's path leads (through links) to this
	 *    very inode. For a script /proc/<pid>/exe is the interpreter, and a
	 *    process that exec'd again since is running something else. */
	if (alive) {
		snprintf(path, sizeof path, "/proc/%d/exe", p->pid);
		ssize_t n = readlink(path, xpath, sizeof xpath - 1);
		xpath[n > 0 ? n : 0] = 0;
		if (n > 0 && xpath[0] == '/') {
			q->fd = open(path, O_RDONLY | O_CLOEXEC | O_NOCTTY);
			if (q->fd >= 0 && fstat(q->fd, &q->st) < 0) {
				close(q->fd);
				q->fd = -1;
			}
		}
		char a[NAME_MAX + 1];
		exe_name(xpath, a, sizeof a);
		if (q->fd >= 0 && strcmp(a, ename)) {
			/* Identity only: a stat through the event's path, never an
			 * open, so a link there can lead nowhere harmful. */
			struct stat est;
			const char *rel = p->exe;
			int start = cwdfd;
			if (rel[0] == '/') {
				start = rootfd;
				while (*rel == '/')
					rel++;
			}
			if (start < 0 || !*rel || fstatat(start, rel, &est, 0) < 0 || !same_file(&est, &q->st)) {
				close(q->fd);
				q->fd = -1;
			}
		}
	}
	if (q->fd >= 0) {
		/* Locate its directory entry: the kernel's current path for it
		 * first (it tracks renames), then the event's. Either must name
		 * exactly this inode. */
		const char *cand[2] = { xpath, p->exe };
		for (int i = 0; i < 2 && q->dirfd < 0; i++) {
			const char *c = cand[i];
			int start = c[0] == '/' ? rootfd : cwdfd;
			if (!c[0] || start < 0)
				continue;
			int dfd = walk_parent(start, c, q->base, sizeof q->base);
			if (dfd >= 0 && entry_is(dfd, q->base, &q->st)) {
				q->dirfd = dfd;
				scopy(q->path, sizeof q->path, c);
			} else if (dfd >= 0) {
				close(dfd);
			}
		}
		if (q->dirfd < 0) {
			if (q->st.st_nlink > 0) {
				snprintf(err, errlen, "the running executable (%s) is not at a path that can be verified",
				         xpath);
				goto out;
			}
			scopy(q->path, sizeof q->path, xpath); /* already unlinked: keep a copy only */
			exe_name(xpath, q->base, sizeof q->base);
		}
	} else {
		/* 2. The event's path, as a regular file reached without symlinks. */
		const char *c = p->exe;
		int start = c[0] == '/' ? rootfd : cwdfd;
		if (start < 0) {
			snprintf(err, errlen, "relative path and the process has exited");
			goto out;
		}
		q->dirfd = walk_parent(start, c, q->base, sizeof q->base);
		if (q->dirfd < 0) {
			snprintf(err, errlen, "cannot reach %s without following a link: %s", c, strerror(errno));
			goto out;
		}
		struct stat lst;
		if (fstatat(q->dirfd, q->base, &lst, AT_SYMLINK_NOFOLLOW) < 0) {
			snprintf(err, errlen, "%s: %s", c, strerror(errno));
			goto out;
		}
		if (S_ISLNK(lst.st_mode)) {
			snprintf(err, errlen, "%s is a symbolic link", c);
			goto out;
		}
		if (!S_ISREG(lst.st_mode)) {
			snprintf(err, errlen, "%s is not a regular file", c);
			goto out;
		}
		/* O_NONBLOCK: should the entry be swapped for a FIFO in between,
		 * the open cannot hang the sensor; the inode check rejects it. */
		q->fd = openat(q->dirfd, q->base, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_NOCTTY | O_CLOEXEC);
		if (q->fd < 0 || fstat(q->fd, &q->st) < 0 || !same_file(&q->st, &lst)) {
			snprintf(err, errlen, "%s changed while it was being opened", c);
			goto out;
		}
		scopy(q->path, sizeof q->path, c);
	}

	if (!S_ISREG(q->st.st_mode)) {
		snprintf(err, errlen, "%s is not a regular file", q->path);
		goto out;
	}
	/* Never let one user's exec make the sensor remove someone else's
	 * file (a setuid tool, another user's program): only the file's owner
	 * running it, or root, counts. */
	uid_t ruid = p->uid;
	if (alive)
		real_uid(p->pid, &ruid);
	if ((q->st.st_uid != p->uid && p->uid != 0) || (q->st.st_uid != ruid && ruid != 0)) {
		snprintf(err, errlen, "%s is owned by uid %u, not by the uid that ran it (%u)", q->path,
		         (unsigned)q->st.st_uid, (unsigned)(p->uid ? p->uid : ruid));
		goto out;
	}
	if (q->st.st_size > QUARANTINE_MAX) {
		snprintf(err, errlen, "%s is larger than %lld MiB", q->path, (long long)(QUARANTINE_MAX >> 20));
		goto out;
	}
	/* Never remove an operating-system file. A root-owned file in a
	 * directory only root can write (/usr/bin, /bin, /sbin, /usr/lib, ...)
	 * was put there by root or a package manager; a rule that matches root
	 * running it must not take the host's tools away. Nor is a root-owned
	 * file with other hard links touched: its mode is shared with names
	 * that may be system files. The process is still killed. */
	if (q->st.st_uid == 0 && q->dirfd >= 0) {
		struct stat dirst;
		if (fstat(q->dirfd, &dirst) < 0 ||
		    (dirst.st_uid == 0 && !(dirst.st_mode & (S_IWGRP | S_IWOTH)))) {
			snprintf(err, errlen, "%s is a system file (root-owned, in a directory only root can write): left in place",
			         q->path);
			goto out;
		}
		if (q->st.st_nlink > 1) {
			snprintf(err, errlen, "%s is root-owned and has %lu other hard link(s): left in place", q->path,
			         (unsigned long)(q->st.st_nlink - 1));
			goto out;
		}
	}
	rc = 0;
out:
	if (rootfd >= 0)
		close(rootfd);
	if (cwdfd >= 0)
		close(cwdfd);
	if (rc < 0)
		qsrc_close(q);
	return rc;
}

/* The sensor's quarantine directory: state_dir/quarantine, 0700, ours. */
static int open_qdir(char *err, size_t errlen)
{
	if (mkdir(cfg.state_dir, 0700) && errno != EEXIST) {
		snprintf(err, errlen, "cannot create %s: %s", cfg.state_dir, strerror(errno));
		return -1;
	}
	int sfd = open(cfg.state_dir, O_DIRECTORY | O_CLOEXEC);
	if (sfd < 0) {
		snprintf(err, errlen, "cannot open %s: %s", cfg.state_dir, strerror(errno));
		return -1;
	}
	if (mkdirat(sfd, "quarantine", 0700) && errno != EEXIST) {
		snprintf(err, errlen, "cannot create the quarantine directory: %s", strerror(errno));
		close(sfd);
		return -1;
	}
	int qfd = openat(sfd, "quarantine", O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
	close(sfd);
	struct stat st;
	if (qfd < 0 || fstat(qfd, &st) < 0 || st.st_uid != geteuid() || (st.st_mode & 077)) {
		snprintf(err, errlen, "the quarantine directory is missing, not ours, or not private");
		if (qfd >= 0)
			close(qfd);
		return -1;
	}
	return qfd;
}

static int copy_fd(int in, int out, off_t size)
{
	off_t off = 0;
	while (off < size) {
		ssize_t n = sendfile(out, in, &off, (size_t)(size - off));
		if (n > 0)
			continue;
		if (n == 0)
			return 0; /* the file shrank: keep what there is */
		if (errno == EINTR)
			continue;
		if (errno != EINVAL && errno != ENOSYS)
			return -1;
		char buf[65536]; /* sendfile not supported here: plain copy */
		while (off < size) {
			ssize_t r = pread(in, buf, sizeof buf, off);
			if (r < 0 && errno == EINTR)
				continue;
			if (r <= 0)
				return r < 0 ? -1 : 0;
			for (ssize_t w = 0; w < r;) {
				ssize_t k = write(out, buf + w, (size_t)(r - w));
				if (k < 0 && errno == EINTR)
					continue;
				if (k <= 0)
					return -1;
				w += k;
			}
			off += r;
		}
	}
	return 0;
}

/* Kill p's process tree and quarantine the executable it ran. *kill_rc gets
 * the kill result. On success dst holds the quarantined copy's path;
 * otherwise err says why the file was left in place. */
int respond_quarantine(const struct proc *p, const char *why, int *kill_rc, char *dst, size_t dstlen,
                       char *err, size_t errlen)
{
	dst[0] = 0;
	err[0] = 0;
	struct ktree t;
	int alive = tree_begin(&t, p->pid, 0) == 0;
	int kerr = errno;
	struct qsrc q;
	int rc = find_source(p, alive, &q, err, errlen); /* while the tree is frozen */
	if (alive) {
		*kill_rc = tree_finish(&t, why);
	} else {
		*kill_rc = -1;
		logmsg("kill pid=%d (%s): %s", p->pid, why, strerror(kerr));
	}
	if (rc < 0)
		goto done;

	int qfd = open_qdir(err, errlen);
	if (qfd < 0) {
		rc = -1;
		goto done;
	}
	char name[NAME_MAX + 1];
	snprintf(name, sizeof name, "%.200s.%ld.%d", q.base, (long)time(NULL), (int)p->pid);
	int out = openat(qfd, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
	if (out < 0 || copy_fd(q.fd, out, q.st.st_size) < 0) {
		snprintf(err, errlen, "cannot copy %s into quarantine: %s", q.path, strerror(errno));
		if (out >= 0) {
			close(out);
			unlinkat(qfd, name, 0);
		}
		close(qfd);
		rc = -1;
		goto done;
	}
	close(out);

	/* Remove the original -- only if its entry still names this inode. */
	if (q.dirfd >= 0) {
		if (!entry_is(q.dirfd, q.base, &q.st)) {
			snprintf(err, errlen, "%s was replaced before it could be removed", q.path);
			rc = -1;
		} else if (unlinkat(q.dirfd, q.base, 0) < 0) {
			snprintf(err, errlen, "cannot remove %s: %s", q.path, strerror(errno));
			rc = -1;
		}
		if (rc < 0) {
			unlinkat(qfd, name, 0); /* nothing was quarantined: keep no copy */
			close(qfd);
			goto done;
		}
		struct stat after;
		if (fstat(q.fd, &after) == 0 && after.st_nlink > 0 &&
		    fchmod(q.fd, after.st_mode & ~(mode_t)(S_ISUID | S_ISGID | 0111)) < 0)
			logmsg("quarantine: %s has %lu other hard link(s) still executable: %s", q.path,
			       (unsigned long)after.st_nlink, strerror(errno));
	}
	close(qfd);
	snprintf(dst, dstlen, "%s/quarantine/%s", cfg.state_dir, name);
	rc = 0;
done:
	if (rc == 0)
		logmsg("quarantine pid=%d (%s): %s -> %s", p->pid, why, q.path, dst);
	else
		logmsg("quarantine pid=%d (%s): not quarantined: %s", p->pid, why, err);
	qsrc_close(&q);
	return rc;
}

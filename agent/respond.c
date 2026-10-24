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
 *    is ever touched, never a system file (see sys_guard: OS directories,
 *    dpkg-installed files, the sensor's own binary and loader, root's files
 *    in root-controlled directories -- a container's too), and the original
 *    is unlinked only after its directory entry is re-checked to be that same
 *    inode. Nothing is ever chmod'ed, renamed or read through a path string
 *    that could be a symlink;
 *  - a pid is only signalled while it still names the process the event was
 *    about (its start time is re-checked; a pidfd pins it), and nothing on a
 *    FUSE filesystem is touched (its daemon could stall the sensor forever,
 *    with the tree still frozen). A refused quarantine still kills.
 */
#include "wisp.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <link.h>
#include <sys/auxv.h>
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

struct ktree {
	pid_t root;
	int pfd;                  /* pidfd of root, or -1 (kernel without pidfd) */
	unsigned long long start; /* root's start time (field 22 of /proc/<pid>/stat) */
	int sid;                  /* root's session */
	struct pidset m;          /* root + every descendant found, all stopped */
};

struct pent {
	pid_t pid, ppid;
	int sid;
	unsigned long long start;
};

/* Every process in /proc (but the sensor, init and kernel threads' parent
 * 0): pid, ppid, session, start time. *n gets the count. */
static struct pent *proc_table(size_t *n)
{
	*n = 0;
	DIR *d = opendir("/proc");
	if (!d)
		return NULL;
	pid_t self = getpid();
	size_t cap = 0;
	struct pent *tab = NULL;
	struct dirent *de;
	char path[48], buf[1024];
	while ((de = readdir(d))) {
		if (de->d_name[0] < '1' || de->d_name[0] > '9')
			continue;
		pid_t c = (pid_t)atoi(de->d_name);
		if (c <= 1 || c == self)
			continue;
		snprintf(path, sizeof path, "/proc/%d/stat", c);
		struct pent e = { .pid = c };
		int pp = 0;
		if (read_small(AT_FDCWD, path, buf, sizeof buf) <= 0 || parse_stat(buf, &pp, &e.sid, NULL, &e.start) < 0 ||
		    pp <= 0)
			continue;
		e.ppid = (pid_t)pp;
		if (*n == cap) {
			size_t nc = cap ? cap * 2 : 256;
			void *nt = realloc(tab, nc * sizeof *tab);
			if (!nt)
				break;
			tab = nt;
			cap = nc;
		}
		tab[(*n)++] = e;
	}
	closedir(d);
	return tab;
}

/* One /proc sweep: add (and SIGSTOP) every process whose parent is already
 * in the set. Returns how many were added. The sensor itself, init and
 * kernel threads are never members. */
static size_t tree_sweep(struct ktree *t)
{
	size_t n;
	struct pent *tab = proc_table(&n);
	/* Fixed point over the snapshot: a grandchild may be listed before its
	 * parent. */
	size_t added = 0;
	for (int changed = 1; changed;) {
		changed = 0;
		for (size_t i = 0; i < n; i++) {
			if (!tab[i].pid || !ps_has(&t->m, tab[i].ppid))
				continue;
			pid_t c = tab[i].pid;
			tab[i].pid = 0;
			if (ps_has(&t->m, c))
				continue;
			kill(c, SIGSTOP); /* no more forks from it */
			/* The parent is stopped and cannot reap it, so c is still the
			 * process listed -- unless it was auto-reaped (SIGCHLD ignored)
			 * and its pid reused in between: then let the newcomer go on. */
			unsigned long long st;
			if (proc_start(c, &st) < 0 || st != tab[i].start) {
				kill(c, SIGCONT);
				continue;
			}
			if (ps_add(&t->m, c) > 0) {
				added++;
				changed = 1;
			} else {
				kill(c, SIGKILL); /* out of memory: never leave it stopped */
			}
		}
	}
	free(tab);
	return added;
}

/* Workers that left the tree before it was frozen -- a double fork reparents
 * them to init or a subreaper, so no /proc link leads from the root to them
 * -- are not killed: nothing proves they belong to it. Those still in the
 * root's session are logged so an operator can follow up. A daemon that also
 * called setsid() (the usual daemonize) cannot be told apart from any other
 * process and is not even logged. Cgroups are no better: a login session's
 * scope holds every one of that user's shells. */
static void tree_escapees(const struct ktree *t)
{
	if (t->sid <= 0)
		return;
	size_t n;
	struct pent *tab = proc_table(&n);
	char list[256] = "";
	size_t found = 0, o = 0;
	for (size_t i = 0; i < n; i++) {
		const struct pent *e = &tab[i];
		if (e->sid != t->sid || e->start < t->start || ps_has(&t->m, e->pid) || e->ppid == e->sid)
			continue;
		/* Reparented: its parent is init, or a process older than the root
		 * (a subreaper). A later job of the same shell has the shell -- the
		 * session leader -- or a younger process as parent. */
		int orphan = e->ppid == 1;
		for (size_t j = 0; j < n && !orphan; j++)
			if (tab[j].pid == e->ppid)
				orphan = tab[j].start < t->start && !ps_has(&t->m, tab[j].pid);
		if (!orphan)
			continue;
		found++;
		if (o + 16 < sizeof list)
			o += (size_t)snprintf(list + o, sizeof list - o, "%s%d", o ? "," : "", (int)e->pid);
	}
	free(tab);
	if (found)
		logmsg("kill pid=%d: %zu process(es) of its session were reparented before the freeze "
		       "(daemonized workers?) and are NOT killed: %s%s", t->root, found, list,
		       o + 16 >= sizeof list ? ",..." : "");
}

/* Freeze pid and its whole tree -- only if pid still names the process that
 * started at expect_start (field 22 of /proc/<pid>/stat); a pid now held by
 * another process is left alone. Returns 0, or -1 with errno set (ENODATA:
 * the start time is not known, so the pid cannot be trusted). */
static int tree_begin(struct ktree *t, pid_t pid, unsigned long long expect_start)
{
	memset(t, 0, sizeof *t);
	t->root = pid;
	t->pfd = -1;
	t->start = expect_start;
	if (pid <= 1 || pid == getpid()) {
		errno = EPERM; /* never init, never the sensor itself */
		return -1;
	}
	if (!expect_start) {
		errno = ENODATA;
		return -1;
	}
	/* The pidfd is taken first: once the start time read after it matches,
	 * it names the original process for good, however soon that exits. */
	t->pfd = pidfd_open_(pid);
	if (t->pfd < 0 && errno == ESRCH)
		return -1;
	char path[48], buf[1024];
	unsigned long long st = 0;
	snprintf(path, sizeof path, "/proc/%d/stat", pid);
	if (read_small(AT_FDCWD, path, buf, sizeof buf) <= 0 || parse_stat(buf, NULL, &t->sid, NULL, &st) < 0 ||
	    st != expect_start) {
		if (t->pfd >= 0)
			close(t->pfd);
		t->pfd = -1;
		errno = ESRCH; /* the process exited and its pid may have been reused */
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
	/* Without a pidfd the pid could have changed hands between the check and
	 * the signal: check again, and let an innocent process go on. */
	if (t->pfd < 0 && (proc_start(pid, &st) < 0 || st != expect_start)) {
		kill(pid, SIGCONT);
		errno = ESRCH;
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
	tree_escapees(t);
	return 0;
}

/* SIGKILL everything tree_begin froze. Returns the root's kill result. A
 * member that cannot be killed is sent SIGCONT: nothing is ever left
 * stopped. */
static int tree_finish(struct ktree *t, const char *why)
{
	size_t kids = 0;
	for (size_t i = 0; i < t->m.cap; i++) {
		pid_t c = t->m.v[i];
		if (!c || c == t->root)
			continue;
		if (kill(c, SIGKILL) == 0)
			kids++;
		else if (errno != ESRCH)
			kill(c, SIGCONT);
	}
	int rc, e;
	unsigned long long st;
	if (t->pfd < 0 && (proc_start(t->root, &st) < 0 || st != t->start)) {
		rc = -1; /* no pidfd, and the stopped root died and was reaped meanwhile */
		e = ESRCH;
	} else {
		rc = sig_send(t->pfd, t->root, SIGKILL);
		e = errno;
		if (rc < 0 && e != ESRCH)
			sig_send(t->pfd, t->root, SIGCONT);
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

static const char *kill_refusal(pid_t pid, int e)
{
	if (e == EPERM && (pid <= 1 || pid == getpid()))
		return "refused (init or the sensor itself)";
	if (e == ENODATA)
		return "refused (start time not known: the pid may have been reused)";
	if (e == ESRCH)
		return "the process has exited (its pid is free or now another process's): not signalled";
	return strerror(e);
}

int respond_kill(pid_t pid, unsigned long long start, const char *why)
{
	struct ktree t;
	if (tree_begin(&t, pid, start) < 0) {
		logmsg("kill pid=%d (%s): %s", pid, why, kill_refusal(pid, errno));
		return -1;
	}
	return tree_finish(&t, why);
}

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

static int same_file(const struct stat *a, const struct stat *b)
{
	return a->st_dev == b->st_dev && a->st_ino == b->st_ino;
}

/* ---- FUSE: never touch a file a user's daemon serves ----------------------
 * Every open, stat or lookup on a FUSE filesystem is a request to a userspace
 * daemon, which can simply never answer -- and may itself be in the tree the
 * sensor has just frozen. The single-threaded sensor would hang for good. So
 * before any call that reaches a filesystem, the descriptor it starts from
 * (an O_PATH one: opening that, or following /proc's magic links, never calls
 * into the filesystem) is checked against the mount table, read from /proc
 * (no filesystem call either). Anything on FUSE, or on a mount that cannot
 * be identified, is left alone: the process is still killed. */
struct mtab {
	int *id;
	unsigned char *fuse;
	size_t n, cap;
};

static void mtab_read(struct mtab *m, const char *path)
{
	FILE *f = fopen(path, "re");
	if (!f)
		return;
	char *line = NULL;
	size_t lcap = 0;
	while (getline(&line, &lcap, f) > 0) {
		char *sep = strstr(line, " - "), *end;
		long id = strtol(line, &end, 10);
		if (!sep || end == line || id < 0 || id > INT_MAX)
			continue;
		char *fs = sep + 3;
		int fuse = !strncmp(fs, "fuse ", 5) || !strncmp(fs, "fuse.", 5) || !strncmp(fs, "fuseblk ", 8);
		if (m->n == m->cap) {
			size_t nc = m->cap ? m->cap * 2 : 128;
			int *ni = realloc(m->id, nc * sizeof *ni);
			if (!ni)
				break;
			m->id = ni;
			unsigned char *nf = realloc(m->fuse, nc);
			if (!nf)
				break;
			m->fuse = nf;
			m->cap = nc;
		}
		m->id[m->n] = (int)id;
		m->fuse[m->n++] = (unsigned char)fuse;
	}
	free(line);
	fclose(f);
}

/* The process's mounts (its namespace) and the sensor's. */
static void mtab_load(struct mtab *m, pid_t pid, int alive)
{
	memset(m, 0, sizeof *m);
	char path[64];
	if (alive) {
		snprintf(path, sizeof path, "/proc/%d/mountinfo", pid);
		mtab_read(m, path);
	}
	mtab_read(m, "/proc/self/mountinfo");
}

static void mtab_free(struct mtab *m)
{
	free(m->id);
	free(m->fuse);
	memset(m, 0, sizeof *m);
}

/* 1 when fd is on FUSE or on a mount that cannot be identified. */
static int fd_unsafe(const struct mtab *m, int fd)
{
	char path[64], buf[512];
	snprintf(path, sizeof path, "/proc/self/fdinfo/%d", fd);
	if (fd < 0 || read_small(AT_FDCWD, path, buf, sizeof buf) <= 0)
		return 1;
	const char *p = strstr(buf, "mnt_id:");
	if (!p)
		return 1;
	int id = atoi(p + 7);
	for (size_t i = 0; i < m->n; i++)
		if (m->id[i] == id)
			return m->fuse[i];
	return 1;
}

/* Everything one quarantine works with. */
struct qctx {
	pid_t pid;
	int alive;
	int rootfd;             /* the process's root directory (or ours), checked */
	int cwdfd;              /* its working directory, or -1 */
	struct stat rootst;
	int contained;          /* its root is not ours: a container or chroot */
	uid_t roots[3];         /* uids that stand for root for this process */
	int nroots;
	struct mtab mt;
};

static void qctx_close(struct qctx *c)
{
	if (c->rootfd >= 0)
		close(c->rootfd);
	if (c->cwdfd >= 0)
		close(c->cwdfd);
	c->rootfd = c->cwdfd = -1;
	mtab_free(&c->mt);
}

/* Open the directory holding path's last component, starting at startfd
 * and refusing symlinks, anything that is not a directory, and any FUSE
 * mount along the way. ".." is refused, unless dotdot (identity lookups
 * only), where it never climbs above the process's root. The last component
 * is copied to base. Returns an O_PATH directory fd, or -1 with errno set. */
static int walk_parent(const struct qctx *qc, int startfd, const char *path, char *base, size_t basecap,
                       int dotdot)
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
	if (startfd < 0 || fd_unsafe(&qc->mt, startfd)) {
		errno = EXDEV;
		return -1;
	}
	int fd = fcntl(startfd, F_DUPFD_CLOEXEC, 0);
	if (fd < 0 || !last)
		return fd;
	*last = 0;
	char *save = NULL;
	for (char *c = strtok_r(tmp, "/", &save); c; c = strtok_r(NULL, "/", &save)) {
		if (!strcmp(c, "."))
			continue;
		if (!strcmp(c, "..")) {
			struct stat st;
			if (!dotdot || fstat(fd, &st) < 0) { /* could climb out of the process's root */
				close(fd);
				errno = EINVAL;
				return -1;
			}
			if (same_file(&st, &qc->rootst))
				continue; /* ".." at the root is the root */
		}
		int nfd = openat(fd, c, O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
		int e = errno;
		close(fd);
		if (nfd < 0) {
			errno = e;
			return -1;
		}
		if (fd_unsafe(&qc->mt, nfd)) {
			close(nfd);
			errno = EXDEV;
			return -1;
		}
		fd = nfd;
	}
	return fd;
}

/* Open dirfd/name (never following a symlink) with flags, once an O_PATH
 * look at it shows it is not on FUSE. -1 with errno set otherwise. */
static int open_checked(const struct qctx *qc, int dirfd, const char *name, int flags)
{
	int pfd = openat(dirfd, name, O_PATH | O_NOFOLLOW | O_CLOEXEC);
	if (pfd < 0)
		return -1;
	if (fd_unsafe(&qc->mt, pfd)) {
		close(pfd);
		errno = EXDEV;
		return -1;
	}
	char fdp[48];
	snprintf(fdp, sizeof fdp, "/proc/self/fd/%d", pfd);
	int fd = open(fdp, flags | O_CLOEXEC);
	int e = errno;
	close(pfd);
	errno = e;
	return fd;
}

/* Does dirfd/base (not following a symlink) name the inode st describes? */
static int entry_is(const struct qctx *qc, int dirfd, const char *base, const struct stat *st)
{
	struct stat cur;
	int fd = openat(dirfd, base, O_PATH | O_NOFOLLOW | O_CLOEXEC);
	int ok = fd >= 0 && !fd_unsafe(&qc->mt, fd) && fstat(fd, &cur) == 0 && same_file(&cur, st);
	if (fd >= 0)
		close(fd);
	return ok;
}

/* Identity only: the inode path leads to from startfd (the root when it is
 * absolute), following up to 8 symlinks by hand, so that no link can lead
 * the lookup into a FUSE mount. An O_PATH fd, or -1. */
static int resolve(const struct qctx *qc, int startfd, const char *path, int depth)
{
	char base[NAME_MAX + 1];
	int dfd = walk_parent(qc, path[0] == '/' ? qc->rootfd : startfd, path, base, sizeof base, 1);
	if (dfd < 0)
		return -1;
	struct stat st;
	int fd = openat(dfd, base, O_PATH | O_NOFOLLOW | O_CLOEXEC);
	if (fd >= 0 && (fd_unsafe(&qc->mt, fd) || fstat(fd, &st) < 0)) {
		close(fd);
		fd = -1;
	} else if (fd >= 0 && S_ISLNK(st.st_mode)) {
		char tgt[MAX_PATH];
		ssize_t n = readlinkat(fd, "", tgt, sizeof tgt - 1);
		close(fd);
		fd = -1;
		if (n > 0 && depth < 8) {
			tgt[n] = 0;
			fd = resolve(qc, dfd, tgt, depth + 1);
		}
	}
	close(dfd);
	return fd;
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

/* The host uid that is root inside pid's user namespace (a rootless
 * container's "root"), or -1. */
static long userns_root(pid_t pid)
{
	char path[48], buf[1024];
	snprintf(path, sizeof path, "/proc/%d/uid_map", pid);
	if (read_small(AT_FDCWD, path, buf, sizeof buf) <= 0)
		return -1;
	for (char *l = buf; l && *l; l = strchr(l, '\n') ? strchr(l, '\n') + 1 : NULL) {
		unsigned long in, out, cnt;
		if (sscanf(l, "%lu %lu %lu", &in, &out, &cnt) == 3 && in == 0 && cnt > 0)
			return (long)out;
	}
	return -1;
}

static int is_root_uid(const struct qctx *qc, uid_t u)
{
	for (int i = 0; i < qc->nroots; i++)
		if (qc->roots[i] == u)
			return 1;
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

/* ---- what quarantine never removes ----------------------------------------
 * A rule that matches (say) a shell's command line must not take the shell
 * away from the host: quarantine is refused, and the process only killed, for
 * an operating-system or package-managed file, the sensor's own binary or
 * its loader, and anything a root (the host's, or a container's) put in a
 * directory only it and its group can write. Inside a container these are
 * judged from the container's own root. */

/* Top-level directories of the operating system (relative to a root). */
static const char *const sysdirs[] = { "usr", "bin", "sbin", "lib", "lib32", "lib64", "libx32", "boot", "etc" };

/* Is the path string under one of them? ("//usr/./bin" counts.) */
static int sys_path(const char *path)
{
	while (*path == '/' || (path[0] == '.' && path[1] == '/'))
		path++;
	for (size_t i = 0; i < sizeof sysdirs / sizeof *sysdirs; i++) {
		size_t l = strlen(sysdirs[i]);
		if (!strncmp(path, sysdirs[i], l) && (path[l] == '/' || !path[l]))
			return 1;
	}
	return 0;
}

/* Is directory dirfd one of the system directories of the process's root,
 * or inside one? Walks up through ".." to the root; 1 = yes, or cannot tell. */
static int sys_dir(const struct qctx *qc, int dirfd)
{
	struct stat sys[sizeof sysdirs / sizeof *sysdirs];
	size_t ns = 0;
	for (size_t i = 0; i < sizeof sysdirs / sizeof *sysdirs; i++) {
		/* /bin -> usr/bin is a link on merged-/usr systems: /usr covers it */
		int fd = openat(qc->rootfd, sysdirs[i], O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
		if (fd < 0)
			continue;
		int bad = fd_unsafe(&qc->mt, fd) || fstat(fd, &sys[ns]) < 0;
		close(fd);
		if (bad)
			return 1;
		ns++;
	}
	int fd = fcntl(dirfd, F_DUPFD_CLOEXEC, 0);
	for (int depth = 0; fd >= 0 && depth < 256; depth++) {
		struct stat st;
		if (fd_unsafe(&qc->mt, fd) || fstat(fd, &st) < 0)
			break;
		for (size_t i = 0; i < ns; i++)
			if (same_file(&st, &sys[i])) {
				close(fd);
				return 1;
			}
		if (same_file(&st, &qc->rootst)) {
			close(fd);
			return 0;
		}
		int up = openat(fd, "..", O_PATH | O_DIRECTORY | O_CLOEXEC);
		struct stat ust;
		if (up >= 0 && !fd_unsafe(&qc->mt, up) && fstat(up, &ust) == 0 && same_file(&ust, &st)) {
			close(up); /* the top of the sensor's tree: not under the process's root */
			close(fd);
			return 0;
		}
		close(fd);
		fd = up;
	}
	if (fd >= 0)
		close(fd);
	return 1;
}

/* The sensor's own executable and its ELF interpreter (the dynamic loader). */
static int self_file(const struct stat *st)
{
	static struct stat self[2];
	static int nself = -1;
	if (nself < 0) {
		nself = 0;
		if (stat("/proc/self/exe", &self[nself]) == 0)
			nself++;
		const ElfW(Phdr) *ph = (const ElfW(Phdr) *)getauxval(AT_PHDR);
		size_t phn = getauxval(AT_PHNUM);
		uintptr_t bias = 0;
		const char *interp = NULL;
		for (size_t i = 0; ph && i < phn; i++)
			if (ph[i].p_type == PT_PHDR)
				bias = (uintptr_t)ph - ph[i].p_vaddr;
		for (size_t i = 0; ph && i < phn; i++)
			if (ph[i].p_type == PT_INTERP)
				interp = (const char *)(bias + ph[i].p_vaddr);
		if (interp && stat(interp, &self[nself]) == 0)
			nself++;
	}
	for (int i = 0; i < nself; i++)
		if (same_file(st, &self[i]))
			return 1;
	return 0;
}

/* The cheap checks, made while the tree is frozen: 0, or -1 with err set. */
static int sys_guard(const struct qctx *qc, const struct qsrc *q, char *err, size_t errlen)
{
	const char *why = NULL;
	struct stat dirst;
	if (self_file(&q->st))
		why = "the sensor's own executable or its loader";
	else if (sys_path(q->path))
		why = "an operating-system path";
	else if (q->dirfd >= 0 && sys_dir(qc, q->dirfd))
		why = "in an operating-system directory";
	else if (is_root_uid(qc, q->st.st_uid) && q->dirfd >= 0) {
		/* Put there by root (or a container's root) in a directory only it
		 * and its group can write -- /usr/local/bin is root:staff 2775 on
		 * some systems: an administrator's install. Nor is a root-owned file
		 * with other hard links touched: its mode is shared with names that
		 * may be system files. */
		if (fstat(q->dirfd, &dirst) < 0 || (is_root_uid(qc, dirst.st_uid) && !(dirst.st_mode & S_IWOTH)))
			why = "root-owned, in a directory only root (and its group) can write";
		else if (q->st.st_nlink > 1)
			why = "root-owned with other hard links";
	}
	if (!why)
		return 0;
	snprintf(err, errlen, "%s is a system file (%s): left in place, process killed only", q->path, why);
	return -1;
}

/* Is path listed in the dpkg database under the process's root
 * (var/lib/dpkg/info/<package>.list holds every file a package installed)?
 * 1 yes, 0 no, -1 cannot tell (the scan is bounded: it runs on the event
 * loop). Run after the kill, never while the tree is frozen. rpm keeps its
 * database in Berkeley DB/SQLite (var/lib/rpm), which cannot be read here
 * without a library or a child process per event; rpm installs root-owned
 * files in root-owned directories, which sys_guard already refuses. */
#define DPKG_SCAN_MAX ((off_t)128 << 20)
static int dpkg_owned(const struct qctx *qc, const char *path)
{
	if (path[0] != '/')
		return 0; /* relative: sys_dir judged its directory */
	char base[NAME_MAX + 1];
	int dfd = walk_parent(qc, qc->rootfd, "var/lib/dpkg/info/x", base, sizeof base, 0);
	if (dfd < 0)
		return errno == ENOENT || errno == ENOTDIR ? 0 : -1;
	int lfd = openat(dfd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	DIR *d = lfd >= 0 ? fdopendir(lfd) : NULL;
	if (!d) {
		if (lfd >= 0)
			close(lfd);
		close(dfd);
		return -1;
	}
	while (path[1] == '/')
		path++;
	size_t pl = strlen(path);
	off_t total = 0;
	int rc = 0;
	char *line = NULL;
	size_t lcap = 0;
	struct dirent *de;
	while (rc == 0 && (de = readdir(d))) {
		size_t l = strlen(de->d_name);
		if (l < 6 || strcmp(de->d_name + l - 5, ".list"))
			continue;
		int fd = open_checked(qc, dfd, de->d_name, O_RDONLY | O_NONBLOCK | O_NOCTTY);
		struct stat st;
		if (fd < 0)
			continue;
		if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode)) {
			close(fd);
			continue;
		}
		if ((total += st.st_size) > DPKG_SCAN_MAX) {
			close(fd);
			rc = -1;
			break;
		}
		FILE *f = fdopen(fd, "re");
		if (!f) {
			close(fd);
			continue;
		}
		ssize_t n;
		while ((n = getline(&line, &lcap, f)) > 0) {
			if (line[n - 1] == '\n')
				n--;
			if ((size_t)n == pl && !memcmp(line, path, pl)) {
				rc = 1;
				break;
			}
		}
		fclose(f);
	}
	free(line);
	closedir(d);
	close(dfd);
	return rc;
}

/* Set up the context: the process's root and working directory (through its
 * own namespace) and mount table, and who counts as root for it. */
static int qctx_open(struct qctx *qc, const struct proc *p, int alive, char *err, size_t errlen)
{
	char path[64];
	memset(qc, 0, sizeof *qc);
	qc->pid = p->pid;
	qc->alive = alive;
	qc->rootfd = qc->cwdfd = -1;
	mtab_load(&qc->mt, p->pid, alive);
	if (alive) {
		snprintf(path, sizeof path, "/proc/%d/root", p->pid);
		qc->rootfd = open(path, O_PATH | O_DIRECTORY | O_CLOEXEC);
		snprintf(path, sizeof path, "/proc/%d/cwd", p->pid);
		qc->cwdfd = open(path, O_PATH | O_DIRECTORY | O_CLOEXEC);
	}
	if (qc->rootfd < 0)
		qc->rootfd = open("/", O_PATH | O_DIRECTORY | O_CLOEXEC);
	struct stat ours;
	if (qc->rootfd < 0 || fd_unsafe(&qc->mt, qc->rootfd) || fstat(qc->rootfd, &qc->rootst) < 0 ||
	    stat("/", &ours) < 0) {
		snprintf(err, errlen, "cannot open the process's root directory safely");
		return -1;
	}
	qc->roots[qc->nroots++] = 0;
	qc->contained = !same_file(&qc->rootst, &ours);
	/* A container's root: the uid its user namespace maps to 0, and the
	 * owner of its root directory. Only for a contained process: one that
	 * merely runs in a user namespace of its own (unshare -r) shares the
	 * host's files, and must not make its user's own files look like
	 * system files. */
	if (qc->contained) {
		long r = alive ? userns_root(p->pid) : -1;
		if (r > 0)
			qc->roots[qc->nroots++] = (uid_t)r;
		if (qc->rootst.st_uid != 0 && (long)qc->rootst.st_uid != r)
			qc->roots[qc->nroots++] = qc->rootst.st_uid;
	}
	return 0;
}

/* Find the file the process is running (or, when that cannot be tied to the
 * event, the regular file at the event's path). qc->alive: the process is
 * frozen, so its /proc entries are usable. */
static int find_source(const struct proc *p, const struct qctx *qc, struct qsrc *q, char *err, size_t errlen)
{
	char path[64], xpath[MAX_PATH] = "", ename[NAME_MAX + 1];
	int rc = -1, alive = qc->alive;
	q->fd = q->dirfd = -1;
	q->path[0] = 0;

	/* The kernel names a process after the file it was started from (its
	 * comm, cut at 15 bytes; both sensors report the kernel's comm at
	 * exec). When that is not the executable's name, the program was a
	 * script run through an interpreter (and the connector sensor reports
	 * the interpreter as exe), or it renamed itself: either way the file to
	 * quarantine cannot be told apart from its interpreter. */
	exe_name(p->exe, ename, sizeof ename);
	if (strncmp(p->comm, ename, 15)) {
		snprintf(err, errlen, "cannot tell which file '%s' was started from (exe %s)", p->comm, p->exe);
		return -1;
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
			/* O_PATH through the magic link reaches no filesystem code:
			 * check the mount before the real open (which would). */
			int xfd = open(path, O_PATH | O_CLOEXEC);
			if (xfd >= 0 && fd_unsafe(&qc->mt, xfd)) {
				close(xfd);
				snprintf(err, errlen, "%s is on a FUSE (user-space) or unidentified filesystem: left in place",
				         xpath);
				goto out;
			}
			if (xfd >= 0) {
				char fdp[48];
				snprintf(fdp, sizeof fdp, "/proc/self/fd/%d", xfd);
				q->fd = open(fdp, O_RDONLY | O_CLOEXEC | O_NOCTTY | O_NONBLOCK);
				close(xfd);
			}
			if (q->fd >= 0 && fstat(q->fd, &q->st) < 0) {
				close(q->fd);
				q->fd = -1;
			}
		}
		char a[NAME_MAX + 1];
		exe_name(xpath, a, sizeof a);
		if (q->fd >= 0 && strcmp(a, ename)) {
			/* Identity only: links followed by hand, never an open. */
			struct stat est;
			int ifd = resolve(qc, qc->cwdfd, p->exe, 0);
			if (ifd < 0 || fstat(ifd, &est) < 0 || !same_file(&est, &q->st)) {
				close(q->fd);
				q->fd = -1;
			}
			if (ifd >= 0)
				close(ifd);
		}
	}
	if (q->fd >= 0) {
		/* Locate its directory entry: the kernel's current path for it
		 * first (it tracks renames), then the event's. Either must name
		 * exactly this inode. */
		const char *cand[2] = { xpath, p->exe };
		for (int i = 0; i < 2 && q->dirfd < 0; i++) {
			const char *c = cand[i];
			int start = c[0] == '/' ? qc->rootfd : qc->cwdfd;
			if (!c[0] || start < 0)
				continue;
			int dfd = walk_parent(qc, start, c, q->base, sizeof q->base, 0);
			if (dfd >= 0 && entry_is(qc, dfd, q->base, &q->st)) {
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
		int start = c[0] == '/' ? qc->rootfd : qc->cwdfd;
		if (start < 0) {
			snprintf(err, errlen, "relative path and the process has exited");
			goto out;
		}
		q->dirfd = walk_parent(qc, start, c, q->base, sizeof q->base, 0);
		if (q->dirfd < 0) {
			snprintf(err, errlen, "cannot reach %s without following a link or entering a FUSE mount: %s", c,
			         strerror(errno));
			goto out;
		}
		struct stat lst;
		int lfd = openat(q->dirfd, q->base, O_PATH | O_NOFOLLOW | O_CLOEXEC);
		if (lfd >= 0 && fd_unsafe(&qc->mt, lfd)) {
			close(lfd);
			snprintf(err, errlen, "%s is on a FUSE (user-space) or unidentified filesystem: left in place", c);
			goto out;
		}
		int sr = lfd >= 0 ? fstat(lfd, &lst) : -1;
		int se = errno;
		if (lfd >= 0)
			close(lfd);
		if (sr < 0) {
			snprintf(err, errlen, "%s: %s", c, strerror(se));
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
		q->fd = open_checked(qc, q->dirfd, q->base, O_RDONLY | O_NONBLOCK | O_NOCTTY);
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
	if (sys_guard(qc, q, err, errlen) < 0)
		goto out;
	rc = 0;
out:
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
 * otherwise err says why the file was left in place (the process is killed
 * either way: a refused quarantine falls back to kill-only). */
int respond_quarantine(const struct proc *p, const char *why, int *kill_rc, char *dst, size_t dstlen,
                       char *err, size_t errlen)
{
	dst[0] = 0;
	err[0] = 0;
	struct ktree t;
	int alive = tree_begin(&t, p->pid, p->start) == 0;
	int kerr = errno;
	struct qctx qc;
	struct qsrc q = { .fd = -1, .dirfd = -1 };
	/* While the tree is frozen. Nothing here can block: no FUSE, no FIFO,
	 * and tree_finish runs whatever the outcome, so no member stays stopped. */
	int rc = qctx_open(&qc, p, alive, err, errlen);
	if (rc == 0)
		rc = find_source(p, &qc, &q, err, errlen);
	if (alive) {
		*kill_rc = tree_finish(&t, why);
	} else {
		*kill_rc = -1;
		logmsg("kill pid=%d (%s): %s", p->pid, why, kill_refusal(p->pid, kerr));
	}
	if (rc < 0)
		goto done;
	/* The slower check, now that nothing waits on it. */
	int owned = dpkg_owned(&qc, q.path);
	if (owned) {
		snprintf(err, errlen, owned > 0 ? "%s is a system file (installed by a dpkg package): left in place, "
		                                  "process killed only"
		                                : "cannot tell whether %s was installed by a dpkg package: left in "
		                                  "place, process killed only",
		         q.path);
		rc = -1;
		goto done;
	}

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
		if (!entry_is(&qc, q.dirfd, q.base, &q.st)) {
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
	qctx_close(&qc);
	return rc;
}

/* File integrity monitoring for a small set of sensitive paths.
 * Pure inotify: no hashing loop, no polling.
 *
 * inotify watches an inode, not a name. A file replaced the usual way --
 * write a temporary copy, rename it over the original: shadow-utils
 * (useradd, passwd, vipw), sed -i, editors, configuration management -- would
 * leave a watch on the old, unlinked inode and nothing on the new file. So
 * every fim.conf path gets two watches:
 *   - one on the path itself: a file's writes and attribute changes, or
 *     everything directly inside a directory. It is re-added whenever the
 *     kernel drops it or the path gets a new inode;
 *   - one on its parent directory, filtered to the path's own name, which
 *     sees the path being created, deleted or renamed over -- and re-arms the
 *     first watch on whatever lives there now.
 * A path that does not exist yet is watched for through its parent.
 * fim_init() also serves as the reload: it swaps in the new set and drops
 * only the watches nothing uses any more, so queued events stay meaningful.
 */
#include "wisp.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAX_FIM 128
#define M_FILE (IN_MODIFY | IN_ATTRIB | IN_CLOSE_WRITE | IN_DELETE_SELF | IN_MOVE_SELF)
#define M_DIR  (IN_CREATE | IN_DELETE | IN_MODIFY | IN_ATTRIB | IN_MOVED_TO | IN_MOVED_FROM | \
                IN_CLOSE_WRITE | IN_DELETE_SELF | IN_MOVE_SELF)
#define M_NAME (IN_CREATE | IN_DELETE | IN_MOVED_TO | IN_MOVED_FROM) /* parent: entry changes */

struct fwatch {
	char path[MAX_PATH];    /* as configured, without a trailing '/' */
	char parent[MAX_PATH];  /* its directory ("" for "/") */
	int boff;               /* offset of the last component in path */
	enum sev sev;
	int wd;                 /* watch on the path itself, -1 = none */
	int pwd;                /* watch on the parent, -1 = none */
	int is_dir;             /* the path was a directory when wd was added */
	int stale;              /* the path has a new inode: re-add wd */
	int line;
};
static struct fwatch tab_a[MAX_FIM], tab_b[MAX_FIM];
static struct fwatch *fw = tab_a;
static int nfw;
static int nabsent;     /* paths of the current set that did not exist when loaded */
static int ifd = -1;
static char conf[MAX_PATH];

static int parse_sev(const char *s)
{
	static const char *n[] = { "info", "low", "medium", "high", "critical" };
	for (int i = 0; i < 5; i++)
		if (!strcmp(s, n[i]))
			return i;
	return -1;
}

/* Read fim.conf into out. Returns the number of paths, -1 if unreadable.
 * Malformed lines are reported (file:line) and skipped. */
static int fim_parse(const char *path, struct fwatch *out)
{
	FILE *f = fopen(path, "re");
	if (!f)
		return -1;
	int n = 0, ln = 0;
	char line[MAX_PATH + 64];
	while (fgets(line, sizeof line, f)) {
		ln++;
		if (!strchr(line, '\n') && !feof(f)) {
			cfg_problem(path, ln, "line longer than %zu bytes (skipped)", sizeof line - 2);
			int ch;
			while ((ch = fgetc(f)) != EOF && ch != '\n')
				;
			continue;
		}
		char *s = line;
		while (isspace((unsigned char)*s))
			s++;
		strip_comment(s);
		if (!*s || *s == '#')
			continue;
		char p[MAX_PATH], sev[16] = "high", more[16];
		int k = sscanf(s, "%511s %15s %15s", p, sev, more);
		if (k < 1)
			continue;
		if (k >= 3) {
			cfg_problem(path, ln, "unexpected '%s' after the severity (line skipped)", more);
			continue;
		}
		int sv = parse_sev(sev);
		if (sv < 0) {
			cfg_problem(path, ln, "unknown severity '%s' (info, low, medium, high or critical; line skipped)", sev);
			continue;
		}
		if (p[0] != '/') {
			cfg_problem(path, ln, "'%s' is not an absolute path (line skipped)", p);
			continue;
		}
		if (n == MAX_FIM) {
			cfg_problem(path, ln, "more than %d paths: this and later lines are not watched", MAX_FIM);
			break;
		}
		size_t l = strlen(p);
		while (l > 1 && p[l - 1] == '/')
			p[--l] = 0;
		struct fwatch *e = &out[n++];
		memset(e, 0, sizeof *e);
		scopy(e->path, sizeof e->path, p);
		const char *b = strrchr(e->path, '/');
		e->boff = (int)(b - e->path) + 1;
		if (b == e->path)
			scopy(e->parent, sizeof e->parent, e->path[1] ? "/" : "");
		else
			snprintf(e->parent, sizeof e->parent, "%.*s", (int)(b - e->path), e->path);
		e->sev = (enum sev)sv;
		e->wd = e->pwd = -1;
		e->line = ln;
	}
	fclose(f);
	return n;
}

static int wd_used(const struct fwatch *t, int n, int wd)
{
	for (int i = 0; i < n; i++)
		if (t[i].wd == wd || t[i].pwd == wd)
			return 1;
	return 0;
}

/* (Re)watch the path itself. IN_MASK_ADD: entries may share an inode (a
 * directory that is also another entry's parent). */
static int arm_self(struct fwatch *e)
{
	int old = e->wd;
	struct stat st;
	int wd = -1;
	if (stat(e->path, &st) == 0) {
		e->is_dir = S_ISDIR(st.st_mode);
		wd = inotify_add_watch(ifd, e->path, IN_MASK_ADD | (e->is_dir ? M_DIR | IN_ONLYDIR : M_FILE));
	}
	int err = errno;
	e->wd = wd;
	e->stale = 0;
	/* A watch left on an inode that no longer lives at this path would only
	 * report changes to someone else's file. */
	if (old >= 0 && old != wd && !wd_used(fw, nfw, old))
		inotify_rm_watch(ifd, old);
	errno = err;
	return wd;
}

static int arm_parent(struct fwatch *e)
{
	if (!e->parent[0])
		return e->pwd = -1;
	e->pwd = inotify_add_watch(ifd, e->parent, IN_MASK_ADD | M_NAME | IN_ONLYDIR);
	return e->pwd;
}

/* A permission error is only a configuration problem for the sensor itself,
 * which runs as root. --check-config run unprivileged (CI, a policy repo)
 * cannot open root-only paths such as /etc/shadow, so it notes them instead. */
static int unprivileged_denial(int err)
{
	return (err == EACCES || err == EPERM) && geteuid() != 0;
}

/* Arm a freshly loaded entry and say what it covers. A path that does not
 * exist is a warning (it is watched for); one that cannot be watched for
 * another reason is a configuration problem. */
static void arm_new(struct fwatch *e, const char *file)
{
	int pw = arm_parent(e), pe = errno;
	if (arm_self(e) >= 0)
		return;
	int se = errno;
	if (se == ENOENT || se == ENOTDIR)
		nabsent++;
	if (unprivileged_denial(se))
		logmsg("fim: %s:%d: cannot check %s as uid %d (%s); the sensor runs as root", file, e->line,
		       e->path, (int)geteuid(), strerror(se));
	else if (se != ENOENT && se != ENOTDIR)
		cfg_problem(file, e->line, "cannot watch %s: %s", e->path, strerror(se));
	else if (pw >= 0)
		logmsg("fim: %s:%d: %s does not exist; watching %s for it to appear", file, e->line, e->path,
		       e->parent);
	else if (pe == ENOENT || pe == ENOTDIR)
		logmsg("fim: %s:%d: neither %s nor its directory exists: not watched (until a reload)", file,
		       e->line, e->path);
	else if (unprivileged_denial(pe))
		logmsg("fim: %s:%d: cannot check %s or its directory as uid %d (%s); the sensor runs as root",
		       file, e->line, e->path, (int)geteuid(), strerror(pe));
	else
		cfg_problem(file, e->line, "cannot watch %s or its directory: %s", e->path, strerror(pe));
}

/* Load fim.conf, or reload it: a new set replaces the current one, and only
 * watches the new set does not use are removed. An unreadable file keeps the
 * current set. Returns the number of watched paths, or -1. */
int fim_init(int inotify_fd, const char *path)
{
	ifd = inotify_fd;
	scopy(conf, sizeof conf, path);
	struct fwatch *nt = fw == tab_a ? tab_b : tab_a, *old = fw;
	int n = fim_parse(path, nt), on = nfw;
	if (n < 0) {
		if (on)
			logmsg("fim: cannot read %s: %s; keeping the %d current path(s)", path, strerror(errno), on);
		return -1;
	}
	/* Switch first, so arm_self() never removes a watch the new set shares. */
	fw = nt;
	nfw = n;
	nabsent = 0;
	for (int i = 0; i < n; i++)
		arm_new(&nt[i], path);
	for (int i = 0; i < on; i++) {
		int w[2] = { old[i].wd, old[i].pwd };
		for (int j = 0; j < 2; j++)
			if (w[j] >= 0 && !wd_used(nt, n, w[j]) && !wd_used(old, i, w[j]))
				inotify_rm_watch(ifd, w[j]);
	}
	return n;
}

int fim_reload(void)
{
	if (ifd < 0 || !conf[0])
		return -1;
	return fim_init(ifd, conf);
}

int fim_count(void) { return nfw; }
int fim_absent(void) { return nabsent; }

/* After an inotify queue overflow the kernel's IN_IGNORED notices may have
 * been lost with everything else: re-add every watch (a live one is kept). */
void fim_resync(void)
{
	for (int i = 0; i < nfw; i++)
		fw[i].stale = 1;
	for (int i = 0; i < nfw; i++) {
		arm_self(&fw[i]);
		arm_parent(&fw[i]);
	}
}

int fim_owns_wd(int wd) { return wd_used(fw, nfw, wd); }

static const char *op_of(uint32_t mask)
{
	return (mask & IN_CREATE) ? "create" :
	       (mask & (IN_DELETE | IN_MOVED_FROM)) ? "delete" :
	       (mask & IN_ATTRIB) ? "attrib" :
	       (mask & IN_MOVED_TO) ? "rename" :
	       (mask & (IN_MODIFY | IN_CLOSE_WRITE)) ? "modify" : NULL;
}

static void report(const char *full, const char *op, enum sev sev)
{
	char extra[JESC_MAX(MAX_PATH + 256) + 64], efull[JESC_MAX(MAX_PATH + 256)];
	jesc(efull, sizeof efull, full);
	snprintf(extra, sizeof extra, "\"path\":\"%s\",\"op\":\"%s\"", efull, op);
	struct proc dummy;
	memset(&dummy, 0, offsetof(struct proc, cmd));
	dummy.cmd[0] = 0;
	dummy.cmdlen = 0;
	dummy.actor = ACTOR_UNKNOWN;
	scopy(dummy.comm, sizeof dummy.comm, "fim");
	scopy(dummy.actor_src, sizeof dummy.actor_src, "fim");
	out_alert("FIM", "T1565.001", "Watched path changed", sev, "alert", &dummy, extra);
}

void fim_on_event(int wd, uint32_t mask, const char *name)
{
	int rearm = 0;
	if (mask & IN_IGNORED) {
		/* The kernel dropped this watch (its inode is gone, or we removed
		 * it). Never an alert by itself: the change that caused it was. */
		for (int i = 0; i < nfw; i++) {
			if (fw[i].wd == wd)
				fw[i].wd = -1, rearm = 1;
			if (fw[i].pwd == wd)
				fw[i].pwd = -1, rearm = 1;
		}
	} else {
		/* One inotify event raises at most one alert, however many entries
		 * it concerns (the most severe one names it). */
		int best = -1;
		const char *bop = NULL;
		char bfull[MAX_PATH + 256] = "";
		for (int i = 0; i < nfw; i++) {
			struct fwatch *e = &fw[i];
			const char *op = NULL;
			char full[MAX_PATH + 256];
			if (e->wd == wd) {
				if (mask & (IN_DELETE_SELF | IN_MOVE_SELF)) {
					/* The watched object was removed or moved away. A moved
					 * inode keeps its watch: drop it, it is not at this path
					 * any more. The parent watch reports the change by name. */
					if (mask & IN_MOVE_SELF)
						inotify_rm_watch(ifd, wd);
					for (int j = 0; j < nfw; j++)
						if (fw[j].wd == wd)
							fw[j].wd = -1;
					rearm = 1;
					if (e->pwd >= 0)
						continue;
					op = "delete";
					scopy(full, sizeof full, e->path);
				} else {
					op = op_of(mask);
					if (e->is_dir && name && *name)
						snprintf(full, sizeof full, "%s%s%s", e->path, e->path[1] ? "/" : "", name);
					else
						scopy(full, sizeof full, e->path);
				}
			} else if (e->pwd == wd && name && (mask & M_NAME) && !strcmp(name, e->path + e->boff)) {
				op = (mask & IN_CREATE) ? "create" : (mask & IN_MOVED_TO) ? "rename" : "delete";
				scopy(full, sizeof full, e->path);
				if (mask & (IN_CREATE | IN_MOVED_TO)) {
					e->stale = 1; /* a new inode lives at the path: watch it */
					rearm = 1;
				}
			}
			if (!op)
				continue;
			if (best < 0 || e->sev > fw[best].sev) {
				best = i;
				bop = op;
				scopy(bfull, sizeof bfull, full);
			}
		}
		if (best >= 0)
			report(bfull, bop, fw[best].sev);
	}
	if (!rearm)
		return;
	for (int i = 0; i < nfw; i++) {
		if (fw[i].wd < 0 || fw[i].stale)
			arm_self(&fw[i]);
		if (fw[i].pwd < 0)
			arm_parent(&fw[i]);
	}
}

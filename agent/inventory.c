/* Fleet inventory: what tools, packages and IDE extensions live on the
 * host. A full scan runs once at startup and on a slow timer; between
 * scans, inotify watches the handful of directories that change when
 * someone installs a package or an IDE extension, so a new install is
 * reported within milliseconds without any polling.
 */
#include "wisp.h"

#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <glob.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <unistd.h>

/* One row per watched directory. inotify returns the same wd for a directory
 * that is already watched, so rows are keyed by wd: rescans (startup, every
 * console reconnect, the daily timer) never add duplicates, and a directory
 * the kernel stops watching (removed) frees its row. */
#define MAX_WATCH 512
struct watch {
	int wd;
	char kind[8];
	char scope[64];      /* npm: "@scope" for a scope directory, else "" */
	char path[MAX_PATH];
};
static struct watch watches[MAX_WATCH];
static int nwatch;
static int ifd = -1;

static void add_watch(const char *kind, const char *scope, const char *path)
{
	if (ifd < 0)
		return;
	int wd = inotify_add_watch(ifd, path,
	                           IN_CREATE | IN_DELETE | IN_MOVED_TO | IN_MOVED_FROM | IN_ONLYDIR);
	if (wd < 0)
		return;
	struct watch *w = NULL;
	for (int i = 0; i < nwatch; i++)
		if (watches[i].wd == wd) {
			w = &watches[i]; /* already watched: refresh the row */
			break;
		}
	if (!w) {
		if (nwatch >= MAX_WATCH) {
			static int warned;
			if (!warned++)
				logmsg("inventory: more than %d install directories; %s and later ones are "
				       "only seen by the periodic rescan", MAX_WATCH, path);
			inotify_rm_watch(ifd, wd);
			return;
		}
		w = &watches[nwatch++];
	}
	w->wd = wd;
	scopy(w->kind, sizeof w->kind, kind);
	scopy(w->scope, sizeof w->scope, scope ? scope : "");
	scopy(w->path, sizeof w->path, path);
}

static void drop_watch(int wd)
{
	for (int i = 0; i < nwatch; i++)
		if (watches[i].wd == wd) {
			watches[i] = watches[--nwatch];
			return;
		}
}

int inventory_owns_wd(int wd)
{
	for (int i = 0; i < nwatch; i++)
		if (watches[i].wd == wd)
			return 1;
	return 0;
}

/* Read "version" out of a package.json / extension manifest. These live in
 * directories users write (home directories, extension folders): read_user
 * refuses a FIFO or device planted there (it would hang the sensor) and a
 * symlink to some other file. */
static void read_json_version(const char *dir, char *ver, size_t vlen)
{
	ver[0] = 0;
	char path[MAX_PATH], buf[4096];
	snprintf(path, sizeof path, "%s/package.json", dir);
	if (read_user(AT_FDCWD, path, buf, sizeof buf) <= 0)
		return;
	char *v = strstr(buf, "\"version\"");
	if (!v)
		return;
	v = strchr(v + 9, '"');
	if (!v)
		return;
	char *e = strchr(++v, '"');
	if (e && (size_t)(e - v) < vlen) {
		memcpy(ver, v, e - v);
		ver[e - v] = 0;
	}
}

/* IDE extensions are governed by the catalog's `vsx` entries. They arrive as
 * directories named "<publisher>.<name>-<version>", so the version suffix is
 * cut before the catalog lookup. Each violation is reported once per sensor
 * run (rescans do not repeat it). This is detect-only: the extension is
 * already on disk, and the sensor does not delete a developer's files. */
static uint64_t vsx_seen[256];

static void check_extension(const char *dirname, const char *ver, const char *where)
{
	char id[160];
	snprintf(id, sizeof id, "%s", dirname);
	char *dash = strrchr(id, '-');
	if (dash && dash[1] >= '0' && dash[1] <= '9')
		*dash = 0;
	char why[256];
	if (!catalog_verdict("vsx", id, ver, why, sizeof why))
		return;
	uint64_t h = 1469598103934665603ULL;
	for (const char *c = dirname; *c; c++)
		h = (h ^ (uint8_t)*c) * 1099511628211ULL;
	for (size_t i = 0; i < sizeof vsx_seen / sizeof *vsx_seen; i++) {
		if (vsx_seen[i] == h)
			return;
		if (!vsx_seen[i]) {
			vsx_seen[i] = h;
			break;
		}
	}
	struct proc p;
	memset(&p, 0, sizeof p);
	p.actor = ACTOR_UNKNOWN;
	snprintf(p.comm, sizeof p.comm, "inventory");
	snprintf(p.exe, sizeof p.exe, "%s/%s", where, dirname);
	snprintf(p.cmd, sizeof p.cmd, "IDE extension %s %s", id, ver);
	p.cmdlen = strlen(p.cmd);
	out_alert("CAT-VSX", "T1195.001", why, SEV_HIGH, "alert", &p, NULL);
}

/* Python distributions: "<name>-<version>.dist-info" (wheels) or
 * "<name>-<version>[-pyX.Y].egg-info". The name is normalised as PEP 503
 * does (lowercase, runs of -_. become one -), which is how the console's
 * vulnerability database keys pip packages. Returns 0 for anything else. */
static int pip_dist(const char *entry, char *name, size_t nlen, char *ver, size_t vlen)
{
	size_t l = strlen(entry);
	size_t sl = l > 10 && !strcmp(entry + l - 10, ".dist-info") ? 10 :
	            l > 9 && !strcmp(entry + l - 9, ".egg-info") ? 9 : 0;
	if (!sl)
		return 0;
	char stem[256];
	if (l - sl >= sizeof stem)
		return 0;
	memcpy(stem, entry, l - sl);
	stem[l - sl] = 0;
	char *dash = strchr(stem, '-');
	ver[0] = 0;
	if (dash) {
		*dash = 0;
		char *v = dash + 1, *e = strchr(v, '-'); /* "-py3.11" after an egg version */
		if (e)
			*e = 0;
		scopy(ver, vlen, v);
	}
	size_t o = 0;
	for (const char *c = stem; *c && o + 1 < nlen; c++) {
		if (*c == '-' || *c == '_' || *c == '.') {
			if (o && name[o - 1] != '-')
				name[o++] = '-';
		} else {
			name[o++] = (char)tolower((unsigned char)*c);
		}
	}
	while (o && name[o - 1] == '-')
		o--;
	name[o] = 0;
	return o > 0;
}

/* Handle one entry of a watched/scanned directory: report it (report) and
 * check an IDE extension against the catalog (check). */
static void note_entry(const char *kind, const char *scope, const char *dir, const char *entry,
                       const char *change, int report, int check)
{
	char sub[MAX_PATH], ver[48] = "", name[256];
	if (!strcmp(kind, "pip")) {
		if (report && pip_dist(entry, name, sizeof name, ver, sizeof ver))
			out_inventory(kind, name, ver, dir, change);
		return;
	}
	snprintf(sub, sizeof sub, "%s/%s", dir, entry);
	if (strcmp(change, "removed"))
		read_json_version(sub, ver, sizeof ver);
	if (scope && *scope)
		snprintf(name, sizeof name, "%s/%s", scope, entry);
	else
		scopy(name, sizeof name, entry);
	if (report)
		out_inventory(kind, name, ver, dir, change);
	if (check && !strcmp(kind, "vsx") && strcmp(change, "removed"))
		check_extension(entry, ver, dir);
}

static void scan_dir(const char *kind, const char *scope, const char *path, int report);

/* npm keeps scoped packages one level down: node_modules/@scope/name. */
static void cover_scope(const char *nm, const char *scope, int report)
{
	char sp[MAX_PATH];
	snprintf(sp, sizeof sp, "%s/%s", nm, scope);
	add_watch("npm", scope, sp);
	scan_dir("npm", scope, sp, report);
}

static void scan_dir(const char *kind, const char *scope, const char *path, int report)
{
	DIR *d = opendir(path);
	if (!d)
		return;
	int pip = !strcmp(kind, "pip");
	struct dirent *de;
	while ((de = readdir(d))) {
		if (de->d_name[0] == '.')
			continue;
		/* pip's .egg-info may be a plain file */
		if (de->d_type != DT_DIR && de->d_type != DT_LNK && de->d_type != DT_UNKNOWN &&
		    !(pip && de->d_type == DT_REG))
			continue;
		if (!strcmp(kind, "npm") && !(scope && *scope) && de->d_name[0] == '@') {
			cover_scope(path, de->d_name, report);
			continue;
		}
		if (report || !strcmp(kind, "vsx"))
			note_entry(kind, scope, path, de->d_name, "present", report, 1);
	}
	closedir(d);
}

/* Watch and scan one install directory if it exists. */
static void cover(const char *kind, const char *path, int report)
{
	struct stat st;
	if (stat(path, &st) || !S_ISDIR(st.st_mode))
		return;
	add_watch(kind, NULL, path);
	scan_dir(kind, NULL, path, report);
}

static void cover_glob(const char *kind, const char *pattern, int report)
{
	glob_t g;
	if (glob(pattern, GLOB_NOSORT | GLOB_ONLYDIR, NULL, &g) == 0)
		for (size_t i = 0; i < g.gl_pathc; i++)
			cover(kind, g.gl_pathv[i], report);
	globfree(&g);
}

/* Watch + optionally scan the usual install locations for one home dir. */
static void cover_home(const char *home, int report)
{
	struct { const char *kind, *rel; } locs[] = {
		{ "npm", "/.npm-global/lib/node_modules" },
		{ "npm", "/node_modules" },
		{ "vsx", "/.vscode/extensions" },
		{ "vsx", "/.vscode-server/extensions" },
		{ "vsx", "/.cursor/extensions" },
	};
	char path[MAX_PATH];
	for (size_t i = 0; i < sizeof locs / sizeof locs[0]; i++) {
		snprintf(path, sizeof path, "%s%s", home, locs[i].rel);
		cover(locs[i].kind, path, report);
	}
	snprintf(path, sizeof path, "%s/.local/lib/python3*/site-packages", home);
	cover_glob("pip", path, report);
}

/* System-wide installs: global npm, and the interpreter's own site/dist-
 * packages directories. Project-local node_modules and virtualenvs are not
 * inventoried (there is no bounded set of places to look). */
static void cover_global(int report)
{
	cover("npm", "/usr/lib/node_modules", report);
	cover("npm", "/usr/local/lib/node_modules", report);
	static const char *const pip[] = {
		"/usr/lib/python3/dist-packages",       "/usr/lib/python3*/site-packages",
		"/usr/lib/python3*/dist-packages",      "/usr/lib64/python3*/site-packages",
		"/usr/local/lib/python3*/site-packages", "/usr/local/lib/python3*/dist-packages",
	};
	for (size_t i = 0; i < sizeof pip / sizeof *pip; i++)
		cover_glob("pip", pip[i], report);
}

static void walk_homes(int report)
{
	cover_home("/root", report);
	setpwent();
	struct passwd *pw;
	while ((pw = getpwent()))
		if (pw->pw_uid >= 1000 && pw->pw_uid < 65534 && pw->pw_dir[0] == '/')
			cover_home(pw->pw_dir, report);
	endpwent();
}

int inventory_init(int inotify_fd)
{
	ifd = inotify_fd;
	cover_global(0);
	walk_homes(0);
	return 0;
}

void inventory_scan(void)
{
	cover_global(1);
	walk_homes(1);
}

void inventory_on_event(int wd, uint32_t mask, const char *name)
{
	if (mask & IN_IGNORED) { /* the directory is gone: free its row */
		drop_watch(wd);
		return;
	}
	if (!name || name[0] == '.')
		return;
	for (int i = 0; i < nwatch; i++) {
		struct watch *w = &watches[i];
		if (w->wd != wd)
			continue;
		int pip = !strcmp(w->kind, "pip");
		/* Packages and extensions are directories (pip's .egg-info may be
		 * a file); anything else in these directories is not a package. */
		if (!(mask & IN_ISDIR) && !pip)
			return;
		const char *change = (mask & (IN_DELETE | IN_MOVED_FROM)) ? "removed" : "installed";
		if (!strcmp(w->kind, "npm") && !w->scope[0] && name[0] == '@') {
			/* A new scope directory: watch it and report what is in it. */
			if (strcmp(change, "removed")) {
				char path[MAX_PATH], scope[64];
				scopy(path, sizeof path, w->path);
				scopy(scope, sizeof scope, name);
				char sp[MAX_PATH];
				snprintf(sp, sizeof sp, "%s/%s", path, scope);
				add_watch("npm", scope, sp); /* may move rows: w is not used after */
				DIR *d = opendir(sp);
				if (d) {
					struct dirent *de;
					while ((de = readdir(d)))
						if (de->d_name[0] != '.')
							note_entry("npm", scope, sp, de->d_name, "installed", 1, 0);
					closedir(d);
				}
			}
			return;
		}
		char kind[8], scope[64], path[MAX_PATH];
		scopy(kind, sizeof kind, w->kind);
		scopy(scope, sizeof scope, w->scope);
		scopy(path, sizeof path, w->path);
		note_entry(kind, scope, path, name, change, 1, 1);
		return;
	}
}

void inventory_dump(FILE *f) { (void)f; }

/* Retrospective forensics over the sensor's own record.
 *
 * io.security's "Immediate / retrospective forensics into any event, flow or
 * activity". Everything Wisp observes is already written as JSONL under
 * log_dir: execs and network flows (telemetry.jsonl), alerts (alerts.jsonl)
 * and inventory changes (inventory.jsonl). `wispd --search` answers questions
 * over that record after the fact, as a separate short-lived process -- the
 * running sensor pays nothing for it.
 *
 *   wispd -c wisp.conf --search [filter...]
 *     key=value     exact match on a field (type=flow actor=ai dport=443)
 *     q=text        substring anywhere in the event
 *     since=ISO     ts >= ISO prefix   (since=2026-10-21T20:00)
 *     until=ISO     ts <  ISO prefix
 *     tree=PID      the process PID, every descendant exec'd under it, and
 *                   all their alerts and flows -- "what did this process do"
 *     limit=N       newest N results (default 1000; 0 = count only)
 *
 * Every segment logrotate left behind is searched, not only the live files:
 * name.N and name.N.gz (the shipped wisp.logrotate) and dateext names
 * (name-YYYYMMDD[.gz]). Output is the matching JSON lines, merged across files
 * in time order; only the newest `limit` are held in memory. stderr says how
 * far back the record on this host goes.
 */
#include "wisp.h"

#include <errno.h>
#include <glob.h>
#include <stdlib.h>
#include <string.h>

#ifdef WISP_SENSOR_BPF /* that build links zlib (libbpf needs it) */
#include <zlib.h>
#define HAVE_ZLIB 1
#endif

/* Copy the value of "key": (string or number) into out. Returns 1 if found. */
static int field(const char *line, const char *key, char *out, size_t n)
{
	char pat[64];
	snprintf(pat, sizeof pat, "\"%s\":", key);
	const char *p = strstr(line, pat);
	if (!p)
		return 0;
	p += strlen(pat);
	while (*p == ' ' || *p == '\t')
		p++;
	size_t i = 0;
	if (*p == '"') {
		for (p++; *p && *p != '"' && i + 1 < n; p++) {
			if (*p == '\\' && p[1])
				p++;
			out[i++] = *p;
		}
	} else {
		for (; *p && *p != ',' && *p != '}' && i + 1 < n; p++)
			out[i++] = *p;
	}
	out[i] = 0;
	return 1;
}

#define MAXF 16
static struct { char key[32], val[256]; } flt[MAXF];
static int nflt;
static char since[40], until[40], q[256];
static long tree_root = -1;

static void oom(void)
{
	fprintf(stderr, "wispd: --search: out of memory\n");
	exit(1);
}

/* ---- the descendant set for tree= (a hash set of pids) ------------------ */

static long *tree;
static size_t ntree, captree;

static size_t th(long pid, size_t cap) { return ((uint64_t)pid * 0x9E3779B97F4A7C15ULL >> 17) & (cap - 1); }

static int in_tree(long pid)
{
	if (!captree)
		return 0;
	for (size_t i = th(pid, captree);; i = (i + 1) & (captree - 1)) {
		if (tree[i] == -1)
			return 0;
		if (tree[i] == pid)
			return 1;
	}
}

static void tree_put(long *t, size_t cap, long pid)
{
	size_t i = th(pid, cap);
	while (t[i] != -1 && t[i] != pid)
		i = (i + 1) & (cap - 1);
	t[i] = pid;
}

static void tree_add(long pid)
{
	if (pid < 0 || in_tree(pid))
		return;
	if ((ntree + 1) * 2 > captree) {
		size_t nc = captree ? captree * 2 : 256;
		long *nt = malloc(nc * sizeof *nt);
		if (!nt)
			oom();
		for (size_t i = 0; i < nc; i++)
			nt[i] = -1;
		for (size_t i = 0; i < captree; i++)
			if (tree[i] != -1)
				tree_put(nt, nc, tree[i]);
		free(tree);
		tree = nt;
		captree = nc;
	}
	tree_put(tree, captree, pid);
	ntree++;
}

/* ---- log segments ---------------------------------------------------------- */

static const char *FILES[] = { "telemetry.jsonl", "alerts.jsonl", "inventory.jsonl" };

static char **segs;
static size_t nsegs, nskipped;

static int is_gz(const char *p)
{
	size_t l = strlen(p);
	return l > 3 && !strcmp(p + l - 3, ".gz");
}

/* Rotation suffix: "" (live), ".N", ".N.gz", "-DIGITS", "-DIGITS.gz".
 * Returns a sort key: older segments sort first, the live file last. */
static long rot_key(const char *suffix, int *ok)
{
	*ok = 1;
	if (!*suffix)
		return -1; /* live file: newest */
	if (*suffix != '.' && *suffix != '-') {
		*ok = 0;
		return 0;
	}
	char *end;
	long n = strtol(suffix + 1, &end, 10);
	if (end == suffix + 1 || (*end && strcmp(end, ".gz"))) {
		*ok = 0;
		return 0;
	}
	/* .N: a larger N is older. -YYYYMMDD: a larger date is newer. */
	return *suffix == '.' ? n : 1000000000L - (n % 1000000000L);
}

struct segkey { char *path; long key; };

static int by_age(const void *a, const void *b)
{
	long ka = ((const struct segkey *)a)->key, kb = ((const struct segkey *)b)->key;
	/* larger key = older = first; the live file (-1) last */
	return ka == kb ? 0 : ka > kb ? -1 : 1;
}

static void list_segments(void)
{
	for (size_t fi = 0; fi < sizeof FILES / sizeof *FILES; fi++) {
		char pat[MAX_PATH + 32], base[MAX_PATH + 32];
		snprintf(base, sizeof base, "%s/%s", cfg.log_dir, FILES[fi]);
		snprintf(pat, sizeof pat, "%s*", base);
		glob_t g;
		if (glob(pat, 0, NULL, &g) != 0)
			continue;
		struct segkey *k = calloc(g.gl_pathc ? g.gl_pathc : 1, sizeof *k);
		if (!k)
			oom();
		size_t nk = 0, bl = strlen(base);
		for (size_t i = 0; i < g.gl_pathc; i++) {
			int ok;
			long key = rot_key(g.gl_pathv[i] + bl, &ok);
			if (!ok)
				continue;
#ifndef HAVE_ZLIB
			if (is_gz(g.gl_pathv[i])) {
				nskipped++;
				continue;
			}
#endif
			k[nk].path = strdup(g.gl_pathv[i]);
			if (!k[nk].path)
				oom();
			k[nk++].key = key;
		}
		globfree(&g);
		qsort(k, nk, sizeof *k, by_age);
		char **ns = realloc(segs, (nsegs + nk + 1) * sizeof *segs);
		if (!ns)
			oom();
		segs = ns;
		for (size_t i = 0; i < nk; i++)
			segs[nsegs++] = k[i].path;
		free(k);
	}
}

/* A line reader over a plain or gzip-compressed segment. Lines of any length
 * (an alert carries up to a 4 KiB command line, escaped). */
struct seg {
	FILE *f;
#ifdef HAVE_ZLIB
	gzFile gz;
#endif
};

static int seg_open(struct seg *s, const char *path)
{
	memset(s, 0, sizeof *s);
#ifdef HAVE_ZLIB
	if (is_gz(path)) {
		s->gz = gzopen(path, "rb");
		return s->gz ? 0 : -1;
	}
#endif
	s->f = fopen(path, "re");
	return s->f ? 0 : -1;
}

static ssize_t seg_line(struct seg *s, char **buf, size_t *cap)
{
	if (s->f)
		return getline(buf, cap, s->f);
#ifdef HAVE_ZLIB
	size_t n = 0;
	for (;;) {
		if (*cap - n < 2) {
			size_t nc = *cap ? *cap * 2 : 8192;
			char *nb = realloc(*buf, nc);
			if (!nb)
				oom();
			*buf = nb;
			*cap = nc;
		}
		if (!gzgets(s->gz, *buf + n, (int)(*cap - n > 1u << 30 ? 1u << 30 : *cap - n)))
			return n ? (ssize_t)n : -1;
		n += strlen(*buf + n);
		if (n && (*buf)[n - 1] == '\n')
			return (ssize_t)n;
	}
#else
	return -1;
#endif
}

static void seg_close(struct seg *s)
{
	if (s->f)
		fclose(s->f);
#ifdef HAVE_ZLIB
	if (s->gz)
		gzclose(s->gz);
#endif
}

/* Pass 1 for tree=: grow the descendant set until it stops changing, from
 * every record that carries a pid/ppid pair -- exec telemetry when it is on,
 * and alerts regardless (they carry pid+ppid too). Segments are read oldest
 * first and lines are parent-before-child in time order, so this converges
 * in one or two sweeps. The exec record is the complete parent/child map;
 * without it (telemetry=0, or shed by the governor) only alerting
 * descendants can be linked, so say so. */
static void build_tree(void)
{
	tree_add(tree_root);
	size_t execs = 0;
	char *line = NULL;
	size_t cap = 0;
	for (size_t before = 0; before != ntree;) {
		before = ntree;
		for (size_t si = 0; si < nsegs; si++) {
			struct seg s;
			if (seg_open(&s, segs[si]) < 0)
				continue;
			char v[32];
			while (seg_line(&s, &line, &cap) > 0) {
				if (field(line, "type", v, sizeof v) && !strcmp(v, "exec"))
					execs++;
				if (field(line, "ppid", v, sizeof v) && in_tree(atol(v)) &&
				    field(line, "pid", v, sizeof v))
					tree_add(atol(v));
			}
			seg_close(&s);
		}
	}
	free(line);
	if (!execs)
		fprintf(stderr, "wispd: tree=%ld: no exec telemetry on record (telemetry=0 or "
		        "shed under load); only descendants that alerted can be linked\n", tree_root);
}

static int match(const char *line)
{
	char v[512], ts[40];
	if (since[0] || until[0]) {
		if (!field(line, "ts", ts, sizeof ts))
			return 0;
		if (since[0] && strncmp(ts, since, strlen(since)) < 0)
			return 0;
		if (until[0] && strncmp(ts, until, strlen(until)) >= 0)
			return 0;
	}
	if (q[0] && !strstr(line, q))
		return 0;
	for (int i = 0; i < nflt; i++)
		if (!field(line, flt[i].key, v, sizeof v) || strcmp(v, flt[i].val))
			return 0;
	if (tree_root >= 0 && !(field(line, "pid", v, sizeof v) && in_tree(atol(v))))
		return 0;
	return 1;
}

/* ---- results: the newest `limit` hits, in a min-heap on (ts, order) ----- */

struct hit {
	char *line;
	char ts[40];
	uint64_t seq; /* reading order: keeps equal timestamps in file order */
};

static int older(const struct hit *a, const struct hit *b)
{
	int c = strcmp(a->ts, b->ts);
	return c ? c < 0 : a->seq < b->seq;
}

static void sift_down(struct hit *h, size_t n, size_t i)
{
	for (;;) {
		size_t l = 2 * i + 1, r = l + 1, m = i;
		if (l < n && older(&h[l], &h[m]))
			m = l;
		if (r < n && older(&h[r], &h[m]))
			m = r;
		if (m == i)
			return;
		struct hit t = h[i];
		h[i] = h[m];
		h[m] = t;
		i = m;
	}
}

static void sift_up(struct hit *h, size_t i)
{
	while (i) {
		size_t p = (i - 1) / 2;
		if (!older(&h[i], &h[p]))
			return;
		struct hit t = h[i];
		h[i] = h[p];
		h[p] = t;
		i = p;
	}
}

static int by_ts(const void *a, const void *b)
{
	const struct hit *x = a, *y = b;
	return older(x, y) ? -1 : older(y, x) ? 1 : 0;
}

int forensics_search(int argc, char **argv)
{
	long limit = 1000;
	for (int i = 0; i < argc; i++) {
		char *eq = strchr(argv[i], '=');
		if (!eq)
			continue;
		*eq = 0;
		const char *k = argv[i], *v = eq + 1;
		if (!strcmp(k, "since"))
			snprintf(since, sizeof since, "%s", v);
		else if (!strcmp(k, "until"))
			snprintf(until, sizeof until, "%s", v);
		else if (!strcmp(k, "q"))
			snprintf(q, sizeof q, "%s", v);
		else if (!strcmp(k, "tree"))
			tree_root = atol(v);
		else if (!strcmp(k, "limit"))
			limit = atol(v);
		else if (nflt < MAXF) {
			snprintf(flt[nflt].key, sizeof flt[nflt].key, "%s", k);
			snprintf(flt[nflt].val, sizeof flt[nflt].val, "%s", v);
			nflt++;
		}
	}
	list_segments();
	if (tree_root >= 0)
		build_tree();

	/* limit < 0: keep everything; 0: count only; else the newest `limit`. */
	struct hit *hits = NULL;
	size_t nh = 0, cap = 0, total = 0;
	uint64_t seq = 0;
	char oldest[40] = "", *line = NULL;
	size_t lcap = 0;
	for (size_t si = 0; si < nsegs; si++) {
		struct seg s;
		if (seg_open(&s, segs[si]) < 0)
			continue;
		char ts[40];
		while (seg_line(&s, &line, &lcap) > 0) {
			seq++;
			if (field(line, "ts", ts, sizeof ts) && ts[0] && (!oldest[0] || strcmp(ts, oldest) < 0))
				scopy(oldest, sizeof oldest, ts);
			if (!match(line))
				continue;
			total++;
			if (!limit)
				continue;
			struct hit h = { .seq = seq };
			if (!field(line, "ts", h.ts, sizeof h.ts))
				h.ts[0] = 0;
			if (limit > 0 && nh == (size_t)limit) {
				if (!older(&hits[0], &h))
					continue; /* older than everything kept */
				free(hits[0].line);
				if (!(h.line = strdup(line)))
					oom();
				hits[0] = h;
				sift_down(hits, nh, 0);
				continue;
			}
			if (nh == cap) {
				size_t nc = cap ? cap * 2 : 256;
				if (limit > 0 && nc > (size_t)limit)
					nc = (size_t)limit;
				struct hit *g = realloc(hits, nc * sizeof *hits);
				if (!g)
					oom();
				hits = g;
				cap = nc;
			}
			if (!(h.line = strdup(line)))
				oom();
			hits[nh++] = h;
			if (limit > 0)
				sift_up(hits, nh - 1);
		}
		seg_close(&s);
	}
	free(line);
	qsort(hits, nh, sizeof *hits, by_ts);
	for (size_t i = 0; i < nh; i++) {
		fputs(hits[i].line, stdout);
		if (!strchr(hits[i].line, '\n'))
			fputc('\n', stdout); /* a last line written without its newline */
		free(hits[i].line);
	}
	free(hits);
	fprintf(stderr, "wispd: %zu matching event(s)%s\n", total,
	        total > nh && limit ? " (showing the newest; raise limit=)" : "");
	fprintf(stderr, "wispd: searched %zu log file(s) in %s", nsegs, cfg.log_dir);
	if (oldest[0])
		fprintf(stderr, "; the oldest record is from %s", oldest);
	fputc('\n', stderr);
	if (nskipped)
		fprintf(stderr, "wispd: %zu compressed segment(s) not searched (this build has no zlib)\n", nskipped);
	if (since[0] && oldest[0] && strncmp(oldest, since, strlen(since)) > 0)
		fprintf(stderr, "wispd: since=%s is before the oldest record on file: older events have been "
		        "rotated away\n", since);
	for (size_t i = 0; i < nsegs; i++)
		free(segs[i]);
	free(segs);
	free(tree);
	return 0;
}

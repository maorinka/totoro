/* Structured output: JSONL to disk (alerts, telemetry, inventory) and,
 * when configured, mirrored to the console connection.
 *
 * The hot path (one line per exec) formats straight into a stack buffer
 * with a tiny append helper -- no fmemopen, no malloc, no fprintf -- and
 * emits the whole line in a single write(). That keeps per-event cost to
 * a few microseconds of CPU.
 */
#include "wisp.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static int fd_alert = -1, fd_tel = -1, fd_inv = -1;
static uint64_t alert_count;
uint64_t out_alert_count(void) { return alert_count; }
char hostname[256] = "localhost";

/* ---- minimal line builder ------------------------------------------
 * Every record must reach disk and the console as exactly one valid JSON
 * line, whatever the (attacker-controllable) field contents. So appends are
 * all-or-nothing: a field that does not fit is shortened (string values, cut
 * at a character boundary by jesc) or left out, never cut mid-token; and the
 * builder keeps BUF_RESERVE bytes back that only bend() may use, for the
 * ,"truncated":true marker and the closing "}\n". */
#define TRUNC_MARK ",\"truncated\":true"
#define BUF_RESERVE (sizeof TRUNC_MARK - 1 + 2)
struct buf {
	char *p;
	size_t n, cap;   /* cap excludes the reserve */
	int trunc;
};
static void binit(struct buf *b, char *line, size_t size)
{
	b->p = line;
	b->n = 0;
	b->cap = size - BUF_RESERVE;
	b->trunc = 0;
}
static size_t broom(const struct buf *b) { return b->cap > b->n ? b->cap - b->n : 0; }
/* Append exactly len bytes, or nothing (marking the record truncated). */
static int braw(struct buf *b, const char *s, size_t len)
{
	if (len > broom(b)) {
		b->trunc = 1;
		return 0;
	}
	memcpy(b->p + b->n, s, len);
	b->n += len;
	return 1;
}
static void blit(struct buf *b, const char *s) { braw(b, s, strlen(s)); }
/* Close the record: always fits, because binit() held the reserve back. */
static void bend(struct buf *b)
{
	if (b->trunc) {
		memcpy(b->p + b->n, TRUNC_MARK, sizeof TRUNC_MARK - 1);
		b->n += sizeof TRUNC_MARK - 1;
	}
	b->p[b->n++] = '}';
	b->p[b->n++] = '\n';
}
/* "key":"<escaped val>" -- the value is shortened to whatever room is left
 * (at a character boundary, so the string stays valid); if not even the key
 * fits, the field is left out. Either way the record is marked truncated. */
static void bkv(struct buf *b, const char *key, const char *val, int comma)
{
	size_t kl = strlen(key), over = (comma ? 1 : 0) + 1 + kl + 3 + 1; /* ,"key":"  " */
	if (over > broom(b)) {
		b->trunc = 1;
		return;
	}
	char *d = b->p + b->n;
	if (comma)
		*d++ = ',';
	*d++ = '"';
	memcpy(d, key, kl);
	d += kl;
	memcpy(d, "\":\"", 3);
	d += 3;
	int t = 0;
	/* room for the value is what is left after the overhead; +1 for jesc's NUL,
	 * which the closing quote then overwrites */
	size_t vl = jesc_ex(d, broom(b) - over + 1, val ? val : "", &t);
	d += vl;
	*d++ = '"';
	b->n = (size_t)(d - b->p);
	if (t)
		b->trunc = 1;
}
/* Append ,"key":<v> without snprintf (format parsing is costly per event). */
static void bint(struct buf *b, const char *key, long v)
{
	char tmp[64], num[24];
	int ni = sizeof num;
	size_t kl = strlen(key);
	unsigned long u = v < 0 ? -(unsigned long)v : (unsigned long)v;
	do {
		num[--ni] = '0' + (u % 10);
		u /= 10;
	} while (u);
	if (v < 0)
		num[--ni] = '-';
	if (kl > sizeof tmp - sizeof num - 4) {
		b->trunc = 1;
		return;
	}
	size_t n = 0;
	tmp[n++] = ',';
	tmp[n++] = '"';
	memcpy(tmp + n, key, kl);
	n += kl;
	tmp[n++] = '"';
	tmp[n++] = ':';
	memcpy(tmp + n, num + ni, sizeof num - ni);
	n += sizeof num - ni;
	braw(b, tmp, n);
}

/* ,"start":N,"pstart":N,"boot":"..." -- which process a pid named (pids are
 * reused; start counts clock ticks from boot, see struct proc). Left out when
 * the sensor does not know it. */
static void bident(struct buf *b, unsigned long long start, unsigned long long pstart)
{
	if (!start)
		return;
	bint(b, "start", (long)start);
	if (pstart)
		bint(b, "pstart", (long)pstart);
	bkv(b, "boot", boot_tag(), 1);
}

static int open_log(const char *name)
{
	char path[MAX_PATH];
	snprintf(path, sizeof path, "%s/%s", cfg.log_dir, name);
	int fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0640);
	if (fd < 0)
		logmsg("cannot open %s: using stderr", path);
	return fd;
}

void out_init(void)
{
	mkdir(cfg.log_dir, 0750);
	gethostname(hostname, sizeof hostname - 1);
	fd_alert = open_log("alerts.jsonl");
	if (cfg.telemetry)
		fd_tel = open_log("telemetry.jsonl");
	fd_inv = open_log("inventory.jsonl");
}

/* ISO-8601 ms timestamp, cached to the second so the strftime cost is
 * paid at most once per wall second regardless of event rate. */
static void iso_now(char *buf, size_t n)
{
	static time_t last_sec;
	static char cached[24];
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	if (ts.tv_sec != last_sec) {
		struct tm tm;
		gmtime_r(&ts.tv_sec, &tm);
		strftime(cached, sizeof cached, "%Y-%m-%dT%H:%M:%S", &tm);
		last_sec = ts.tv_sec;
	}
	snprintf(buf, n, "%s.%03ldZ", cached, ts.tv_nsec / 1000000);
}

/* Local log writes. A failed or short write (ENOSPC, EIO, quota) must not
 * vanish silently: it is counted (reported in the heartbeat), logged on the
 * first failure and then at most once a minute with the running count, and a
 * line left torn by a short write is terminated so the next record does not
 * fuse onto it. */
static uint64_t n_write_err, n_write_err_logged, last_err_log;
uint64_t out_write_errors(void) { return n_write_err; }

static void write_failed(const char *what, int err)
{
	n_write_err++;
	uint64_t now = now_ms();
	if (n_write_err_logged == 0 || now - last_err_log >= 60000) {
		logmsg("log write to %s failed: %s (%llu failed writes so far; records are being lost)",
		       what, strerror(err), (unsigned long long)n_write_err);
		n_write_err_logged = n_write_err;
		last_err_log = now;
	}
}

/* fds whose last write left a torn (unterminated) line: the next write to
 * them first ends it, so a full disk that recovers does not fuse records. */
static unsigned char torn[256];

static int write_raw(int fd, const char *buf, size_t len, size_t *done)
{
	size_t off = 0;
	while (off < len) {
		ssize_t w = write(fd, buf + off, len - off);
		if (w > 0) {
			off += (size_t)w;
			continue;
		}
		if (w < 0 && errno == EINTR)
			continue;
		*done = off;
		return w < 0 ? errno : ENOSPC;
	}
	*done = off;
	return 0;
}

static int write_all(int fd, const char *buf, size_t len, const char *what)
{
	size_t done;
	int err;
	if (fd >= 0 && fd < (int)sizeof torn && torn[fd]) {
		if ((err = write_raw(fd, "\n", 1, &done)) != 0) {
			write_failed(what, err);
			return -1;
		}
		torn[fd] = 0;
	}
	if ((err = write_raw(fd, buf, len, &done)) == 0)
		return 0;
	if (done > 0 && fd < (int)sizeof torn) {
		size_t d2;
		if (write_raw(fd, "\n", 1, &d2) != 0)
			torn[fd] = 1;   /* terminate it on the next write instead */
	}
	write_failed(what, err);
	return -1;
}

static void emit(int fd, const char *line, size_t len, const char *what)
{
	if (fd < 0) {
		(void)!write(2, line, len); /* no log file: stderr (journald) */
		return;
	}
	write_all(fd, line, len, what);
}

/* Telemetry is the one high-volume stream (a line per exec). Under
 * coalescing we drain many execs per wakeup, so we accumulate their lines
 * in a buffer and flush with a single write() per drain cycle instead of
 * one write() per event -- turning N syscalls into 1. out_flush() is called
 * by the main loop at the end of each batch. */
static char telbuf[256 * 1024];
static size_t teln;

static void tel_emit(const char *line, size_t len)
{
	if (fd_tel < 0) {
		emit(fd_tel, line, len, "telemetry.jsonl");
		return;
	}
	/* One telemetry line (at most ~30 KB, see out_telemetry) always fits in
	 * telbuf; flush first if this line would not fit the remaining space. */
	if (teln + len > sizeof telbuf) {
		write_all(fd_tel, telbuf, teln, "telemetry.jsonl");
		teln = 0;
	}
	memcpy(telbuf + teln, line, len);
	teln += len;
}

void out_telemetry(const struct proc *p)
{
	char line[JESC_MAX(MAX_CMD) + JESC_MAX(MAX_PATH) + 1024], ts[40];
	struct buf b;
	binit(&b, line, sizeof line);
	iso_now(ts, sizeof ts);
	braw(&b, "{", 1);
	bkv(&b, "ts", ts, 0);
	bkv(&b, "type", "exec", 1);
	bkv(&b, "host", hostname, 1);
	bint(&b, "pid", p->pid);
	bint(&b, "ppid", p->ppid);
	bident(&b, p->start, p->pstart);
	bint(&b, "uid", p->uid);
	bkv(&b, "actor", actor_name(p->actor), 1);
	bkv(&b, "actor_src", p->actor_src, 1);
	bkv(&b, "comm", p->comm, 1);
	bkv(&b, "exe", p->exe, 1);
	bkv(&b, "cmd", p->cmd, 1);
	if (p->cmd_truncated)
		blit(&b, ",\"cmd_truncated\":true");
	bend(&b);
	tel_emit(line, b.n);
}

void out_alert(const char *rule, const char *mitre, const char *title, enum sev sev,
               const char *action, const struct proc *p, const char *extra_json)
{
	char line[JESC_MAX(MAX_CMD) + JESC_MAX(MAX_PATH) + 3072], ts[40];
	struct buf b;
	binit(&b, line, sizeof line);
	iso_now(ts, sizeof ts);
	braw(&b, "{", 1);
	bkv(&b, "ts", ts, 0);
	bkv(&b, "type", "alert", 1);
	bkv(&b, "host", hostname, 1);
	bkv(&b, "group", cfg.group, 1);
	bkv(&b, "rule", rule, 1);
	if (mitre && *mitre)
		bkv(&b, "mitre", mitre, 1);
	bkv(&b, "title", title, 1);
	bkv(&b, "severity", sev_name(sev), 1);
	bkv(&b, "action", action, 1);
	bkv(&b, "actor", actor_name(p->actor), 1);
	bkv(&b, "actor_src", p->actor_src, 1);
	bint(&b, "pid", p->pid);
	bint(&b, "ppid", p->ppid);
	bident(&b, p->start, p->pstart);
	bint(&b, "uid", p->uid);
	bkv(&b, "comm", p->comm, 1);
	bkv(&b, "exe", p->exe, 1);
	bkv(&b, "cmd", p->cmd, 1);
	if (p->cmd_truncated)
		blit(&b, ",\"cmd_truncated\":true");
	if (extra_json && *extra_json) {
		size_t el = strlen(extra_json);
		if (el + 1 <= broom(&b)) {   /* all or nothing: never half a fragment */
			braw(&b, ",", 1);
			braw(&b, extra_json, el);
		} else {
			b.trunc = 1;
		}
	}
	bend(&b);
	alert_count++;
	emit(fd_alert, line, b.n, "alerts.jsonl");
	console_send(line, b.n);
}

void out_inventory(const char *kind, const char *name, const char *ver,
                   const char *where, const char *change)
{
	char line[2 * JESC_MAX(MAX_PATH) + 1024], ts[40];
	struct buf b;
	binit(&b, line, sizeof line);
	iso_now(ts, sizeof ts);
	braw(&b, "{", 1);
	bkv(&b, "ts", ts, 0);
	bkv(&b, "type", "inventory", 1);
	bkv(&b, "host", hostname, 1);
	bkv(&b, "kind", kind, 1);
	bkv(&b, "name", name, 1);
	if (ver && *ver)
		bkv(&b, "version", ver, 1);
	bkv(&b, "where", where, 1);
	bkv(&b, "change", change, 1);
	bend(&b);
	emit(fd_inv, line, b.n, "inventory.jsonl");
	console_send(line, b.n);
}

void out_heartbeat(uint64_t execs, uint64_t alerts, double cpu_pct, long rss_kb)
{
	char line[1536], ts[40], num[32];
	struct buf b;
	binit(&b, line, sizeof line);
	iso_now(ts, sizeof ts);
	braw(&b, "{", 1);
	bkv(&b, "ts", ts, 0);
	bkv(&b, "type", "heartbeat", 1);
	bkv(&b, "host", hostname, 1);
	bkv(&b, "group", cfg.group, 1);
	bint(&b, "execs", (long)execs);
	bint(&b, "alerts_total", (long)alerts);
	snprintf(num, sizeof num, ",\"cpu_pct\":%.4f", cpu_pct);
	blit(&b, num);
	bint(&b, "rss_kb", rss_kb);
	bkv(&b, "mode", cfg.mode == MODE_ENFORCE ? "enforce" : "monitor", 1);
	/* Coverage and delivery health, so loss is visible at the console rather
	 * than silent: the governor's current in-kernel sampling divisor (1 = every
	 * exec evaluated) and the execs it has dropped, lines dropped because the
	 * console link was congested, and failed local log writes. ring_lost
	 * counts exec records the kernel could not queue (ring buffer full). */
	bint(&b, "sample_n", (long)governor_sample_n());
	bint(&b, "sampled_drops", (long)proc_sampled_drops());
	bint(&b, "ring_lost", (long)proc_ring_lost());
	bint(&b, "console_dropped", (long)console_dropped_lines());
	bint(&b, "log_write_errors", (long)n_write_err);
	char eco[128], rt[160];
	ecosystem_json(eco, sizeof eco);
	snprintf(rt, sizeof rt, ",\"runtimes\":%s", eco);
	blit(&b, rt);
	bend(&b);
	console_send(line, b.n);
}

/* A local audit record (alerts.jsonl only, not sent to the console): who
 * changed the sensor's behaviour remotely, e.g. a console mode switch. */
void out_audit(const char *event, const char *detail, const char *peer)
{
	char line[2048], ts[40];
	struct buf b;
	binit(&b, line, sizeof line);
	iso_now(ts, sizeof ts);
	braw(&b, "{", 1);
	bkv(&b, "ts", ts, 0);
	bkv(&b, "type", "audit", 1);
	bkv(&b, "host", hostname, 1);
	bkv(&b, "event", event, 1);
	bkv(&b, "detail", detail, 1);
	bkv(&b, "peer", peer, 1);
	bend(&b);
	emit(fd_alert, line, b.n, "alerts.jsonl");
}

/* One outbound network flow (telemetry stream, so it is searchable later). */
void out_flow(pid_t pid, unsigned long long start, uid_t uid, const char *comm, enum actor a,
              const char *asrc, const char *dest, int dport, const char *verdict)
{
	char line[2048], ts[40];
	struct buf b;
	binit(&b, line, sizeof line);
	iso_now(ts, sizeof ts);
	braw(&b, "{", 1);
	bkv(&b, "ts", ts, 0);
	bkv(&b, "type", "flow", 1);
	bkv(&b, "host", hostname, 1);
	bint(&b, "pid", pid);
	bident(&b, start, 0);
	bint(&b, "uid", uid);
	bkv(&b, "actor", actor_name(a), 1);
	bkv(&b, "actor_src", asrc, 1);
	bkv(&b, "comm", comm, 1);
	bkv(&b, "dest", dest, 1);
	bint(&b, "dport", dport);
	bkv(&b, "verdict", verdict, 1);
	bend(&b);
	tel_emit(line, b.n);
}

/* SIGHUP: reopen the log files by name, so logrotate can rename them away
 * (create + postrotate kill -HUP) instead of copytruncate, which loses the
 * lines written between its copy and its truncate. Buffered telemetry goes
 * to the old file first; a file that cannot be reopened keeps its old fd. */
void out_reopen(void)
{
	out_flush();
	struct { int *fd; const char *name; int on; } f[] = {
		{ &fd_alert, "alerts.jsonl", 1 },
		{ &fd_tel, "telemetry.jsonl", cfg.telemetry },
		{ &fd_inv, "inventory.jsonl", 1 },
	};
	mkdir(cfg.log_dir, 0750);
	for (size_t i = 0; i < sizeof f / sizeof *f; i++) {
		if (!f[i].on)
			continue;
		int nfd = open_log(f[i].name);
		if (nfd < 0)
			continue;
		if (*f[i].fd >= 0) {
			if (*f[i].fd < (int)sizeof torn)
				torn[*f[i].fd] = 0;
			close(*f[i].fd);
		}
		if (nfd < (int)sizeof torn)
			torn[nfd] = 0;
		*f[i].fd = nfd;
	}
	logmsg("log files reopened (SIGHUP)");
}

void out_flush(void)
{
	if (teln) {
		write_all(fd_tel, telbuf, teln, "telemetry.jsonl");
		teln = 0;
	}
}

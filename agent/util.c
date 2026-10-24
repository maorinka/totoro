#include "wisp.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* Length of the well-formed UTF-8 sequence at s (1..4 bytes), or 0 when the
 * bytes there are not one: a stray continuation byte, an overlong form, a
 * UTF-16 surrogate, a code point above U+10FFFF, or a sequence cut short by
 * the end of the string. s is NUL-terminated, so the short-circuit tests
 * below never read past the terminator. */
static int utf8_seq(const unsigned char *s)
{
	unsigned c = s[0];
	if (c < 0x80)
		return 1;
	if (c >= 0xC2 && c <= 0xDF)
		return (s[1] & 0xC0) == 0x80 ? 2 : 0;
	if (c >= 0xE0 && c <= 0xEF) {
		unsigned lo = c == 0xE0 ? 0xA0 : 0x80, hi = c == 0xED ? 0x9F : 0xBF;
		return s[1] >= lo && s[1] <= hi && (s[2] & 0xC0) == 0x80 ? 3 : 0;
	}
	if (c >= 0xF0 && c <= 0xF4) {
		unsigned lo = c == 0xF0 ? 0x90 : 0x80, hi = c == 0xF4 ? 0x8F : 0xBF;
		return s[1] >= lo && s[1] <= hi && (s[2] & 0xC0) == 0x80 && (s[3] & 0xC0) == 0x80 ? 4 : 0;
	}
	return 0;
}

/* Escape src as the body of a JSON string. The output is always valid JSON
 * text, whatever bytes src holds: '"' and '\\' are backslash-escaped,
 * control bytes become \u00XX, well-formed UTF-8 is copied through, and any
 * byte that is not part of well-formed UTF-8 is emitted as \u00XX (its
 * Latin-1 code point) so the line still parses at the console. Output never
 * ends inside an escape or a multi-byte character; when src does not fit,
 * *trunc (if given) is set. Returns the bytes written, excluding the NUL. */
size_t jesc_ex(char *dst, size_t cap, const char *src, int *trunc)
{
	static const char hex[] = "0123456789abcdef";
	const unsigned char *s = (const unsigned char *)src;
	size_t n = 0;
	if (trunc)
		*trunc = 0;
	if (!cap) {
		if (trunc && *s)
			*trunc = 1;
		return 0;
	}
	for (;;) {
		/* Fast path: one memcpy for the run of printable ASCII that needs
		 * no escaping -- nearly all exe paths and command lines. */
		size_t run = 0;
		while (s[run] >= 0x20 && s[run] < 0x80 && s[run] != '"' && s[run] != '\\')
			run++;
		if (run) {
			size_t room = cap - 1 - n;
			if (run > room) {
				memcpy(dst + n, s, room);
				n += room;
				if (trunc)
					*trunc = 1;
				break;
			}
			memcpy(dst + n, s, run);
			n += run;
			s += run;
		}
		unsigned c = *s;
		if (!c)
			break;
		char tmp[6];
		const char *out = tmp;
		size_t tl, adv = 1;
		if (c == '"' || c == '\\') {
			tmp[0] = '\\';
			tmp[1] = (char)c;
			tl = 2;
		} else if (c >= 0x80 && (tl = (size_t)utf8_seq(s)) != 0) {
			out = (const char *)s; /* well-formed multi-byte character */
			adv = tl;
		} else {
			/* control byte, or a byte that is not valid UTF-8 */
			tmp[0] = '\\';
			tmp[1] = 'u';
			tmp[2] = '0';
			tmp[3] = '0';
			tmp[4] = hex[c >> 4];
			tmp[5] = hex[c & 15];
			tl = 6;
		}
		if (n + tl > cap - 1) {
			if (trunc)
				*trunc = 1;
			break;
		}
		memcpy(dst + n, out, tl);
		n += tl;
		s += adv;
	}
	dst[n] = 0;
	return n;
}

size_t jesc(char *dst, size_t cap, const char *src)
{
	return jesc_ex(dst, cap, src, NULL);
}

void jstr(FILE *f, const char *key, const char *val, int comma)
{
	char buf[JESC_MAX(MAX_CMD)];
	jesc(buf, sizeof buf, val ? val : "");
	fprintf(f, "%s\"%s\":\"%s\"", comma ? "," : "", key, buf);
}

/* One openat+fstat+read+close of at most cap-1 bytes, NUL-terminated.
 * O_NONBLOCK, and only a regular file is read: the sensor is single-threaded,
 * so a FIFO (or a device) planted where a file is expected must not be able
 * to hang it in open() or read(). */
static ssize_t read_reg(int dirfd, const char *path, char *buf, size_t cap, int flags)
{
	if (!cap)
		return -1;
	buf[0] = 0;
	int fd = openat(dirfd, path, O_RDONLY | O_CLOEXEC | O_NOCTTY | O_NONBLOCK | flags);
	if (fd < 0)
		return -1;
	struct stat st;
	if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode)) {
		close(fd);
		errno = EINVAL;
		return -1;
	}
	ssize_t n;
	do
		n = read(fd, buf, cap - 1);
	while (n < 0 && errno == EINTR);
	close(fd);
	if (n < 0)
		return -1;
	buf[n] = 0;
	return n;
}

/* Returns bytes read, NUL-terminated. For /proc and the sensor's own files. */
ssize_t read_small(int dirfd, const char *path, char *buf, size_t cap)
{
	return read_reg(dirfd, path, buf, cap, 0);
}

/* A file in a directory some user controls (a home directory, a package
 * directory): a symlink as the last component is refused too, so the sensor
 * cannot be pointed at a file the user could not read themselves. */
ssize_t read_user(int dirfd, const char *path, char *buf, size_t cap)
{
	return read_reg(dirfd, path, buf, cap, O_NOFOLLOW);
}

/* "pid (comm) state ppid pgrp session tty_nr ... starttime(22) ...". comm
 * may hold spaces and parentheses: parse from the last ')'. */
int parse_stat(const char *buf, int *ppid, int *sid, int *tty, unsigned long long *start)
{
	const char *r = strrchr(buf, ')');
	int pp = 0, se = 0, tt = 0;
	unsigned long long st = 0;
	if (!r || sscanf(r + 1, " %*c %d %*d %d %d %*d %*u %*u %*u %*u %*u %*u %*u %*d %*d %*d %*d %*d %*d %llu",
	                 &pp, &se, &tt, &st) != 4)
		return -1;
	if (ppid)
		*ppid = pp;
	if (sid)
		*sid = se;
	if (tty)
		*tty = tt;
	if (start)
		*start = st;
	return 0;
}

int proc_start(pid_t pid, unsigned long long *start)
{
	char path[48], buf[1024];
	snprintf(path, sizeof path, "/proc/%d/stat", (int)pid);
	if (read_small(AT_FDCWD, path, buf, sizeof buf) <= 0)
		return -1;
	return parse_stat(buf, NULL, NULL, NULL, start);
}

/* The first 8 hex digits of the kernel's boot id. Start times count from
 * boot, so records name a process by (boot, pid, start): pids and early
 * start times repeat from one boot to the next. */
const char *boot_tag(void)
{
	static char tag[9];
	if (!tag[0]) {
		char buf[64];
		size_t o = 0;
		if (read_small(AT_FDCWD, "/proc/sys/kernel/random/boot_id", buf, sizeof buf) > 0)
			for (const char *c = buf; *c && o < 8; c++)
				if ((*c >= '0' && *c <= '9') || (*c >= 'a' && *c <= 'f'))
					tag[o++] = *c;
		if (o < 8)
			scopy(tag, sizeof tag, "00000000");
		tag[8] = 0;
	}
	return tag;
}

const char *sev_name(enum sev s)
{
	static const char *n[] = { "info", "low", "medium", "high", "critical" };
	return n[s];
}

const char *actor_name(enum actor a)
{
	static const char *n[] = { "unknown", "human", "ai", "code", "ci", "service" };
	return n[a];
}

const char *base_name(const char *p)
{
	const char *s = strrchr(p, '/');
	return s ? s + 1 : p;
}

/* Milliseconds on a MONOTONIC clock, for intervals, deadlines and rate
 * limits only (console retry, governor cadence, netpolicy buckets). A wall
 * clock step (NTP correction, RTC fixed at boot, VM snapshot restore) must not
 * stall or speed up any of them. Record timestamps use CLOCK_REALTIME
 * separately (output.c iso_now). Never 0, so callers may use 0 as "unset". */
uint64_t now_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000 + 1;
}

/* Strict integer parse: the whole value must be a base-10 integer within
 * [lo, hi]. Returns 0 on success, -1 otherwise (out untouched). */
int parse_long(const char *s, long lo, long hi, long *out)
{
	char *end;
	if (!s || !*s)
		return -1;
	errno = 0;
	long v = strtol(s, &end, 10);
	if (errno || end == s || *end || v < lo || v > hi)
		return -1;
	*out = v;
	return 0;
}

/* Boolean config value: 1/0, yes/no, true/false, on/off. */
int parse_bool(const char *s, int *out)
{
	static const char *const t[] = { "1", "yes", "true", "on" };
	static const char *const f[] = { "0", "no", "false", "off" };
	for (int i = 0; i < 4; i++) {
		if (!strcasecmp(s, t[i])) {
			*out = 1;
			return 0;
		}
		if (!strcasecmp(s, f[i])) {
			*out = 0;
			return 0;
		}
	}
	return -1;
}

/* Configuration problems found while loading policy. A malformed line is
 * always skipped -- never reinterpreted as something more permissive -- and
 * counted, so `wispd --check-config` can fail a CI or MDM pipeline. */
int cfg_problems;

/* Cut a trailing "  # comment" (a '#' preceded by whitespace) off a line. */
void strip_comment(char *s)
{
	for (char *p = s; *p; p++)
		if (*p == '#' && (p == s || p[-1] == ' ' || p[-1] == '\t')) {
			*p = 0;
			return;
		}
}

void cfg_problem(const char *file, int line, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	if (line > 0)
		fprintf(stderr, "wispd: %s:%d: ", file, line);
	else
		fprintf(stderr, "wispd: %s: ", file);
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
	va_end(ap);
	cfg_problems++;
}

void logmsg(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	fputs("wispd: ", stderr);
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
	va_end(ap);
}

/* ns of CPU consumed by the whole process (every thread, user+system).
 * CLOCK_PROCESS_CPUTIME_ID reads the same scheduler accounting as
 * /proc/self/schedstat, but is always available (no CONFIG_SCHED_INFO, no
 * mounted /proc needed) and costs one syscall instead of open+read+close. */
static int self_runtime_ns(uint64_t *ns)
{
	struct timespec ts;
	if (clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts) != 0)
		return -1;
	*ns = (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
	return 0;
}

/* One CPU sampler: average % of one core since its previous sample. The
 * first sample only takes the baseline (returns 0). A failed or backwards
 * reading also returns 0 and re-baselines, instead of producing an absurd
 * value that would slam the governor. */
struct cpu_sampler {
	uint64_t last_ns, last_wall;
	int primed;
};

static double cpu_sample(struct cpu_sampler *cs)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	uint64_t wall = (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec, run;
	if (self_runtime_ns(&run) != 0) {
		cs->primed = 0;
		return 0;
	}
	double pct = 0;
	if (cs->primed && wall > cs->last_wall && run >= cs->last_ns)
		pct = 100.0 * (double)(run - cs->last_ns) / (double)(wall - cs->last_wall);
	cs->last_ns = run;
	cs->last_wall = wall;
	cs->primed = 1;
	return pct;
}

static struct cpu_sampler hb_sampler, gov_sampler;

/* Heartbeat sampler: average CPU% of one core since the previous call. */
double self_cpu_pct(void) { return cpu_sample(&hb_sampler); }

/* Resident set size in KiB from /proc/self/status. */
long self_rss_kb(void)
{
	char buf[2048];
	if (read_small(AT_FDCWD, "/proc/self/status", buf, sizeof buf) <= 0)
		return 0;
	char *p = strstr(buf, "VmRSS:");
	return p ? strtol(p + 6, NULL, 10) : 0;
}

/* Fast bounded string copy (strlcpy-ish): avoids snprintf's format parsing
 * in the per-event hot path. Returns bytes written (excl NUL). */
size_t scopy(char *dst, size_t cap, const char *src)
{
	size_t i = 0;
	if (!cap)
		return 0;
	for (; i + 1 < cap && src[i]; i++)
		dst[i] = src[i];
	dst[i] = 0;
	return i;
}

/* Governor's own CPU sampler (separate state from self_cpu_pct so the two
 * callers don't corrupt each other's deltas). */
double gov_cpu_sample(void) { return cpu_sample(&gov_sampler); }

/* Length (ms) of the window the next gov_cpu_sample() would average over. */
uint64_t gov_cpu_window_ms(void)
{
	if (!gov_sampler.primed)
		return 0;
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	uint64_t wall = (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
	return wall > gov_sampler.last_wall ? (wall - gov_sampler.last_wall) / 1000000 : 0;
}

/* Take both baselines at startup so the first real samples are valid. */
void cpu_samplers_prime(void)
{
	(void)cpu_sample(&hb_sampler);
	(void)cpu_sample(&gov_sampler);
}

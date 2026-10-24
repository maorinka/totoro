/* First-seen program anomaly detection.
 *
 * io.security's "Behavior Tracking, Signatures & Anomalies": signatures are the
 * rules engine; this is the anomaly half. Every host has a stable set of
 * programs it runs. After a learning window, a program path this host has
 * NEVER executed before is an anomaly worth a look -- a dropped binary, a
 * freshly installed tool, an AI agent running something new.
 *
 * The "ever seen" set is a 1 Mbit Bloom filter (128 KiB, 3 probes from one
 * 64-bit FNV hash): constant memory, a few bit operations per exec, no
 * allocation. A false positive only means a novel program is (rarely) taken
 * for a known one. The filter is persisted to state_dir so a restart does not
 * relearn the host or re-alert on everything.
 */
#include "wisp.h"

#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define BLOOM_BITS (1u << 20)
#define MAGIC 0x57495350414e4f4dULL /* "WISPANOM" */

static uint8_t bloom[BLOOM_BITS / 8];
static uint64_t learn_start;  /* epoch seconds the learning window began */
/* Header: MAGIC, learn_start, FNV(hostname). A baseline is only restored
 * for the host that learned it, so a golden image carrying another host's
 * seen.bloom does not skip this host's learning window. */
static int dirty, enabled;
static uint64_t n_anom;

uint64_t anomaly_count(void) { return n_anom; }

static uint64_t fnv(const char *s)
{
	uint64_t h = 1469598103934665603ULL;
	for (; *s; s++)
		h = (h ^ (uint8_t)*s) * 1099511628211ULL;
	return h;
}

/* Test-and-set: returns 1 if the key was (probably) already present. */
static int bloom_add(uint64_t h)
{
	int present = 1;
	uint32_t a = (uint32_t)h, b = (uint32_t)(h >> 32) | 1;
	for (int i = 0; i < 3; i++) {
		uint32_t bit = (a + i * b) & (BLOOM_BITS - 1);
		uint8_t m = 1u << (bit & 7);
		if (!(bloom[bit >> 3] & m)) {
			present = 0;
			bloom[bit >> 3] |= m;
		}
	}
	return present;
}

static void path_of(char *out, size_t n)
{
	snprintf(out, n, "%s/seen.bloom", cfg.state_dir);
}

void anomaly_init(void)
{
	enabled = cfg.anomaly_learn >= 0;
	if (!enabled)
		return;
	char path[MAX_PATH];
	path_of(path, sizeof path);
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	uint64_t hdr[3];
	if (fd >= 0 && read(fd, hdr, sizeof hdr) == sizeof hdr && hdr[0] == MAGIC &&
	    hdr[2] == fnv(hostname) && read(fd, bloom, sizeof bloom) == sizeof bloom) {
		learn_start = hdr[1];
		logmsg("anomaly: restored first-seen baseline (%s)", path);
	} else {
		if (fd >= 0)
			logmsg("anomaly: baseline at %s is not this host's (or is damaged); relearning", path);
		memset(bloom, 0, sizeof bloom);
		learn_start = (uint64_t)time(NULL);
		dirty = 1;
		logmsg("anomaly: learning program baseline for %ds", cfg.anomaly_learn);
	}
	if (fd >= 0)
		close(fd);
}

void anomaly_check(struct proc *p)
{
	if (!enabled || !p->exe[0])
		return;
	if (bloom_add(fnv(p->exe)))
		return;               /* seen before: the common, cheap path */
	dirty = 1;
	if ((uint64_t)time(NULL) < learn_start + (uint64_t)cfg.anomaly_learn)
		return;               /* still learning this host's baseline */
	n_anom++;
	enum sev sev = (p->actor == ACTOR_AI || p->actor == ACTOR_CODE) ? SEV_MEDIUM : SEV_LOW;
	out_alert("ANOM-001", "T1204", "First execution of a program never seen on this host",
	          sev, "alert", p, NULL);
}

/* Persist the baseline (housekeeping tick, and at shutdown). */
void anomaly_save(void)
{
	if (!enabled || !dirty)
		return;
	char path[MAX_PATH], tmp[MAX_PATH + 8];
	path_of(path, sizeof path);
	snprintf(tmp, sizeof tmp, "%s.tmp", path);
	mkdir(cfg.state_dir, 0700);
	int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (fd < 0)
		return;
	uint64_t hdr[3] = { MAGIC, learn_start, fnv(hostname) };
	int ok = write(fd, hdr, sizeof hdr) == sizeof hdr &&
	         write(fd, bloom, sizeof bloom) == sizeof bloom;
	close(fd);
	if (ok && rename(tmp, path) == 0)
		dirty = 0;
}

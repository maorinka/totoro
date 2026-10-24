/* Host identity & root of trust.
 *
 * io.security pairs a hardware-backed host identity (TPM / Secure Enclave)
 * with mutual TLS. Wisp establishes a stable host identity rooted in the
 * strongest anchor the machine actually provides, and reports which tier
 * it got -- so the console can see, per host, whether identity is hardware-
 * backed or only software-stable, rather than pretending every host has a
 * TPM.
 *
 * Tiers, strongest first:
 *   tpm        - the mTLS client key is TPM-resident (`tpm = 1`; the link only
 *                comes up when the tpm2 provider loaded it, see console.c),
 *                so it cannot be copied off the host. A TPM device that the
 *                key does not live in anchors nothing and is not reported.
 *   dmi        - SMBIOS/DMI product UUID (hardware-burned on real machines)
 *   machine-id - systemd /etc/machine-id (software, stable across reboots)
 *   generated  - a key we generated and persisted (weakest; first boot)
 *
 * The mutual-TLS layer (console.c) authenticates the host with its client
 * certificate regardless of tier; the tier describes how hard the private
 * key is to steal. It is the sensor's own claim (sent in hello).
 */
#include "wisp.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include <openssl/sha.h>

static char host_id[65];
static char host_tier[16];

static int readfile(const char *path, char *buf, size_t cap)
{
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	ssize_t n = read(fd, buf, cap - 1);
	close(fd);
	if (n <= 0)
		return -1;
	buf[n] = 0;
	return (int)n;
}

/* A text identifier (DMI UUID, machine-id) with its trailing newline and
 * blanks dropped; 0 when the file is missing, empty or only whitespace. */
static size_t read_id(const char *path, char *buf, size_t cap)
{
	int n = readfile(path, buf, cap);
	if (n <= 0)
		return 0;
	size_t l = (size_t)n;
	/* Hashed as read before; the newline is kept for a stable host_id, and
	 * only a value with visible content counts. */
	for (size_t i = 0; i < l; i++)
		if (buf[i] > ' ')
			return l;
	return 0;
}

#define SEED_LEN 32

/* Persist a random seed the first time, reuse it after. The seed is binary
 * and hashed over its full length. Seeds written by older sensors were hashed
 * up to their first NUL byte; that is kept for any old seed with at least 8
 * bytes before a NUL (its host_id must not change), and only a seed whose
 * NUL-cut prefix is shorter -- a weak, possibly shared id -- moves to the
 * full length. */
static int persisted_seed(unsigned char *out, size_t *len)
{
	char path[MAX_PATH], tmp[MAX_PATH + 8];
	snprintf(path, sizeof path, "%s/host.seed", cfg.state_dir);
	unsigned char buf[256];
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd >= 0) {
		ssize_t n = read(fd, buf, sizeof buf - 1);
		close(fd);
		size_t cut = n > 0 ? strnlen((const char *)buf, (size_t)n) : 0;
		if (cut >= 8 || n == SEED_LEN) {
			*len = cut >= 8 ? cut : SEED_LEN;
			memcpy(out, buf, *len);
			return 0;
		}
		logmsg("identity: %s is empty or damaged; generating a new seed", path);
	}
	int r = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
	if (r < 0 || read(r, out, SEED_LEN) != SEED_LEN) {
		if (r >= 0)
			close(r);
		return -1;
	}
	close(r);
	*len = SEED_LEN;
	/* No NUL in a new seed: an older sensor reading it back (a downgrade)
	 * then hashes the same 32 bytes. */
	for (int i = 0; i < SEED_LEN; i++)
		if (!out[i])
			out[i] = 0xa5;
	mkdir(cfg.state_dir, 0700);
	snprintf(tmp, sizeof tmp, "%s.tmp", path);
	int w = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
	int ok = w >= 0 && write(w, out, SEED_LEN) == SEED_LEN && fsync(w) == 0;
	if (w >= 0)
		close(w);
	if (!ok || rename(tmp, path) < 0) {
		logmsg("identity: cannot persist %s (%s): host_id will change at the next start", path,
		       strerror(errno));
		unlink(tmp);
	}
	return 0;
}

/* Resolve the identity once at startup. host_id is a SHA-256 hex of the
 * anchor material, so it is stable but does not leak the raw UUID/seed. */
void identity_init(void)
{
	unsigned char anchor[256];
	size_t alen = 0;
	const char *tier = NULL;
	struct stat st;
	int tpm_dev = stat("/dev/tpmrm0", &st) == 0 || stat("/dev/tpm0", &st) == 0;

	/* Anchor order. Hosts with a TPM device always anchored on machine-id
	 * first; keep that so their host_id does not change. */
	if ((cfg.tpm || tpm_dev) && (alen = read_id("/etc/machine-id", (char *)anchor, sizeof anchor)))
		tier = "machine-id";
	else if ((alen = read_id("/sys/class/dmi/id/product_uuid", (char *)anchor, sizeof anchor)))
		tier = "dmi";
	else if ((alen = read_id("/etc/machine-id", (char *)anchor, sizeof anchor)))
		tier = "machine-id";
	else if (persisted_seed(anchor, &alen) == 0)
		tier = "generated";

	if (!tier) {
		snprintf(host_tier, sizeof host_tier, "none");
		snprintf(host_id, sizeof host_id, "unknown");
		return;
	}
	snprintf(host_tier, sizeof host_tier, "%s", cfg.tpm ? "tpm" : tier);

	unsigned char d[SHA256_DIGEST_LENGTH];
	SHA256(anchor, alen, d);
	static const char hex[] = "0123456789abcdef";
	for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
		host_id[i * 2] = hex[d[i] >> 4];
		host_id[i * 2 + 1] = hex[d[i] & 15];
	}
	host_id[64] = 0;
}

const char *identity_id(void) { return host_id[0] ? host_id : "unknown"; }
const char *identity_tier(void) { return host_tier[0] ? host_tier : "none"; }

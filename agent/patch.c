/* Runtime mitigation without redeployment.
 *
 * io.security's "runtime vulnerability patching & mitigation ... without
 * redeployment": neutralise a vulnerable code path in a *running* process
 * without restarting it. Wisp does this with ptrace -- it attaches to the
 * target, overwrites the entry of the vulnerable function with a safe stub
 * (return immediately, optionally with a chosen return value), and detaches.
 * The process keeps running, now with the exploitable path disabled.
 *
 * This is a surgical, reversible mitigation (the original bytes are saved so
 * the patch can be lifted), applied live as a response to a reachable/
 * exploited vulnerability -- not a binary redeploy.
 */
#include "wisp.h"

#include <errno.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

/* x86-64 stub: "xor eax,eax; ret"  (return 0 and bail out of the function). */
static const unsigned char STUB_RET0[] = { 0x31, 0xc0, 0xc3 };
/* "ret" only, for void functions. */
static const unsigned char STUB_RET[] = { 0xc3 };

struct saved_patch {
	pid_t pid;
	unsigned long addr;
	unsigned char orig[8];
	int len;
	int used;
};
static struct saved_patch saved[64];

static int poke_bytes(pid_t pid, unsigned long addr, const unsigned char *b, int n)
{
	for (int i = 0; i < n; i += sizeof(long)) {
		errno = 0;
		long word = ptrace(PTRACE_PEEKTEXT, pid, addr + i, 0);
		if (word == -1 && errno)
			return -1;
		unsigned char buf[sizeof(long)];
		memcpy(buf, &word, sizeof buf);
		for (int j = 0; j < (int)sizeof(long) && i + j < n; j++)
			buf[j] = b[i + j];
		memcpy(&word, buf, sizeof word);
		if (ptrace(PTRACE_POKETEXT, pid, addr + i, word) < 0)
			return -1;
	}
	return 0;
}

/* Live-patch the function at `addr` in process `pid` to a safe stub. kind:
 * 0 = "ret", 1 = "xor eax,eax; ret". Returns 0 on success. */
int respond_patch(pid_t pid, unsigned long addr, int kind, const char *why)
{
	const unsigned char *stub = kind ? STUB_RET0 : STUB_RET;
	int len = kind ? sizeof STUB_RET0 : sizeof STUB_RET;

	if (ptrace(PTRACE_ATTACH, pid, 0, 0) < 0) {
		logmsg("patch: attach pid=%d failed: %s", pid, strerror(errno));
		return -1;
	}
	int st;
	waitpid(pid, &st, 0);

	/* save original bytes so the mitigation is reversible */
	struct saved_patch *slot = NULL;
	for (int i = 0; i < 64; i++)
		if (!saved[i].used) { slot = &saved[i]; break; }
	if (slot) {
		errno = 0;
		long w = ptrace(PTRACE_PEEKTEXT, pid, addr, 0);
		memcpy(slot->orig, &w, sizeof(long));
		slot->pid = pid;
		slot->addr = addr;
		slot->len = len;
		slot->used = 1;
	}

	int rc = poke_bytes(pid, addr, stub, len);
	ptrace(PTRACE_DETACH, pid, 0, 0);
	logmsg("patch: pid=%d addr=0x%lx mitigated (%s): %s", pid, addr,
	       why ? why : "runtime patch", rc == 0 ? "ok" : "failed");
	return rc;
}

/* Lift a previously applied patch (restore original bytes). */
int respond_unpatch(pid_t pid, unsigned long addr)
{
	for (int i = 0; i < 64; i++) {
		struct saved_patch *s = &saved[i];
		if (s->used && s->pid == pid && s->addr == addr) {
			if (ptrace(PTRACE_ATTACH, pid, 0, 0) < 0)
				return -1;
			int st;
			waitpid(pid, &st, 0);
			long w;
			memcpy(&w, s->orig, sizeof(long));
			ptrace(PTRACE_POKETEXT, pid, addr, w);
			ptrace(PTRACE_DETACH, pid, 0, 0);
			s->used = 0;
			logmsg("patch: pid=%d addr=0x%lx reverted", pid, addr);
			return 0;
		}
	}
	return -1;
}

/* Cross-process runtime-mitigation demo (legitimate target: own child).
 *
 * Exercises the REAL agent code path -- respond_patch() / respond_unpatch()
 * from agent/patch.c -- across a process boundary, the way the agent would
 * neutralise a reachable vulnerability in a running process without a restart.
 *
 * The target is a child this process forked and controls (the same relation a
 * debugger has to its debuggee). That is an ordinary, authorised ptrace use,
 * not injection into an unrelated or uncooperative process, so it does not
 * trip -- and does not try to work around -- the sandbox's RCE guard. What it
 * proves is exactly the io.security claim "runtime vulnerability mitigation
 * without redeployment": the parent attaches to the LIVE child, overwrites the
 * entry of vulnerable() with the safe stub, detaches, and the child -- still
 * the same process, never restarted -- starts returning the mitigated value.
 * The parent then lifts the patch and the child reverts.
 *
 * Build: cc -O0 -no-pie -fno-pic crosspatch_demo.c ../agent/patch.c
 * (fork + no-pie => &vulnerable is identical in parent and child.)
 */
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>

/* patch.c calls logmsg(); provide the one symbol it needs. */
void logmsg(const char *fmt, ...)
{
	va_list ap; va_start(ap, fmt);
	fprintf(stderr, "    [agent] "); vfprintf(stderr, fmt, ap); fputc('\n', stderr);
	va_end(ap);
}

int respond_patch(pid_t pid, unsigned long addr, int kind, const char *why);
int respond_unpatch(pid_t pid, unsigned long addr);

/* The "reachable vulnerability": returns 1 (exploitable) until mitigated. */
int __attribute__((noinline)) vulnerable(void) { return 1; }

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	unsigned long addr = (unsigned long)&vulnerable;

	pid_t child = fork();
	if (child == 0) {
		/* LIVE target: never restarts, just keeps calling vulnerable(). */
		for (int i = 0; i < 20; i++) {
			int v = vulnerable();
			printf("  child tick %2d: vulnerable() -> %d  (%s)\n",
			       i, v, v ? "EXPLOITABLE" : "mitigated");
			usleep(250000);
		}
		_exit(0);
	}

	printf("[agent] child pid=%d running; vulnerable() live at 0x%lx\n", child, addr);
	usleep(900000); /* let it run exploitable for a bit */

	printf("[agent] applying live cross-process patch (no restart)...\n");
	if (respond_patch(child, addr, 1, "CVE-DEMO reachable->mitigated") != 0)
		printf("[agent] patch FAILED\n");

	usleep(1200000); /* observe mitigated */

	printf("[agent] lifting patch (restore original bytes)...\n");
	if (respond_unpatch(child, addr) != 0)
		printf("[agent] unpatch FAILED\n");

	usleep(1200000); /* observe reverted */
	kill(child, SIGTERM);
	return 0;
}

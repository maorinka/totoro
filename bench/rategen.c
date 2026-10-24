/* Exec /bin/true at RATE per second for SECS seconds, then print the rate
 * actually achieved:
 *
 *   rategen RATE SECS     ->  "rategen: target 2000/s achieved 1998.7/s (59961 execs in 30.00 s)"
 *
 * Each exec is started on an absolute schedule (start + i/RATE, with
 * clock_nanosleep TIMER_ABSTIME), so the time an exec takes does not slow the
 * rate down; children run concurrently and are reaped as they finish. At most
 * MAX_INFLIGHT children run at once: when the host cannot keep up, the
 * achieved rate printed is lower than the target, and callers must check it.
 * Pacing uses nanosleep-family syscalls only, so the only execs the sensor
 * sees are the /bin/true ones (started with posix_spawn). */
#include <errno.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define MAX_INFLIGHT 256

extern char **environ;
static char *targv[] = { "true", NULL };

static double now(void)
{
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return t.tv_sec + t.tv_nsec / 1e9;
}

int main(int argc, char **argv)
{
	if (argc != 3) {
		fprintf(stderr, "usage: rategen RATE SECS\n");
		return 2;
	}
	long rate = strtol(argv[1], NULL, 10), secs = strtol(argv[2], NULL, 10);
	if (rate <= 0 || rate > 1000000 || secs <= 0 || secs > 86400) {
		fprintf(stderr, "rategen: RATE must be 1..1000000 and SECS 1..86400\n");
		return 2;
	}
	long total = rate * secs, started = 0, inflight = 0;
	struct timespec t0;
	clock_gettime(CLOCK_MONOTONIC, &t0);
	double start = now();
	for (long i = 0; i < total; i++) {
		long long due = (long long)t0.tv_sec * 1000000000LL + t0.tv_nsec + i * 1000000000LL / rate;
		struct timespec at = { (time_t)(due / 1000000000LL), (long)(due % 1000000000LL) };
		while (clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &at, NULL) == EINTR)
			;
		while (inflight > 0 && waitpid(-1, NULL, WNOHANG) > 0)
			inflight--;
		if (inflight >= MAX_INFLIGHT && wait(NULL) > 0) /* host cannot keep up */
			inflight--;
		/* posix_spawn (vfork-style) instead of fork: copying this
		 * process's page tables for every exec would cap the rate. */
		pid_t p;
		if (posix_spawn(&p, "/bin/true", NULL, NULL, targv, environ) == 0) {
			started++;
			inflight++;
		}
	}
	double elapsed = now() - start + 1.0 / rate; /* N execs span N periods */
	while (wait(NULL) > 0)
		;
	if (elapsed < 1e-9)
		elapsed = 1e-9;
	printf("rategen: target %ld/s achieved %.1f/s (%ld execs in %.2f s)\n", rate, started / elapsed, started,
	       elapsed);
	return started == total ? 0 : 1;
}

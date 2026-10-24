/* CPU self-governor.
 *
 * Holds cfg.cpu_budget (percent of one core) by shedding load in a fixed
 * order, cheapest-to-give-up first, and gives coverage back as soon as load
 * subsides:
 *
 *   1. Telemetry. The per-exec telemetry stream is the most expensive and
 *      least security-critical output. Over budget -> suppress it; well under
 *      budget -> restore it. Alerts are unaffected.
 *   2. In-kernel sampling of proven-benign REPEATS. If the pipeline alone
 *      still exceeds the budget, the governor raises the eBPF sampling
 *      divisor N. The kernel then forwards only 1-in-N of the execs whose
 *      whole context -- program path, full argv, uid, tty, parent and
 *      grandparent comm -- exactly repeats one that has been evaluated many
 *      times without alerting (proc_bpf.c). Every exec with a context not
 *      proven benign is still evaluated in full, so a novel command line (one
 *      byte different from a benign one) is never dropped, whatever the load.
 *      What sampling can miss is limited to repeats of a proven-benign context
 *      that a rule would treat differently only because of the inherited actor
 *      (e.g. the same command, same parents, now under an AI agent).
 *
 * Consequence: the budget is held against storms of repeated execs (the
 * common case: loops, polling scripts, build steps re-run identically). A
 * storm of distinct command lines cannot be sampled without losing coverage,
 * so it is evaluated in full and the sensor may exceed the budget for its
 * duration; that is visible in the heartbeat (cpu_pct, sample_n,
 * sampled_drops) and logged.
 *
 * budget_mode tunes eagerness only: budget-first starts sampling as soon as
 * the pipeline is hot; security-first waits until actually at the cap.
 */
#include "wisp.h"

#include <math.h>

#define SAMPLE_MAX 4096
/* A CPU average over a longer window than this is history, not load: it may
 * restore coverage but never raise sampling. */
#define RAISE_WINDOW_MS 5000

int telemetry_on = 1;         /* runtime gate; initialised from cfg at startup */

static unsigned sample_n = 1; /* current eBPF sampling divisor */
static unsigned logged_n = 1; /* last divisor reported in the log */
static int tel_suppressed;    /* governor turned telemetry off */
static uint64_t drops_seen;   /* proc_sampled_drops() at the previous tick */

unsigned governor_sample_n(void) { return sample_n; }
int governor_shedding(void) { return sample_n > 1 || tel_suppressed; }

static void set_sampling(unsigned n)
{
	sample_n = n;
	proc_set_sampling(n);
}

void governor_tick(double cpu, uint64_t window_ms)
{
	if (cfg.cpu_budget <= 0 || !isfinite(cpu))
		return;
	if (cpu < 0)
		cpu = 0;
	double budget = cfg.cpu_budget;
	int fresh = window_ms <= RAISE_WINDOW_MS;
	uint64_t drops = proc_sampled_drops(), ddrops = drops - drops_seen;
	drops_seen = drops;

	/* --- lever 1: telemetry ------------------------------------------- */
	if (cpu > budget && cfg.telemetry && telemetry_on) {
		telemetry_on = 0;
		tel_suppressed = 1;
		logmsg("governor: %.4f%% > %.4f%% budget -> telemetry suppressed", cpu, budget);
	} else if (tel_suppressed && cpu < budget * 0.5) {
		telemetry_on = 1;
		tel_suppressed = 0;
		logmsg("governor: back under budget -> telemetry restored");
	}

	/* --- lever 2: in-kernel sampling of proven-benign repeats ---------- */
	double ramp_at = cfg.budget_mode ? budget * 0.8 : budget * 0.95;
	double setpoint = cfg.budget_mode ? budget * 0.6 : budget * 0.8;
	if (fresh && cpu > ramp_at && (!telemetry_on || !cfg.telemetry)) {
		double want_d = (double)sample_n * (cpu / setpoint) + 0.5; /* aim at setpoint */
		unsigned want = want_d >= SAMPLE_MAX ? SAMPLE_MAX : (unsigned)want_d;
		if (want <= sample_n)
			want = sample_n + 1;
		if (want > SAMPLE_MAX)
			want = SAMPLE_MAX;
		if (want != sample_n)
			set_sampling(want);
		/* Log engagement and each doubling, not every 250 ms step. */
		if (logged_n == 1 || sample_n >= logged_n * 2) {
			logmsg("governor: cpu %.4f%% > %.4f%% cap -> forwarding 1-in-%u repeats of "
			       "proven-benign exec contexts (novel execs are always evaluated)",
			       cpu, budget, sample_n);
			logged_n = sample_n;
		}
	} else if (sample_n > 1 && cpu < setpoint * 0.5) {
		/* Well below the setpoint: give coverage back. If nothing was
		 * sampled away since the last tick the storm is over: restore full
		 * coverage at once. Otherwise step down quickly (halve), so coverage
		 * recovers in a few ticks, not hours. In between it holds. */
		unsigned n = ddrops == 0 ? 1 : sample_n / 2;
		set_sampling(n < 1 ? 1 : n);
		if (sample_n == 1) {
			logmsg("governor: load eased -> full event coverage restored "
			       "(%llu execs sampled out in total)", (unsigned long long)drops);
			logged_n = 1;
		}
	}
}

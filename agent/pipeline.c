#include "wisp.h"

/* The detection pipeline applied to every exec, regardless of event source
 * (netlink proc connector or eBPF). The struct proc must already be filled. */
void pipeline_run(struct proc *p)
{
	actor_resolve(p);
	ecosystem_note(p->comm);
	catalog_check_exec(p);
	rules_eval(p);
	anomaly_check(p);
	if (telemetry_on)
		out_telemetry(p);
}

/* Event sources without in-kernel sampling (the netlink connector) keep no
 * benign-context set; the eBPF sensor (proc_bpf.c) overrides these. */
__attribute__((weak)) void proc_benign_reset(const char *why) { (void)why; }
__attribute__((weak)) void proc_benign_tick(void) {}
/* ...and no in-kernel ring buffer to size the coalescing window by or to
 * overflow. */
__attribute__((weak)) double proc_ring_fill(void) { return 0; }
__attribute__((weak)) uint64_t proc_ring_lost(void) { return 0; }

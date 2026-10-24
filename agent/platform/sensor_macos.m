// SPDX-License-Identifier: GPL-2.0
//
// macOS exec sensor backend (EndpointSecurity).
//
// This is the macOS equivalent of agent/proc_bpf.c: it captures every process
// exec AT EXEC TIME -- with full argv -- and feeds it through the same
// platform-independent detection pipeline (`pipeline_run`). It implements the
// same conceptual contract as the Linux backends:
//
//   proc_open()   -> start the ES client, return a file descriptor the main
//                    loop can wait on (one end of a self-pipe the ES handler
//                    writes to when an event is ready).
//   proc_handle() -> drain queued events and run the pipeline on each.
//
// Build: clang -framework EndpointSecurity -framework Foundation, and the
// binary must carry the `com.apple.developer.endpoint-security.client`
// entitlement (ES is a privileged, Apple-approved API -- the macOS analogue of
// "no kernel module, EDR-friendly"). The full macOS port also swaps the Linux
// epoll loop in main.c for a kqueue/dispatch loop; this file is the sensor
// core, which is the part with real platform specificity.
//
// NOTE: not compiled in the Linux build environment this repo was developed in
// (no macOS SDK). It is provided as the concrete macOS backend, reviewed
// against the EndpointSecurity API, not as runtime-tested code.

#import <Foundation/Foundation.h>
#import <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>
#include <unistd.h>
#include <string.h>
#include <libproc.h>

#include "wisp.h"

static es_client_t *g_client;
static int g_evpipe[2] = { -1, -1 }; // [0] read end for the event loop, [1] write

// A compact, pipeline-ready snapshot handed from the ES callback to the loop.
struct mac_event {
	pid_t pid, ppid;
	uid_t uid;
	char exe[MAX_PATH];
	char comm[17];
	char cmd[MAX_CMD];
	size_t cmdlen;
};

// Ring of pending events (ES delivers on its own queue; the loop drains here).
#define RING 1024
static struct mac_event ring[RING];
static volatile unsigned r_head, r_tail;

static void fill_from_exec(const es_message_t *msg, struct mac_event *e)
{
	const es_process_t *p = msg->event.exec.target;
	e->pid = audit_token_to_pid(p->audit_token);
	e->ppid = p->ppid;
	e->uid = audit_token_to_euid(p->audit_token);

	es_string_token_t path = p->executable->path;
	size_t n = path.length < sizeof e->exe - 1 ? path.length : sizeof e->exe - 1;
	memcpy(e->exe, path.data, n);
	e->exe[n] = 0;
	const char *b = strrchr(e->exe, '/');
	snprintf(e->comm, sizeof e->comm, "%s", b ? b + 1 : e->exe);

	// argv, captured in-kernel at exec time -- the macOS analogue of reading
	// the BPF ring buffer, and likewise safe against short-lived processes.
	uint32_t argc = es_exec_arg_count(&msg->event.exec);
	size_t off = 0;
	for (uint32_t i = 0; i < argc && off < sizeof e->cmd - 1; i++) {
		es_string_token_t a = es_exec_arg(&msg->event.exec, i);
		size_t k = a.length;
		if (off + k + 1 >= sizeof e->cmd)
			k = sizeof e->cmd - 1 - off;
		memcpy(e->cmd + off, a.data, k);
		off += k;
		if (off < sizeof e->cmd - 1)
			e->cmd[off++] = ' ';
	}
	if (off)
		off--; // trailing space
	e->cmd[off] = 0;
	e->cmdlen = off;
}

int proc_open(void)
{
	if (pipe(g_evpipe) < 0)
		return -1;

	es_new_client_result_t res = es_new_client(&g_client, ^(es_client_t *c, const es_message_t *msg) {
		if (msg->event_type != ES_EVENT_TYPE_NOTIFY_EXEC)
			return;
		unsigned next = (r_tail + 1) % RING;
		if (next == r_head)
			return; // ring full: drop (bounded, like the BPF ring overflow)
		fill_from_exec(msg, &ring[r_tail]);
		r_tail = next;
		char w = 1;
		(void)!write(g_evpipe[1], &w, 1); // wake the event loop
	});
	if (res != ES_NEW_CLIENT_RESULT_SUCCESS) {
		logmsg("macos: es_new_client failed (%d) -- entitlement/permission?", res);
		return -1;
	}
	es_event_type_t events[] = { ES_EVENT_TYPE_NOTIFY_EXEC };
	if (es_subscribe(g_client, events, 1) != ES_RETURN_SUCCESS) {
		logmsg("macos: es_subscribe failed");
		return -1;
	}
	logmsg("macos: EndpointSecurity exec subscription active");
	return g_evpipe[0]; // the loop waits on this fd (readable when events queued)
}

int proc_handle(int fd)
{
	char drain[256];
	while (read(fd, drain, sizeof drain) > 0)
		; // clear wake bytes
	int handled = 0;
	while (r_head != r_tail) {
		struct mac_event *e = &ring[r_head];
		struct proc p;
		memset(&p, 0, offsetof(struct proc, cmd));
		p.pid = e->pid;
		p.ppid = e->ppid;
		p.uid = e->uid;
		snprintf(p.exe, sizeof p.exe, "%s", e->exe);
		snprintf(p.comm, sizeof p.comm, "%s", e->comm);
		snprintf(p.cmd, sizeof p.cmd, "%s", e->cmd);
		p.cmdlen = e->cmdlen;
		pipeline_run(&p);
		r_head = (r_head + 1) % RING;
		handled++;
	}
	return handled;
}

// EndpointSecurity has no equivalent of the eBPF sampling map; on macOS the
// governor falls back to telemetry-shedding and coalescing (same as the Linux
// connector backend).
void proc_set_sampling(unsigned n) { (void)n; }
uint64_t proc_sampled_drops(void) { return 0; }

uint64_t proc_events(void)
{
	static uint64_t n; // the ES callback path would increment this; kept for ABI
	return n;
}

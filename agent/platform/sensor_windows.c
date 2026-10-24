// SPDX-License-Identifier: GPL-2.0
//
// Windows exec sensor backend (ETW -- Event Tracing for Windows).
//
// The Windows equivalent of agent/proc_bpf.c: it subscribes to the
// Microsoft-Windows-Kernel-Process provider and receives a ProcessStart event
// for every process creation, with the image name and command line, then feeds
// each through the same platform-independent pipeline (`pipeline_run`). ETW is
// the Microsoft-sanctioned, no-driver telemetry path -- the Windows analogue of
// "no kernel module, EDR-friendly" (a full EDR may add a minifilter/ELAM, but
// process-exec visibility needs only ETW).
//
// Contract, matching the other backends:
//   proc_open()   -> start a real-time ETW session + consumer thread, return a
//                    descriptor the event loop waits on (a self-pipe fd, or on
//                    Windows an event HANDLE surfaced through the loop's IOCP).
//   proc_handle() -> drain queued events, run the pipeline on each.
//
// Build: MSVC/clang-cl, link advapi32/tdh. The full Windows port replaces the
// Linux epoll loop in main.c with an IOCP/WaitForMultipleObjects loop (ETW
// delivers on a dedicated consumer thread via ProcessTrace); this file is the
// sensor core. Not compiled in the Linux dev environment (no Windows SDK);
// provided as the concrete ETW backend, reviewed against the ETW/TDH API.

#include "compat.h"
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <stdio.h>
#include <string.h>

#include "wisp.h"

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "tdh.lib")

// Microsoft-Windows-Kernel-Process: {22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}
static const GUID KERNEL_PROCESS_GUID =
	{ 0x22fb2cd6, 0x0e7b, 0x422b, { 0xa0, 0xc7, 0x2f, 0xad, 0x1f, 0xd0, 0xe7, 0x16 } };
#define ID_PROCESS_START 1

static TRACEHANDLE g_session, g_consumer;
static HANDLE g_thread;

// Bounded ring drained by the event loop (ETW callback runs on its own thread).
struct win_event {
	DWORD pid, ppid;
	char exe[MAX_PATH];
	char comm[17];
	char cmd[MAX_CMD];
	size_t cmdlen;
};
#define RING 1024
static struct win_event ring[RING];
static volatile unsigned r_head, r_tail;
static HANDLE g_wake; // signalled when an event is queued

// Pull a property (by name) from a parsed ProcessStart event.
static int get_prop(PEVENT_RECORD rec, const wchar_t *name, PBYTE out, ULONG cap)
{
	PROPERTY_DATA_DESCRIPTOR d = { 0 };
	d.PropertyName = (ULONGLONG)(uintptr_t)name;
	d.ArrayIndex = ULONG_MAX;
	return TdhGetProperty(rec, 0, NULL, 1, &d, cap, out) == ERROR_SUCCESS;
}

static void WINAPI on_event(PEVENT_RECORD rec)
{
	if (!IsEqualGUID(&rec->EventHeader.ProviderId, &KERNEL_PROCESS_GUID) ||
	    rec->EventHeader.EventDescriptor.Id != ID_PROCESS_START)
		return;
	unsigned next = (r_tail + 1) % RING;
	if (next == r_head)
		return; // ring full: bounded drop
	struct win_event *e = &ring[r_tail];

	DWORD pid = 0, ppid = 0;
	get_prop(rec, L"ProcessID", (PBYTE)&pid, sizeof pid);
	get_prop(rec, L"ParentProcessID", (PBYTE)&ppid, sizeof ppid);
	e->pid = pid;
	e->ppid = ppid;

	wchar_t wimg[MAX_PATH] = L"", wcmd[MAX_CMD] = L"";
	get_prop(rec, L"ImageName", (PBYTE)wimg, sizeof wimg);
	get_prop(rec, L"CommandLine", (PBYTE)wcmd, sizeof wcmd);
	WideCharToMultiByte(CP_UTF8, 0, wimg, -1, e->exe, sizeof e->exe, NULL, NULL);
	int n = WideCharToMultiByte(CP_UTF8, 0, wcmd, -1, e->cmd, sizeof e->cmd, NULL, NULL);
	e->cmdlen = n > 0 ? (size_t)n - 1 : 0;
	const char *b = strrchr(e->exe, '\\');
	snprintf(e->comm, sizeof e->comm, "%s", b ? b + 1 : e->exe);

	r_tail = next;
	SetEvent(g_wake);
}

static DWORD WINAPI consumer_thread(LPVOID arg)
{
	(void)arg;
	ProcessTrace(&g_consumer, 1, NULL, NULL); // blocks, delivering to on_event
	return 0;
}

int proc_open(void)
{
	// Real-time session.
	BYTE buf[sizeof(EVENT_TRACE_PROPERTIES) + 256] = { 0 };
	EVENT_TRACE_PROPERTIES *props = (EVENT_TRACE_PROPERTIES *)buf;
	props->Wnode.BufferSize = sizeof buf;
	props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
	props->Wnode.ClientContext = 1; // QPC timestamps
	props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
	props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
	const char *session = "WispExecSession";

	StopTraceA(0, session, props); // clear a stale session
	if (StartTraceA(&g_session, session, props) != ERROR_SUCCESS) {
		logmsg("windows: StartTrace failed (admin rights?)");
		return -1;
	}
	if (EnableTraceEx2(g_session, &KERNEL_PROCESS_GUID, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
	                   TRACE_LEVEL_INFORMATION, 0x10 /*WINEVENT_KEYWORD_PROCESS*/, 0, 0, NULL)
	    != ERROR_SUCCESS) {
		logmsg("windows: EnableTraceEx2 failed");
		return -1;
	}

	EVENT_TRACE_LOGFILEA log = { 0 };
	log.LoggerName = (LPSTR)session;
	log.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
	log.EventRecordCallback = on_event;
	g_consumer = OpenTraceA(&log);
	if (g_consumer == INVALID_PROCESSTRACE_HANDLE) {
		logmsg("windows: OpenTrace failed");
		return -1;
	}
	g_wake = CreateEventA(NULL, FALSE, FALSE, NULL);
	g_thread = CreateThread(NULL, 0, consumer_thread, NULL, 0, NULL);
	logmsg("windows: ETW Kernel-Process subscription active");

	// The Linux loop waits on an fd; on Windows the port's IOCP loop waits on
	// g_wake instead. Returning its HANDLE value lets a Windows loop register
	// it; a plain fd-based loop would use a self-pipe here.
	return (int)(intptr_t)g_wake;
}

int proc_handle(int fd)
{
	(void)fd;
	int handled = 0;
	while (r_head != r_tail) {
		struct win_event *e = &ring[r_head];
		struct proc p;
		memset(&p, 0, offsetof(struct proc, cmd));
		p.pid = e->pid;
		p.ppid = e->ppid;
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

void proc_set_sampling(unsigned n) { (void)n; } // ETW has its own rate controls
uint64_t proc_sampled_drops(void) { return 0; }
uint64_t proc_events(void) { return 0; }

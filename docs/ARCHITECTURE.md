# Wisp architecture

```
                  ┌──────────────── kernel ────────────────┐   ┌─────────── wispd (userspace) ──────────┐
   exec happens → │ tracepoint sys_enter_execve (exec.bpf.c)│   │                                        │
                  │  capture pid/ppid/uid/comm/filename/argv│   │  proc_bpf.c    actor.c     rules.c      │
                  │            │                            │   │  drain ring ─▶ attribute ─▶ policy      │
                  │            ▼                            │   │  (batched)     human/ai     engine      │
                  │     ┌─────────────┐   ring buffer       │   │     │          /code/ci        │        │
                  │     │  BPF RINGBUF │══════════════════════▶ │     ├─▶ catalog.c (npm/pip/vsx/ai)       │
                  │     └─────────────┘  (event captured    │   │     ▼                         ▼        │
                  │                       at exec time)     │   │  inventory.c  fim.c      output.c      │
 ┌─────────────┐  │                                         │   │  (pkgs/exts) (tamper)   JSONL+console   │
 │ inotify     │──┼────────────────────────────────────────┼──▶│     └──── one epoll loop (main.c) ──┘   │
 └─────────────┘  └─────────────────────────────────────────┘   └────────────────┬───────────────────────┘
                                                                                  │ NDJSON over TLS (mTLS)
                                                                                  ▼
                                                              ┌──────────────────────────┐
                                                              │  wisp-console (C++)      │
                                                              │  mTLS ingest · journal    │
                                                              │  · web UI · API · Slack   │
                                                              └──────────────────────────┘
```

## Event sources (no kernel module)

| Source | Kernel mechanism | Why it is cheap / correct |
|---|---|---|
| Outbound connections | **eBPF tracepoint** on `inet_sock_set_state` (→ `SYN_SENT`) → second ring buffer | attributed to the same actor model; network policy and rate limits evaluated in userspace |
| Process exec (default) | **eBPF tracepoint** on `sys_enter_execve` → **ring buffer** | full event (incl. argv) captured in-kernel at exec time: no `/proc` read, and safe to drain in batches without racing short-lived processes |
| Process exec (fallback) | netlink **proc connector** + classic-BPF socket filter | portable, no BPF/BTF needed; reads `/proc` per event, so cannot batch safely |
| Package / extension installs | **inotify** on install dirs (`node_modules`, `.vscode/extensions`, …) | fires only on change; no tree walks on a timer |
| File tampering | **inotify** on sensitive paths (`/etc/shadow`, `/etc/ssh`, …) | same |
| Housekeeping | one `timerfd` (default 60 s) | console retry, heartbeat, slow rescan |
| Coalescing | one `timerfd` (`coalesce_ms`) | drains a burst in one wakeup; disarmed when idle |

All fds are serviced by a **single `epoll_wait(-1)`** loop in `main.c`. No
threads, no busy loops, no polling in the hot path. Under load the exec ring-
buffer fd is briefly dropped from `epoll` and drained by the coalescing timer so
one wakeup handles a whole batch; when a window comes up empty the fd is re-armed
and the loop blocks again — an idle host wakes zero times per second.

## Actor attribution (`actor.c`)

Every exec is classified as **human / ai / code / ci / service**:

1. Classify the process on its own identity (binary name, argv markers such as
   `@anthropic-ai/claude-code`, package‑manager install verbs, CI runner names,
   terminal/ssh roots).
2. If inconclusive, inherit the parent's cached verdict.
3. Only a cold miss walks `/proc` ancestry upward (bounded to 24 levels).

Verdicts are cached in a fixed 64k‑slot table keyed by pid, so the steady‑state
cost is one array lookup. This is what lets a rule say `actor=ai` and have it
mean "anything ultimately driven by an AI agent", tracked down the whole process
tree — the core of the io.security "monitor humans, code and AI agents" story.

## Policy engine (`rules.c`)

Rules are parsed once into a compact array of compiled conditions (field id +
operator + alternatives). Evaluation is first‑match over the list; each
condition is a bounded set of `memmem`/compare calls. `cmd` length is cached so
`contains` checks don't re‑`strlen`. Actions: `ignore` (allow‑list), `alert`,
`kill`, `quarantine`; global **monitor/enforce** with per‑rule override.

## Catalog / curation (`catalog.c`)

At the moment an installer execs (`npm install X`, `pip install Y`), Wisp parses
the requested package specs out of the command line and checks them against the
curated catalog **before the package manager has resolved them** — allow/deny
per name, version pinning, and default allow or default‑deny ("only the curated
catalog is permitted") per ecosystem. Unknown AI tools starting on their own are
flagged as **Shadow AI**.

## Response (`respond.c`)

Userspace only: `SIGKILL` the process and its immediate children; quarantine a
binary by moving it into a `0700` store with exec bits stripped (copy+unlink
across filesystems). Nothing here touches the kernel or any OS integrity control
— matching io.security's "EDR‑friendly, no kernel extensions" constraint.

## CPU self-governor (`governor.c`) + frequency filter

The governor enforces `cpu_budget` as a hard SLA. Under load it re-evaluates
every 250 ms while above 60% of the budget and every second otherwise (driven
from the active drain path, so an idle host still has zero wakeups). It reads
the agent's own CPU and sheds work cheapest-first: first it suppresses the per-exec
telemetry *log* (no events lost); if the pipeline itself is still over budget
(budget-first mode) it raises an eBPF sampling divisor.

Sampling never drops security-relevant events. The eBPF program hashes each
program path and samples **only** paths present in a `benign` map. Userspace
maintains that map with a frequency filter (`proc_bpf.c`): a path seen executing
`BENIGN_PROMOTE` times with no alert is published as benign; a path that ever
alerts is pinned out of it permanently. So under an exec storm the kernel sheds
only repetitive proven-benign churn (`/usr/bin/cc` in a build loop, say) while
every novel, rare, or previously-alerting path is always forwarded and
evaluated. This is what lets the hard CPU cap coexist with not missing new or
suspicious activity.

## Console link (`console.c`)

A single persistent TLS connection, driven **entirely non‑blocking** by the main
epoll loop as a small state machine (connect → TLS handshake → up). A slow or
dead console can never stall the sensor; undelivered lines drop past a bounded
ring rather than growing memory. Alerts, inventory changes and a periodic
heartbeat (exec count, live self‑CPU%, RSS) are streamed up; policy reloads and
mode changes come back down.

## Network policy (`netpolicy.c`)

Each outbound TCP connection attempt arrives with pid, uid, destination and
port, and is attributed to an actor from the pid cache. Rules are evaluated
first-match. `limit` rules keep a token bucket per (rule, process) in a small
open-addressed table, are transparent within budget, and are cleared on policy
reload. Parsing fails closed: an unknown verb, actor, network, port or rate is
reported and the line skipped.

## Anomalies (`anomaly.c`)

A 1 Mbit Bloom filter (128 KiB, three probes from one 64-bit FNV hash) records
every program path the host has executed. After the learning window
(`anomaly_learn`), a path not in the filter raises `ANOM-001` once and is
added. The filter is persisted to `state_dir` with the hostname's hash, so a
baseline baked into a golden image is rejected on the clone. Cost per exec: a
hash and three bit tests.

## Forensics (`forensics.c`)

`wispd --search` runs as a separate short-lived process over the sensor's
JSONL record, so the running sensor pays nothing. `tree=PID` first grows the
descendant set from every record carrying `pid`/`ppid` (exec telemetry and
alerts), then returns those processes' execs, alerts and network flows merged
in time order.

## Console (`console/`)

- **Ingest** (`console.cpp`): one thread per sensor connection, 10 s TLS
  handshake deadline, read deadline 10 minutes, 1 MiB line cap. Each connection speaks for one host, and writes
  back to it are serialised by a per-connection lock. A connection must
  say hello first and is then bound to that host. Sensor input is
  sanitised of console-only fields before use.
- **Journal** (`store.cpp`): every non-heartbeat event is appended to
  `events.jsonl` and indexed in memory for search. At startup the journal
  (rotated segment first) is replayed through the same `apply` path as live
  ingest, rebuilding hosts, alerts with triage, inventory, lifecycle and
  rollout history. The journal rotates by size.
- **Lifecycle**: hosts are active, stale or decommissioned. Ephemeral hosts
  retire on goodbye or disconnect; a reaper retires silent persistent hosts.
- **Rollouts**: each host's position in a group is `fnv32a(hostname) mod 100`,
  so a larger percentage is always a superset of a smaller one. The web UI
  uses the same hash to preview a stage exactly.
- **HTTP** (`http.cpp`, `console.cpp`): an HTTP/1.1 server with keep-alive,
  header/request/idle timeouts and a connection cap; routes, RBAC wrapper,
  method guards, security headers, body limit, access log, health and
  readiness, graceful shutdown. TLS (OpenSSL 3) lives in `net.cpp`. Read
  models, vulnerability tiers and posture live in `store.cpp`; the vault in
  `vault.cpp` (AES-256-GCM via OpenSSL EVP).
- **Analysis** (`analysis.cpp`): reads consistent snapshots from the store.
  - It correlates alerts into incidents by union-find over (host, time gap,
    actor or process lineage), and scores them with per-point reasons.
  - It computes fleet health and rule statistics.
  - It builds suggestions. A background pass runs every `-analysis-interval`.
  - Suggestions and decisions are console-only journal records (`suggestion`,
    `suggestion_decision`). They are replayed through `Store::replay_hook`, so
    the inbox survives restarts.
  - Approving runs the action through the same store paths as the manual
    controls (`push_control`, `rollout`, `triage`).
- **AI assistant** (`ai.cpp`): an optional Claude Messages API client over
  raw HTTPS (`net.cpp`: verified TLS, `HTTPS_PROXY` CONNECT, chunked bodies).
  - One worker thread runs a bounded job queue.
  - Triage and rule review use structured outputs (JSON schema). Ask is a
    tool-use loop over ten read-only tools.
  - Inputs are redacted. Outputs go back through `Analyst::propose`, which
    validates them.
  - Results are journaled as `ai_result` records.
- **Web UI** (`web/`): plain HTML, CSS and JavaScript compiled into the
  binary by `tools/embed.cpp`. No framework and no network dependencies. DOM is built through
  one helper that only ever sets text, which keeps it compatible with a
  strict CSP and safe from markup injection by sensor data.

# Parity with io.security

**Source of truth.** `https://io.security/` is unreachable from this build
environment — every attempt returns a proxy `403` / `getaddrinfo ENOTFOUND`
(the environment's network policy blocks it). Parity below is therefore mapped
against the **page content the user supplied** (the uploaded
`IO.Security_-_Full_control._Anywhere._Everywhere..html`). Each row quotes a
capability from that page and maps it to the implementing component and the
evidence that it works.

Legend: ✅ implemented & tested on Linux · ◐ implemented with a stated gap
(platform/hardware to finish, coverage or testing limits) · ○ designed, not
built here (reason given).

## Visibility & monitoring

| io.security (from the page) | Wisp component | Status / evidence |
|---|---|---|
| "Continuous behavioral monitoring of Endpoints, Software, Code and AI Agents" | `proc_bpf.c` eBPF exec tracepoint → `pipeline_run` | ✅ every exec captured in-kernel (2000/2000 under load) |
| "Every actor on your fleet… Humans, code and AI agents — observed" | `actor.c` attribution | ✅ classifies human / ai / code / ci / service; console shows `AI agent · claude` etc. |
| "Immediate / retrospective forensics into any event, flow or activity" | agent `forensics.c` (`wispd --search`) over the JSONL record (execs, **flows**, alerts, inventory); console `/api/events` over a durable journal | ✅ `--search tree=PID` rebuilds a process's descendants with their alerts and outbound flows; field / text / time filters; console journal replayed after restart and still searchable (`verify.sh`) |
| "Fully auditable user and operator activity logs" | telemetry stream + alert trail | ✅ one JSON line per exec with actor/uid/cmd |

## Prevention, enforcement & response

| io.security | Wisp | Status / evidence |
|---|---|---|
| "Realtime policy enforcement across processes, APIs and data flows" | `rules.c` engine, `respond.c` | ✅ monitor/enforce; kill verified (victim SIGKILLed + alert) |
| "Malicious activity and exploitation — prevention, detection and automated response" | rule packs (reverse shell, cred theft, LOTL, persistence, privesc) + kill/quarantine | ✅ CRED/RSHELL/LOL/PERSIST/PRIV rules fire; quarantine implemented |
| "Monitoring-only out of the box, gradual enforcement under your policy" | `mode = monitor` default, per-rule `mode=enforce` | ✅ ships in monitor; per-rule override |
| "Slack notifications" | `wisp-console` Slack webhook | ✅ high/critical alerts POSTed |

## Curation / governance (the io.security differentiator)

| io.security | Wisp | Status / evidence |
|---|---|---|
| "Curated enterprise catalog — only sanctioned packages, plugins and tools" | `catalog.c` | ✅ allow/deny/pin per ecosystem |
| "NPM Package Curation", "PIP Package Curation" | catalog `npm`/`pip` kinds, install-time exec check | ✅ real `npm install event-stream` blocked as catalog violation |
| "IDE Extension / VSCode / Cursor Curation" | catalog `vsx` kind, checked by `inventory.c` on discovery and live install | ✅ allow-list enforced as detection (`CAT-VSX`); verified in `verify.sh`. Detect-only: the sensor does not delete installed extensions |
| "Governance of transient and unsanctioned tooling & Shadow AI" | catalog `ai` kind (allow-list), Shadow-AI alert on unknown agent self-start | ✅ unknown AI tool → Shadow-AI alert |
| "Fleet Security Scan — discover every tool, package and extension" | `inventory.c` baseline scan + live inotify | ◐ reports installs/removals with version for system and per-user locations: global npm, `~/node_modules`, `~/.npm-global`, system and `~/.local` Python site/dist-packages, VS Code / VS Code Server / Cursor extensions. **Project-local `node_modules` and virtualenvs are not inventoried** (no bounded set of places to look) |

## Fleet, identity & deployment

| io.security | Wisp | Status / evidence |
|---|---|---|
| "One userspace sensor… non-kernel, EDR-friendly" | eBPF (not a kernel module) + userspace agent | ✅ no kernel module; runs as root confined to a capability set (`CAP_BPF/PERFMON/SYS_PTRACE/KILL/DAC_READ_SEARCH/DAC_OVERRIDE/FOWNER`), `NoNewPrivileges`, read-only system (a guard against accidents, not a boundary against a compromised sensor) |
| "Single console, full fleet coverage" | `wisp-console` (C++): mTLS ingest, durable journal, web console, API | ✅ live fleet view with host lifecycle, per-host CPU/alerts/inventory, alert triage; restart-safe (journal replay) |
| "Hardware-backed host identity (TPM / Secure Enclave) with mutual TLS" | `identity.c` + `console.c` mTLS + tpm2 provider | ✅ **mTLS verified both ways** (rogue rejected) **and TPM key-residency demonstrated**: against a software TPM 2.0 the mTLS client key is a TPM-resident blob, the TPM signs the handshake, and the sensor registers with `trust=tpm` (`bench/tpm_identity_demo.sh`). Identical path on a hardware TPM via `/dev/tpmrm0`. Secure Enclave (macOS) not built here |
| "Built-in gradual-deployment controls" | `console/src/store.cpp` `/api/policy/rollout` (deployer+) | ✅ staged rollout to a deterministic % cohort of a group; 10%→50%→100% cohorts are nested (canary stays in), every host in the cohort was delivered the push, other groups untouched, each stage journaled (`verify.sh`, 20-host simulated fleet + real agent) |
| "Ephemeral sensor lifecycle for short-lived runners/containers" + "Automatic discovery, provisioning and decommissioning" | agent `ephemeral = 1` (hello + goodbye on exit); console host states active / stale / decommissioned, reaper | ✅ real ephemeral agent decommissioned the moment it exits; silent persistent hosts go stale, then are retired after `-decommission-after`; a returning host is re-provisioned on hello; retired hosts stay queryable (`verify.sh`) |
| "MacOS / Windows" coverage | pluggable sensor interface; **four backends**: Linux eBPF (`proc_bpf.c`) + connector (`proc.c`), macOS EndpointSecurity (`platform/sensor_macos.m`), Windows ETW (`platform/sensor_windows.c`) | ◐ Linux backends **built & tested**. Windows ETW backend **compiles against the real Windows SDK headers** via MinGW cross-compile (`make check-platform`) — API-verified, not runtime-tested (no Windows host). macOS EndpointSecurity backend **compiles as valid Objective-C against the documented ES API** (`make check-platform`, clang syntax-check against public-doc declarations in `platform/shim/` -- not Apple's SDK, which links on macOS). Full port also swaps epoll for kqueue/IOCP. Real code, honestly not a runtime-tested macOS/Windows product |

## Performance claim

io.security markets low-overhead; Wisp commits to a **hard, self-enforced
`cpu_budget` (default 0.05% of one core) for the userspace sensor** (in-kernel
eBPF cost is measured separately). See `BENCHMARKS.md`: idle 0.002%, and the
governor holds the cap against storms of repeated execs at every rate tested
(0.023% at 3000/s, 0.036% at 5000/s). A storm of distinct command lines cannot
be sampled and may exceed it. At the rates a real endpoint sees it runs
full-coverage with telemetry, well under budget.


## Vulnerability, governance & integration (added after initial build)

| io.security (from the page) | Wisp component | Status / evidence |
|---|---|---|
| "High resolution vulnerability tracking: Exploited > Vulnerable > Reachable > Dormant > Theoretical" | `console/src/vulndb.cpp` + embedded `vulndb.json` | ◐ four of the five tiers, exactly the ones the sensor can observe: **exploited** (an alert involves the package), **reachable** (affected version + its runtime executing), **dormant** (runtime not seen), **theoretical** (version unknown). The **vulnerable** tier (vulnerable code actually loaded) needs module-load visibility the sensor does not have, so it is not claimed. Covered by the `VulnTiers` unit test |
| "Risk-based vulnerability prioritization" — "rank what is reachable and exploitable, not merely present" | `vulnFindings` ranks tier then CVSS | ✅ `/api/vulns`, console Vulnerabilities page |
| "Admin / Operator / Deployer roles with granular permissions" | `console/src/rbac.cpp` | ✅ token→role, per-endpoint; verified viewer-read-200 / viewer-push-403 / operator-push-200 |
| "We suggest, you approve, we solve" / gradual enforcement | `console/src/analysis.cpp` suggestions + `/api/suggestions/decide`; `/api/policy/push` | ✅ the engine proposes contain / staged-enforcement / rule / patch / housekeeping fixes. Approval (role-checked, re-validated, journaled) carries them out. `verify.sh`: an approved suggestion switched the **real sensor** monitor → enforce |
| "We observe, research and analyze your fleet health and IO Security events" | `analysis.cpp` fleet health | ✅ sensors over budget, silent hosts, version drift, weak identity, unprotected hosts under attack, alert spikes, noisy rules (`FleetHealthFindings`) |
| "We research security incidents and prioritize for you" | `analysis.cpp` incidents | ✅ alerts correlated by actor and process lineage, scored 0–100 with per-point reasons, campaign detection across hosts, P1–P4 (`IncidentsCorrelateByActorAndLineage`, `IncidentScoringCampaignAndContainment`; real-agent incident in `verify.sh`) |
| "We curate monitoring and realtime enforcement rules" | `analysis.cpp` rule review | ✅ noisy rules (from triage outcomes) with the exact exclusion, rules ready to block, as suggestions (`RuleReviewFindsNoiseAndRulesReadyToEnforce`) |
| "Optional AI assistance for triage and rule curation" | `console/src/ai.cpp` (Claude API) | ✅ AI triage (verdict, reasoning, recommended actions), AI rule review (validated `rules.conf` lines), and fleet Q&A with read-only tools. Off without a key; redacted inputs; proposals scoped, validated and approval-gated; journaled. ◐ exercised end to end against a conformance-checking mock of the Messages API (unit tests, `verify.sh`, UI smoke test). A live call reached `api.anthropic.com` (401 without a key); no key was available to run real triage here |
| "SDK and API clients: TypeScript/JavaScript, Python 3..." | `sdk/wisp.py`, `sdk/wisp.ts` | ◐ Python + TS clients over the REST API, verifying TLS by default. CI (`sdk-mcp` job) type-checks the TS SDK with strict `tsc` and byte-compiles the Python SDK; neither SDK's calls are exercised against a console in CI |
| "MCP-native interfaces for coding agents and their tools" | `mcp/wisp_mcp.py` | ✅ MCP stdio server, viewer token enforced; `wisp_check_package` denies event-stream (CVE), allows left-pad — agent checks limits before acting. CI (`sdk-mcp` job) runs a JSON-RPC session against a local `-dev` console with a viewer token (initialize, tools/list, ping, parse and unknown-method errors, one `wisp_fleet` call) and checks the server refuses to start with an admin token. Other tools, including `wisp_check_package`, are not exercised in CI |
| "API monitoring ... in-app data-flow and exposure control" / "enforcement across processes, APIs and data flows" | eBPF `inet_sock_set_state` + `netpolicy.c` | ✅ outbound-connection monitoring attributed to the actor model; allow/deny by CIDR/port/actor; verified deny of :9999/:2323 (actor=ai), allow :8080. Enforce mode kills the offending process (inline correction) |
| "Integrated secret vaults with policy-controlled access" | `console/src/vault.cpp` | ✅ AES-256-GCM encrypted at rest, RBAC-gated (admin write / operator read), every read audited into the alert stream; verified write/read/deny/encryption/audit |
| "API monitoring, rate limiting and inline correction" | `netpolicy.c` `limit <dest> <N>/s or <N>/m [actor=]` — per-process token bucket; every outbound flow written to telemetry | ✅ 10 connects against a 3/s limit → exactly 7 `NET-RATE` alerts, a second process keeps its own budget; enforce mode stops the over-limit process inline (`verify.sh`). **Scope:** limits TCP *connection* rate per process — not individual requests multiplexed on a kept-alive connection, and no L7 payload rewriting |
| "Behavior Tracking, Signatures & Anomalies" | signatures: `rules.c`; anomalies: `anomaly.c` first-seen-program detection (persistent Bloom filter, learning window) | ✅ after learning, a program never run on the host raises `ANOM-001` once; learned programs stay silent; baseline survives restart (`verify.sh`). Fits the CPU budget: a hash + 3 bit tests per exec (CPU still 0.025% at 2000 exec/s) |
| "Attack-surface posture management across tools and dependencies" | `console/src/store.cpp` `/api/posture` | ✅ per-host 0–100 score + grade from vuln tiers, unsanctioned tooling, anomalies, alerts, identity trust and enforcement mode, with plain-language findings; fleet roll-up, worst first |
| "MDM Integration for rollouts & deployments (no changes to code, tools or pipelines)" | `packaging/install.sh` unattended mode | ✅ env-driven (`WISP_CONSOLE/GROUP/MODE/EPHEMERAL`, mTLS PEMs from MDM secrets → 0600), `--root` image bake, `--no-start` for containers; verified into a staging root (`verify.sh`). Vendor-specific packages (Jamf `.pkg`, Intune `.intunewin`) are wrappers around this script and are not built here |
| "Runtime vulnerability patching & mitigation without redeployment" | `patch.c` (ptrace live-patch) | ◐ **mechanism only, no operator interface**: no rule action, console API, suggestion or control line reaches `respond_patch`/`respond_unpatch`, so the shipped product cannot trigger a patch. The mechanism is **runtime-verified cross-process**: `bench/crosspatch_demo.c` (in `verify.sh`) calls the real `respond_patch`/`respond_unpatch` from `patch.c` to ptrace-attach a **separate live child**, overwrite its vulnerable function with the safe stub, and detach — the child keeps running and flips EXPLOITABLE→mitigated with no restart, then reverts when the patch is lifted. The target is an own child (an authorised ptrace relation, as a debugger has), so it needs no RCE-guard bypass; injecting into an *unrelated/uncooperative* process is the guarded path and is not attempted |

## Honest gaps

0. **Runtime binary patching** exists as a mechanism (`patch.c`, ptrace
   live-patch with reversible saved bytes), **runtime-verified cross-process** on
   an own child (`bench/crosspatch_demo.c`), but nothing in the shipped product
   (rules, console, suggestions, control lines) can invoke it. Injecting into an *unrelated/uncooperative*
   process — the dual-use path a real response against a compromised host would
   take — is what the sandbox's RCE guard covers and is not demonstrated here;
   the mechanism itself (attach → patch live → detach → revert, across a process
   boundary) is. Deep L7 API body inspection / payload data-filters remain out of
   scope (Wisp monitors and gates connections, not payload contents).
1. **Live-site verification** — io.security is network-blocked here; parity is
   against the uploaded HTML, not the live product.
2. **macOS / Windows** — the Windows ETW backend **compiles against the real
   Windows SDK headers** (MinGW cross-compile, `make check-platform`); the macOS
   EndpointSecurity backend compiles as valid Objective-C against the documented
   ES API (clang syntax-check; Apple's framework links on macOS).
   Neither is runtime-tested (no Windows/macOS host), and the full port needs a
   kqueue/IOCP main loop. Implemented and (Windows) API-compile-verified, not
   runtime-verified.
3. **TPM key-residency** — demonstrated end-to-end against a *software* TPM 2.0
   (swtpm): the key is non-extractable, the TPM signs the TLS handshake, and the
   sensor authenticates as `trust=tpm`. A hardware TPM uses the identical code via
   the kernel resource manager (`/dev/tpmrm0`), which is also more robust than
   swtpm's socket mode. Not demonstrated on real TPM hardware (none in this VM).

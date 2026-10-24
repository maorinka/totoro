# Changelog

All notable changes to Wisp. Versions follow [Semantic Versioning](https://semver.org/);
the single source of truth is the `VERSION` file.

## Unreleased

### Analysis and AI assistance
- **Incidents**: alerts on a host that share an actor or a process lineage
  and are close in time are correlated into one incident. It is scored 0–100
  with the reason for every point (severity, attack-chain breadth, campaign
  across hosts, exploited vulnerabilities, exposure, containment) and ranked
  P1–P4. You can triage a whole incident at once.
- **Fleet health**: sensors over budget, hosts that stopped reporting, version
  drift, weak identities, unprotected hosts under attack, alert spikes.
- **Rule review**: per-rule volume, spread and triage outcomes. Flags noisy
  rules (with the exact exclusion to add) and rules ready to block.
- **Suggestions** (*we suggest, you approve, we solve*). The engine proposes:
  - containing hosts under attack;
  - staged enforcement per group (10% → 50% → 100%, with a noise gate);
  - rule changes;
  - patches;
  - housekeeping.

  Approving carries the action out through the normal controls. Each
  suggestion is role-checked and validated twice. Decisions are journaled and
  survive restarts.
- **AI assistant** (optional, Claude API, `claude-opus-5-5` by default):
  - triages an incident: verdict, confidence, reasoning, recommended actions;
  - reviews a rule: proposed `rules.conf` lines, grammar-checked;
  - answers questions about the fleet with read-only tools.

  It is off without a key (`-ai-key-file`, the vault secret
  `anthropic/api-key`, or `ANTHROPIC_API_KEY`). Data is redacted before
  sending. The AI only proposes: its recommendations are scoped to the
  incident, may not weaken protection, and wait for approval. Every request is
  journaled.
- New pages: Incidents, Suggestions and Analysis; Overview shows top incidents
  and next steps. New API endpoints, SDK methods and read-only MCP tools.
- The console's HTTPS client now honours `HTTPS_PROXY` / `NO_PROXY` (this also
  applies to Slack).


### Console rewritten in C++
The console (`wisp-console`) is now C++20, built on OpenSSL 3 and
nlohmann/json; the sensor was already C. Flags, the REST API, the sensor
protocol and the journal and vault formats are unchanged: an existing
`events.jsonl` and `vault.json` work as they are, and a journal written by the
new console replays identically in 1.0.0 (checked endpoint by endpoint in both
directions). Building it needs `g++` 10+ (or clang 12+), `libssl-dev` and
`nlohmann-json3-dev` instead of Go. `make test` now runs the console tests under
AddressSanitizer + UndefinedBehaviorSanitizer and under ThreadSanitizer.

Behaviour changes:
- A sensor connection must send `hello` first and then speaks only for that
  host. Before, events sent before `hello` could name any host.
- An unknown `/api/…` path returns `404` JSON instead of the web UI.
- `/api/version` reports `runtime` (e.g. `C++ / OpenSSL 3.0.13 …`) in place of `go`.
- A host's `runtimes` is `[]` rather than `null` when empty.
- Lists with equal sort keys (top rules, vulnerabilities, posture) now have a
  fixed order.
- A request body over 1 MiB gets `413` on every endpoint, and a chunked
  request body gets `501`.

## 1.0.0

First production release.

### Console
- New web console: overview, alerts with triage, hosts with detail panels,
  investigation over the event journal, vulnerabilities, attack-surface
  posture, a staged-rollout planner that previews the exact cohort, and
  settings. Light and dark themes, phone layout, keyboard shortcuts. Served
  from the binary; loads nothing from the network and runs under a strict
  Content-Security-Policy.
- Fails closed: refuses to start without a roles file, or without
  mutual-TLS sensor ingest, unless `-dev` is given.
- API tokens: SHA-256 hashes in `roles.conf`, constant-time comparison,
  `wisp-console -gen-token <role>:<name>`.
- All state-changing endpoints are POST-only. Rollout history is readable by
  every role; starting a rollout needs `deployer`.
- Alert triage (open / acknowledged / resolved, with note and author),
  journaled and restored on restart.
- The event journal now restores hosts, alerts, triage, inventory, lifecycle
  and rollout history after a restart, and rotates by size.
- `HOST-ID-MISMATCH` alert when a hostname reconnects with a different host
  identity.
- Sensors can no longer set console-only fields (triage, rollout records) or
  impersonate the console.
- `/healthz`, `/readyz`, `/api/session`, `/api/summary`, `/api/hosts/detail`,
  filtered `/api/alerts`, `/api/alerts/triage`.
- Server timeouts, request-body limit, security headers, access log for
  mutations and errors, graceful shutdown, optional HTTPS (`-http-cert`).
- Vault writes are atomic; a corrupt vault or a missing vault key is now an
  error instead of an empty vault.
- The vulnerability database is embedded; a bad `-vulndb` file is an error.

### Sensor
- `--check-config` validates the config and every policy file and exits
  non-zero with `file:line` messages.
- Policy parsers no longer fail open: an unknown verb, actor, network, port
  or rate in `netpolicy.conf`, or an unknown verdict in `catalog.conf`, is
  reported and the line skipped (previously some became `allow`).
- `--help`; unknown arguments are rejected.
- Version stamped from `VERSION`.

### Fixed
- Vulnerability tiers: the `vulnerable` tier was dead code. Tiers are now
  exactly what the sensor observes: exploited, reachable, dormant,
  theoretical (version unknown).
- Posture no longer counts a host whose mode is not yet known as "monitor".
- A `/0` network prefix no longer triggers undefined behaviour.
- The secrets-vault master key used during development was committed to the
  repository; it is removed and runtime state is ignored. Any vault created
  with that key should be considered exposed.

## 0.x

Development releases: eBPF sensor, actor attribution, rules engine, catalog,
inventory, FIM, network data-flow policy with rate limiting, first-seen
program anomalies, forensics search, runtime patching, CPU governor, fleet
console, vulnerability tiers, RBAC, vault, SDKs, MCP server.

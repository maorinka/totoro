# Analysis and AI assistance

io.security describes its service as: *"We observe, research and analyze your
fleet health and events. We curate monitoring and realtime enforcement rules.
We research security incidents and prioritize for you. We suggest solutions.
You approve. We solve."*, with *"optional AI assistance for triage and rule
curation"*.

Wisp does this inside the console, in two layers:

1. **The analysis engine** is always on, deterministic and explainable. It
   correlates alerts into incidents and ranks them, checks fleet health,
   reviews every rule, and turns what it finds into concrete suggestions.
2. **The AI assistant** is optional and off until you give it a Claude API
   key. It triages an incident, reviews a rule or answers a question about the
   fleet. It can only propose: its recommendations go through the same
   validation and the same approval inbox as the engine's.

Nothing changes on the fleet until a person with the right role approves.

## Incidents

**Incidents** (`/incidents`, `GET /api/incidents`) groups related alerts on a
host into one incident. Two alerts are related when they are less than 30
minutes apart **and** either share an actor (the same AI agent, tool or user)
or a process lineage (the same process, or one is the other's parent). A chain
links through intermediate alerts. Unrelated activity on the same host at the
same time stays separate.

Each incident gets a score from 0 to 100, and every point is explained:

| Points | Why |
|---|---|
| +60 / +45 / +25 / +10 | the most severe detection: critical / high / medium / low |
| +5 each, max +15 | more medium-or-higher detections |
| +4 each, max +12 | more ATT&CK techniques: a chain, not a one-off |
| +5 | a never-before-seen program (`ANOM-001`) is part of it |
| +5 | an AI agent was the actor |
| +10 | the same medium-or-higher detection fired on 3+ hosts within an hour: a campaign (the hosts are listed) |
| +10 / +5 | the host has an exploited / a reachable vulnerability |
| +3 | the host identity is not hardware-anchored |
| +5 | a blocking rule matched but the host is in monitor mode, so nothing was stopped |
| −20 | contained: the sensor killed or blocked every offending process |

Priority: **P1** ≥ 75, **P2** ≥ 55, **P3** ≥ 30, **P4** below. Open incidents
are listed first, then by score. Triaging an incident (acknowledge, resolve,
reopen) triages all of its alerts at once.

An incident's ID is `INC-` plus its first alert's ID, so it stays stable while
the incident grows.

## Fleet health

The **Analysis** page (`GET /api/analysis/health`) lists what needs fixing in
the fleet itself:

| Finding | Severity |
|---|---|
| hosts with an open P1/P2 incident that are in monitor mode | high |
| sensors over the 0.05% CPU budget | medium |
| hosts with a software-generated identity | medium |
| alert volume spike (last hour ≥ 10 and ≥ 3× the hourly average) | medium |
| hosts that stopped reporting | low |
| mixed sensor versions | low |
| rules that are mostly noise | low |

## Rule review

For every rule that has fired (`GET /api/analysis/rules`), Wisp counts its
alerts, the hosts and programs involved, and how its alerts were triaged. A
resolved alert whose note says *benign*, *false positive*, *expected*, *known
good* or *legit* as a whole word counts as noise ("unexpected" does not). So write those words in triage notes when
you close a false positive.

- **Noisy**: 10+ alerts, 5+ closed as benign, and benign is ≥ 60% of
  everything triaged. If one program accounts for most alerts, the advice is
  to exclude it (`!comm=<program>`). Otherwise it is to narrow the rule or
  lower its severity.
- **Ready to block**: a high or critical rule with action `alert` that has
  fired 3+ times, has 2+ triaged alerts and none closed as benign. The advice
  is to change its action to `kill`.

## Suggestions: we suggest, you approve, we solve

The engine runs every minute (`-analysis-interval`), and on demand with
**Analyze now** (`POST /api/analysis/run`). It proposes:

| Kind | When | What approving does | Role |
|---|---|---|---|
| Contain | an open P1/P2 incident on a connected host in monitor mode | sends `enforce` to that host | operator |
| Gradual enforcement | a group has been watched for 24 h and still has hosts in monitor mode, and no alert from a blocking rule in it was closed as benign in the last 7 days | stages `enforce` to 10% of the group, then 50% and 100%, at least 24 h apart; a rollback to monitor holds it off for a week | deployer |
| Rule tuning / hardening | rule review found a noisy rule or one ready to block | records the decision; you edit `rules.conf` (shown) and push a reload | operator |
| Patch | an exploited vulnerability, or a reachable one with CVSS ≥ 9 | records the decision; the exact upgrade is shown | operator |
| Housekeeping | a P4 incident with no activity for 7 days | resolves its alerts | operator |

Approving carries the action out through the same code paths as the
console's own controls. A rollout appears in rollout history as
`<you> via S…`. The decision, the approver and the outcome are journaled.
Suggestions survive restarts.

What you will not see:

- a suggestion you rejected, for 7 days;
- one you approved, for 24 hours;
- an engine suggestion whose condition no longer holds: it expires, for
  example when the host was switched to enforce another way.

Every action is validated twice, when proposed and again when approved:

- the action type must be one of `push`, `rollout`, `triage` or `manual`;
- the target must exist and be live;
- a percentage must be 1–100;
- alert IDs must exist.

## AI assistant

### Turning it on

The assistant uses the Claude API (`claude-opus-5-5` by default). Give the
console a key in one of these ways:

1. `-ai-key-file /etc/wisp/console/anthropic.key` (mode 0600; a systemd
   credential works too), or
2. the vault secret `anthropic/api-key`. This needs the admin role:
   `curl -X PUT --data-binary @key "https://console/api/vault?key=anthropic/api-key"`.
   It is picked up without a restart.
3. `ANTHROPIC_API_KEY` in the console's environment.

| Flag | Default | Meaning |
|---|---|---|
| `-ai` | `true` | set `-ai=false` to disable the assistant entirely |
| `-ai-model` | `claude-opus-5-5` | Claude model |
| `-ai-effort` | `high` | reasoning effort: `low`, `medium`, `high`, `xhigh`, `max` |
| `-ai-url` | `https://api.anthropic.com` | API base URL (a gateway that speaks the same API) |
| `-ai-ca` | | extra CA to trust for `-ai-url` (added to the system store), e.g. a TLS-inspecting proxy |
| `-ai-max-per-hour` | `60` | cap on requests per hour |
| `-ai-fallback` | `true` | let the API retry a declined request on its recommended fallback model |

The console honours `HTTPS_PROXY` / `NO_PROXY`. `NO_PROXY` can list hosts,
domain suffixes and IPv4 CIDRs.

### What it does

| | Where | Result |
|---|---|---|
| **Triage** | incident drawer → *Ask AI to triage*, `POST /api/ai/triage` | verdict (malicious / suspicious / benign), confidence, a short summary, the reasoning, and recommended actions |
| **Rule review** | Analysis → a rule → *Ask AI to review*, `POST /api/ai/curate` | assessment and complete `rules.conf` lines |
| **Ask** | Analysis → *Ask about your fleet*, `POST /api/ai/ask` | an answer that cites hosts, incidents and rules. The model looks things up through ten read-only tools over the console's own data: incidents, alerts, the event journal, hosts, health, rule review, vulnerabilities and posture |

Requests run in the background (`GET /api/ai/jobs?id=`). The UI and SDKs wait
for them; a long analysis does not hold an HTTP request open. Triage verdicts
are shown on the incident, and rule reviews in Rule review.

### Safety

- **It only proposes.** Triage recommendations become suggestions only through
  the engine's validation. They are also kept inside the incident's scope: a
  push can only target the incident's host or a host in its campaign; a
  rollout only the incident host's group; triage only the incident's own
  alerts. The assistant can never suggest weakening protection (monitor
  mode). Rule lines must pass the sensor's grammar check. Anything else is
  dropped, and the drop is shown to you. Everything that survives waits for a
  human, marked **AI**.
- **Telemetry is untrusted.** Command lines, file names and notes can be
  written by an attacker. They are sent as data inside `<fleet_data>` tags,
  and the model is told never to follow instructions found there. The two
  rules above are the hard limit if it does anyway.
- **Secrets are redacted before anything leaves the console:**
  - private keys and credentials in URLs;
  - `Authorization` headers;
  - `password=`, `token:`, `--api-key …` and similar;
  - known token formats (AWS, GitHub, Slack, GitLab, JWT, Anthropic, Wisp);
  - other long mixed-case alphanumeric strings.

  Hex digests and file paths are kept.
- **Audited.** Every request is journaled as an `ai_result` record: who asked,
  what, which model, token usage, and the result or error. The API key is
  never written anywhere.
- **Bounded.** One request at a time, a queue of 8, and an hourly cap. Tool
  results are truncated, and a question gets at most 10 tool rounds.
- **Failures are explicit.**
  - If the model declines a request, the job fails with the reason, after the
    API's own fallback has been tried.
  - `429` and `5xx` errors are retried with backoff, honouring `retry-after`.
  - Authentication and validation errors are not retried.
  - On console shutdown an in-flight request is abandoned within half a
    second and the job is marked failed.

What is sent: the incident or rule data shown in the UI, redacted, and for
triage the related process events from the journal. Nothing is sent until
someone with the operator role asks.

### Testing without a key

`bench/mock_claude_api.py` stands in for the Messages API. It checks every
request (headers, schema rules, strict tools, tool-result pairing) and replies
deterministically. The unit tests and `bench/verify.sh` use it:

```bash
python3 bench/mock_claude_api.py --port 9443 --cert mock.crt --key mock.key &
ANTHROPIC_API_KEY=placeholder wisp-console ... -ai-url https://localhost:9443 -ai-ca mock.crt
```

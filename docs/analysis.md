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
| +5 each, max +15 | each further distinct rule whose first alert in the incident is medium or higher |
| +4 each, max +12 | more ATT&CK techniques: a chain, not a one-off |
| +5 | a never-before-seen program (`ANOM-001`) is part of it, together with at least one other rule (an incident of `ANOM-001` alone gets nothing) |
| +5 | an AI agent was the actor |
| +10 | the same medium-or-higher detection fired on 3+ hosts within an hour: a campaign (the hosts are listed) |
| +10 / +5 | the host has an exploited / a reachable vulnerability |
| +3 | the host's identity is software-generated (trust `generated` or none). A `machine-id` identity is not penalised |
| +5 | a blocking rule matched but the host is in monitor mode, so nothing was stopped |
| −20 | contained: the sensor killed or blocked every offending process |

Priority: **P1** ≥ 75, **P2** ≥ 55, **P3** ≥ 30, **P4** below. Open incidents
are listed first, then by score. Triaging an incident (acknowledge, resolve,
reopen) triages all of its alerts at once.

An incident's ID is `INC-` plus its first alert's ID, so it stays stable while
the incident grows. After a console restart, once that alert has aged out of
the live window, the incident can get a new ID. Correlation uses the sensors'
timestamps, so clock skew between hosts can affect grouping and campaign
detection; ages and the time gates below use the console's receipt time.

## Fleet health

The **Analysis** page (`GET /api/analysis/health`) lists what needs fixing in
the fleet itself:

| Finding | Severity |
|---|---|
| hosts with an open P1/P2 incident that are in monitor mode | high |
| sensors over the 0.05% CPU budget | medium |
| hosts with a software-generated identity (trust `generated` or none) | medium |
| alert volume spike (last hour ≥ 10 and ≥ 3 × the hourly average of the hours before + 1) | medium |
| hosts that stopped reporting | low |
| mixed sensor versions | low |
| rules that are mostly noise | low |

## Rule review

For every rule that has fired (`GET /api/analysis/rules`), Wisp counts its
alerts, the hosts and programs involved, and how its alerts were triaged. A
resolved alert whose note says *benign*, *false positive*, *fp*, *expected*,
*known good*, *legit* or *legitimate* as a whole word counts as noise
("unexpected" does not), unless it is negated ("not benign", "wasn't
expected"). So write those words in triage notes when you close a false
positive. Alerts closed by an approved suggestion (triaged by
`<you> via S…`) never count as benign, whatever their note says.

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
| Gradual enforcement | a named group has been watched for 24 h and still has hosts in monitor mode, and no alert from a blocking rule in it was closed as benign in the last 7 days (by close time) | stages `enforce` to 10% of the group, then 50% and 100%, at least 24 h apart; a rollback to monitor holds it off for a week | deployer |
| Rule tuning / hardening | rule review found a noisy rule or one ready to block | records the decision; you edit `rules.conf` (shown) and push a reload | operator |
| Patch | an exploited vulnerability, or a reachable one with CVSS ≥ 9 | records the decision; the exact upgrade is shown | operator |
| Housekeeping | a P4 incident with no activity for 7 days | resolves its alerts | operator |
| AI recommendation | the AI assistant's triage or rule review (below) | as for its action type | **at least operator**, rollouts included |

Approving carries the action out through the same code paths as the
console's own controls. A rollout appears in rollout history as
`<you> via S…`. The suggestion is journaled as `applying` before anything is
done, then with its outcome; one that was being applied when the console
stopped comes back as `interrupted`. A rollout's result lists hosts that
could not be written to separately from hosts that were offline. The
decision, the approver and the outcome are journaled. Suggestions survive
restarts; decided ones are pruned after 30 days (at most 5,000 are kept).

What you will not see:

- a suggestion you rejected, for 7 days;
- one you approved, for 24 hours;
- an engine suggestion whose condition no longer holds: it expires, for
  example when the host was switched to enforce another way. Nothing expires
  while the inputs are unknown (a host whose mode has not been reported since
  a restart). If the condition comes back, the same suggestion ID is
  reopened.

Every action is validated twice, when proposed and again when approved:

- the action type must be one of `push`, `rollout`, `triage` or `manual`;
- the target must exist and be live;
- a rollout must name a group (an empty group would mean every group);
- a percentage must be 1–100;
- alert IDs must exist.

## AI assistant

### Turning it on

The assistant uses the Claude API (`claude-opus-5-5` by default). Give the
console a key in one of these ways:

1. `-ai-key-file`. Under the systemd unit the file must be a credential:
   add `LoadCredential=anthropic.key:/etc/wisp/console/anthropic.key` with
   `systemctl edit wisp-console` and put
   `-ai-key-file /run/credentials/wisp-console.service/anthropic.key` in
   `WISP_EXTRA` (see [installation.md](installation.md#3-install-the-console)).
   An unreadable file turns only the assistant off, with the reason in
   `/api/ai/status`; or
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
| `-ai-max-per-hour` | `60` | cap on API requests per hour, counting every attempt: retries, fallbacks and each round of a question |
| `-ai-fallback` | `true` | let the API retry a declined request on its recommended fallback model |

The console honours `HTTPS_PROXY` / `NO_PROXY`. `NO_PROXY` can list hosts,
domain suffixes and IPv4 CIDRs.

### What it does

| | Where | Result |
|---|---|---|
| **Triage** | incident drawer → *Ask AI to triage*, `POST /api/ai/triage` | verdict (malicious / suspicious / benign), confidence, a short summary, the reasoning, and recommended actions |
| **Rule review** | Analysis → a rule → *Ask AI to review*, `POST /api/ai/curate` | assessment and complete `rules.conf` lines |
| **Ask** | Analysis → *Ask about your fleet*, `POST /api/ai/ask` | an answer that cites hosts, incidents and rules. The model looks things up through ten read-only tools over the console's own data: incidents, alerts, the event journal, hosts, health, rule review, vulnerabilities and posture (see [what is sent](#data-sent-to-the-claude-api)) |

Requests run in the background (`GET /api/ai/jobs?id=`). The UI and SDKs wait
for them; a long analysis does not hold an HTTP request open. Triage verdicts
are shown on the incident, and rule reviews in Rule review.

### Safety

- **It only proposes.** Triage recommendations become suggestions only through
  the engine's validation. They are also kept inside the incident's scope: a
  push can only target the incident's host or a host in its campaign; a
  rollout only the incident host's own, named group (none when the host has
  no group); triage only the incident's own alerts, with a fixed note (the
  model's words never become a triage verdict). The assistant can never
  switch hosts to monitor. Rule lines must pass the sensor's grammar check and
  limits (id at most 23 characters, title under 160 bytes, at most 8
  conditions of at most 16 values each). A rule proposal that adds an
  `ignore` entry, lowers severity, stops blocking or narrows the rule is
  marked **weakens detection** in its title and instructions. Anything else
  is dropped, and the drop is shown to you. Everything that survives waits for
  a human with at least the operator role, marked **AI suggestion — review
  before approving**.
- **Telemetry is untrusted.** Command lines, file names and notes can be
  written by an attacker. They are sent as JSON data inside `<fleet_data>`
  tags, with `<`, `>` and `&` escaped so the data cannot close the tag, and
  the model is told never to follow instructions found there. The operator's
  question is escaped the same way. The rules above are the hard limit if it
  follows them anyway.
- **Secrets are redacted** in every string sent (fleet data, JSON keys and
  the question), on a best-effort, pattern basis:
  - private keys, credentials in URLs, `Authorization` headers;
  - `password=`, `token:`, `--api-key …`, `aws_secret_access_key`, `sig=`,
    secrets in JSON bodies and similar;
  - command-line passwords: `mysql -pSECRET`, `sshpass -p`, `redis-cli -a`,
    `docker login -p`, `sqlcmd -P`, `-u user:pass`, `-U user%pass` and
    similar;
  - base64 that decodes to a readable command is decoded, then redacted;
  - known token formats (AWS, GitHub, Slack, GitLab, JWT, Anthropic, Wisp);
  - other long mixed-case alphanumeric strings.

  Hex digests, file paths and harmless settings such as
  `PasswordAuthentication=no` or `--author=` are kept. Every string is cut to
  4 KB and invalid UTF-8 is replaced. A secret in a format these patterns do
  not know is sent as is.
- **Audited.** Every request is journaled as an `ai_result` record (see
  below). The API key is never written anywhere.
- **Bounded.** One request at a time, a queue of 8, and an hourly cap that
  counts every API attempt. A triage prompt holds at most 50 alerts and 200 KB
  of fleet data; a question gets at most 10 tool rounds, 40 KB per tool result
  and 400 KB of tool data in all.
- **Failures are explicit.**
  - If the model declines a request, the job fails with the reason, after the
    API's own fallback has been tried.
  - `429`, `408`, `409`, `5xx` and transport errors are retried (three
    attempts in all) with backoff, honouring `retry-after`.
  - Authentication and validation errors, configuration and certificate
    errors, and a request that ran into the full timeout are not retried. A
    broken configuration (bad `-ai-url`, unreadable `-ai-ca` or key file)
    shows the assistant as unavailable, with the reason.
  - Responses are not streamed: a very long `xhigh` or `max` generation can
    hit the 10-minute request timeout.
  - On console shutdown an in-flight request is abandoned within half a
    second and the job is marked failed.

### Data sent to the Claude API

Nothing is sent until someone with the operator role asks. Each request then
goes to a **third party**: `POST <-ai-url>/v1/messages` (Anthropic's API by
default, or the gateway you configure), over verified TLS, through
`HTTPS_PROXY` when set, with `anthropic-version: 2023-06-01`. Everything below
is redacted as described above before it is sent.

| Request | What is sent |
|---|---|
| **Triage** | the incident (score, reasons, summary, rules, campaign hosts); up to 50 of its alerts, most severe first, each with time, rule, title, severity, actor, pid, ppid, uid, program, executable, full command line, destination and port, path, status and triage note (the rest counted by rule); up to 60 related journal events of the same processes; and the host's record: identity and trust, group, mode, sensor version and resources, posture score and findings, and up to 40 software-inventory entries. Over 200 KB, the related events and host record are dropped first |
| **Rule review** | the rule's statistics (alerts, triage outcomes, hosts, top programs, engine assessment) and up to 40 recent alerts with host name, program, executable, command line, actor, uid, action, status and note |
| **Ask** | the question, then whatever the model asks for through its tools: incidents with all their alerts, alert searches, **raw journal records** (`search_events`), every host's record, a host's posture and full inventory, fleet health, rule review, vulnerabilities and posture. Up to 400 KB per question |

What the console keeps: each request is journaled as an `ai_result` record
with who asked, the kind and target, the model, token usage, and the result
(the model's answer, which can quote the redacted data) or the error. For Ask
the journaled question is redacted. The prompts themselves are not
journaled. `ai_result` records are not searchable from Investigate. The
operator-only `/api/ai/jobs` keeps the latest 200 jobs in memory, with the
question as typed.

How the provider handles the data, including retention and use, is governed
by your agreement with Anthropic (or with the operator of `-ai-url`). For a
privacy or compliance review, treat enabling the assistant as sending
hostnames, user IDs, command lines, file paths, network destinations,
software inventory and journal content, after best-effort secret redaction,
to that provider. Keep `-ai=false` (or no key) if that is not acceptable.

### Testing without a key

`bench/mock_claude_api.py` stands in for the Messages API. It checks every
request (headers, schema rules, strict tools, tool-result pairing) and replies
deterministically. The unit tests and `bench/verify.sh` use it:

```bash
python3 bench/mock_claude_api.py --port 9443 --cert mock.crt --key mock.key &
ANTHROPIC_API_KEY=placeholder wisp-console ... -ai-url https://localhost:9443 -ai-ca mock.crt
```

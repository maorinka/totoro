# Console API

Everything the web console does is available as a JSON API on the console's
HTTP address (default `127.0.0.1:8080`). Clients for Python and TypeScript
are in `sdk/`, and an MCP server for coding agents is in `mcp/`.

## Authentication

Send an API token as a bearer token:

```bash
curl -s -H "Authorization: Bearer $WISP_TOKEN" http://127.0.0.1:8080/api/summary
```

Tokens are issued with `wisp-console -gen-token <role>:<name>` (see
[security.md](security.md#roles)). Responses:

| Status | Meaning |
|---|---|
| `401` | no token, or the token is not recognised |
| `403` | the token's role is too low for this endpoint |
| `405` | wrong method. State changes are `POST` only, so a link or prefetch can never trigger one |
| `404` | unknown `/api/…` path (paths outside `/api/` serve the web UI) |
| `413` | request body over 1 MiB |
| `431` | request headers over 64 KiB |
| `501` | chunked request bodies (`Transfer-Encoding`); send `Content-Length` |

Errors are JSON: `{"error": "…"}`.

## Endpoints

### Public (no token)

| Method | Path | Returns |
|---|---|---|
| GET | `/healthz` | `ok`: the process is alive |
| GET | `/readyz` | `ready` (200) when ingest is listening and the journal is open, else 503 |
| GET | `/api/session` | `{"auth": true}`: whether this console requires tokens |

### Read (viewer and above)

| Method | Path | Returns |
|---|---|---|
| GET | `/api/me` | `{"role", "name"}` of the caller |
| GET | `/api/version` | `{"version", "runtime", "uptime_s", "auth"}`. `runtime` names the build, e.g. `C++ / OpenSSL 3.0.13 30 Jan 2024` |
| GET | `/api/summary` | everything on the Overview page: host counts by state and group, open alerts by severity, alerts per hour (24 values, oldest first), top rules, vulnerabilities by tier, fleet posture, sensor CPU (max, average, budget, hosts over budget), recent rollouts |
| GET | `/api/hosts?state=&group=` | hosts. `state`: `active`, `stale`, `decommissioned`, `all`; default is the live fleet (everything not decommissioned) |
| GET | `/api/hosts/detail?name=` | one host: record, posture with findings, its latest 100 alerts, current software inventory |
| GET | `/api/alerts?…` | alerts, newest first. Filters: `severity` (minimum: `low` … `critical`), `status` (`open`, `acknowledged`, `resolved`, `all`), `host`, `rule`, `actor`, `q` (text in rule, title, command, host, program), `limit` (default 500, max 5000) |
| GET | `/api/events?…` | the event journal, newest first. Any event field is a filter (`type=alert`, `host=web-01`, `rule=CRED-001`, `pid=4242`), plus `q` (substring), `since` / `until` (ISO-8601, compared as text) and `limit` (default 500) |
| GET | `/api/vulns` | vulnerability findings: `host`, `ecosystem`, `name`, `version`, `cve`, `severity`, `cvss`, `tier` (`exploited`, `reachable`, `dormant`, `theoretical`), `note`; most urgent first |
| GET | `/api/posture` | `{"fleet_score", "fleet_grade", "hosts": [{host, score, grade, trust, mode, vulns, unsanctioned_tooling, anomalies, alerts_by_severity, findings}]}`, weakest first |
| GET | `/api/inventory?host=` | latest 1000 inventory records (`kind`, `name`, `version`, `where`, `change`) |
| GET | `/api/policy/rollout` | rollout history, newest first: `ts`, `by`, `action`, `group`, `percent`, `cohort`, `delivered`, `failed` |

### Analysis (viewer and above)

See [analysis.md](analysis.md) for how incidents are scored and what each suggestion does.

| Method | Path | Returns |
|---|---|---|
| GET | `/api/incidents?status=&priority=&host=&limit=` | correlated incidents, open first then by score: `id`, `host`, `group`, `priority` (`P1`–`P4`), `score`, `severity`, `status`, `first_ts`, `last_ts`, `alert_count`, `rules`, `techniques`, `actors`, `campaign_hosts`, `contained`, `summary`, `reasons` (one line per scoring point), `ai` (verdict summary or null). `status` defaults to everything not resolved; `all` for everything |
| GET | `/api/incidents/detail?id=` | one incident plus `alerts`, the full `ai` record and its `suggestions` |
| GET | `/api/analysis/health` | `{"status": "ok"\|"attention"\|"critical", "hosts_live", "sensors_connected", "findings": [{id, severity, category, title, detail, hosts}]}` |
| GET | `/api/analysis/rules` | per rule: `alerts`, `open`, `acknowledged`, `resolved`, `benign`, `hosts`, `programs`, `assessment` (`ok`, `noisy`, `ready_to_enforce`), `advice`, `ai` |
| GET | `/api/suggestions?status=` | suggestions, newest first: `id`, `kind`, `title`, `rationale`, `severity`, `source` (`analysis` or `ai`), `status` (`proposed`, `applied`, `accepted`, `failed`, `rejected`, `expired`), `action`, `required_role`, `evidence`, `decided_by`, `decided_at`, `result`. Default: waiting for approval; `all` for everything |
| GET | `/api/ai/status` | `{"enabled", "reason", "model", "effort", "queued", "used_this_hour", "max_per_hour"}` |

### Deploy (deployer and above)

| Method | Path | Does |
|---|---|---|
| POST | `/api/policy/rollout?action=&group=&percent=` | push `action` (`enforce`, `monitor`, `reload`) to `percent`% (1–100) of `group` (all groups if empty). Each host has a fixed position in the order, so a larger percentage is always a superset of a smaller one. Returns the rollout record |

### Operate (operator and above)

| Method | Path | Does |
|---|---|---|
| POST | `/api/alerts/triage` | body `{"id", "status": "open"\|"acknowledged"\|"resolved", "note"}`; returns the updated alert. Recorded with the caller's name |
| POST | `/api/suggestions/decide` | body `{"id", "decision": "approve"\|"reject", "note"}`. Approving carries the action out; returns the suggestion with its `status` and `result`. A rollout suggestion needs deployer, everything else operator |
| POST | `/api/incidents/triage` | body `{"id", "status", "note"}`: triage every alert in the incident; returns `{"updated"}` |
| POST | `/api/analysis/run` | run the analysis now; returns `{"proposed"}` (new suggestions) |
| POST | `/api/ai/triage` | body `{"incident"}`. Queues an AI triage; returns the job (`202`). `503` when the assistant is off, `429` when busy or over the hourly cap |
| POST | `/api/ai/curate` | body `{"rule"}`: AI review of one rule |
| POST | `/api/ai/ask` | body `{"question"}` (max 2000 characters): AI answer using read-only tools |
| GET | `/api/ai/jobs[?id=]` | AI jobs (newest 50), or one: `status` (`queued`, `running`, `done`, `failed`), `result`, `error`, `usage` |
| POST | `/api/policy/push?host=&action=` | push `enforce`, `monitor` or `reload` to one host. Returns `{"host", "action", "delivered"}` |
| GET | `/api/vault` | `{"keys": [...]}`: secret names |
| GET | `/api/vault?key=` | `{"key", "value"}`. Every read raises a `VAULT-ACCESS` audit alert with the reader's name |

### Administer (admin)

| Method | Path | Does |
|---|---|---|
| PUT | `/api/vault?key=` | store the request body (max 1 MiB) as the secret's value, encrypted at rest |

## Examples

```bash
H="Authorization: Bearer $WISP_TOKEN"; C=http://127.0.0.1:8080

# open critical alerts from AI agents
curl -s -H "$H" "$C/api/alerts?status=open&severity=critical&actor=ai"

# resolve one with a note
curl -s -H "$H" -X POST $C/api/alerts/triage \
  -d '{"id":"A1792680663-96","status":"resolved","note":"red-team exercise"}'

# everything that happened on a host during an incident window
curl -s -H "$H" "$C/api/events?host=web-01&since=2026-10-21T09:00&until=2026-10-21T10:00"

# canary 5% of prod-web into enforce, then widen
curl -s -H "$H" -X POST "$C/api/policy/rollout?action=enforce&group=prod-web&percent=5"
curl -s -H "$H" -X POST "$C/api/policy/rollout?action=enforce&group=prod-web&percent=100"
```

With the SDKs:

```python
from wisp import Wisp
w = Wisp("https://console.corp:8080", token=OPERATOR_TOKEN)
for inc in w.incidents(priority="P1"):
    print(inc["id"], inc["host"], inc["summary"])
    print(w.ai_triage(inc["id"])["verdict"])       # waits for the job
for s in w.suggestions():
    print(s["title"], s["required_role"])
w.decide(s["id"], approve=True, note="contain now")
```

The MCP server adds read-only `wisp_incidents`, `wisp_incident`,
`wisp_fleet_health` and `wisp_suggestions` tools. It has no approve tool, by
design: a coding agent can see what is suggested but cannot sign off on it.

## Sensor wire protocol

Sensors connect to the ingest port over mutual TLS and send newline-delimited
JSON: `hello` (identity, group, version, trust tier, ephemeral), `heartbeat`
(execs, CPU, memory, mode, active runtimes), `alert`, `inventory` and `bye`.
The console sends control lines back on the same connection:
`{"reload":true}`, `{"mode":"enforce"}`, `{"mode":"monitor"}`. One connection
speaks for one host. Console-only fields (`id`, `status`, triage, rollout
records) are stripped from anything a sensor sends.

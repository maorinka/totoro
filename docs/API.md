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
| `400` | malformed request: an encoded `/` (`%2F`) or a control character in the path, query parameters that are not UTF-8, or a bad body |
| `401` | no token, or the token is not recognised |
| `403` | the token's role is too low for this endpoint |
| `405` | wrong method. State changes are `POST` only, so a link or prefetch can never trigger one |
| `404` | unknown `/api/…` path (paths outside `/api/` serve the web UI) |
| `413` | request body over 1 MiB |
| `431` | request headers over 64 KiB |
| `501` | chunked request bodies (`Transfer-Encoding`); send `Content-Length` |

Errors are JSON: `{"error": "…"}`. Authenticated responses carry
`X-Wisp-Role` and `X-Wisp-User`. Every response, errors included, carries
`Content-Security-Policy`, `X-Frame-Options: DENY`,
`X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`,
`Cross-Origin-Opener-Policy: same-origin`, and `Strict-Transport-Security`
when served over HTTPS. A `HEAD` request gets the headers without a body, for
errors too. Each client address may hold at most 64 of the 1,024 HTTP
connections (see `-http-local-proxy` in
[configuration.md](configuration.md#network)).

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
| GET | `/api/me` | `{"role", "name"}` of the caller. Use it to check a token's role (the MCP server does, at startup) |
| GET | `/api/version` | `{"version", "runtime", "uptime_s", "auth"}`. `runtime` names the build, e.g. `C++ / OpenSSL 3.0.13 30 Jan 2024` |
| GET | `/api/summary` | everything on the Overview page: host counts by state and group, open alerts by severity, alerts per hour (24 values, oldest first), top rules, vulnerabilities by tier, fleet posture, sensor CPU (max, average, budget, hosts over budget), recent rollouts, and `incidents_open`: `{"total", "by_priority": {"P1", "P2", "P3", "P4"}}`, every incident not resolved, uncapped |
| GET | `/api/hosts?state=&group=` | hosts. `state`: `active`, `stale`, `decommissioned`, `all`; default is the live fleet (everything not decommissioned) |
| GET | `/api/hosts/detail?name=` | one host: record, posture with findings, its latest 100 alerts, current software inventory |
| GET | `/api/alerts?…` | alerts, newest first. Filters: `severity` (minimum: `low` … `critical`), `status` (`open`, `acknowledged`, `resolved`, `all`), `host`, `rule`, `actor`, `q` (text in rule, title, command, host, program), `limit` (default 500, max 5000) |
| GET | `/api/events?…` | the event journal, newest first. Any event field is a filter (`type=alert`, `host=web-01`, `rule=CRED-001`, `pid=4242`), plus `q` (substring), `since` / `until` (ISO-8601, compared as text) and `limit` (default 500). Each record carries `rx_ts`, the time the console received it; `since` / `until` compare the sensor's event time. Searches the in-memory index: the newest 50,000 security records and the newest 50,000 telemetry records ([operations.md](operations.md#retention-and-capacity)). AI job records are not included |
| GET | `/api/vulns` | vulnerability findings: `host`, `ecosystem`, `name`, `version`, `cve`, `severity`, `cvss`, `tier` (`exploited`, `reachable`, `dormant`, `theoretical`), `note`; most urgent first |
| GET | `/api/posture` | `{"fleet_score", "fleet_grade", "hosts": [{host, score, grade, trust, mode, vulns, unsanctioned_tooling, anomalies, alerts_by_severity, findings}]}`, weakest first |
| GET | `/api/inventory?host=` | latest 1000 inventory records (`kind`, `name`, `version`, `where`, `change`) |
| GET | `/api/policy/rollout` | rollout history, newest first: `id`, `ts`, `by`, `action`, `group`, `percent`, `cohort`, `delivered`, `failed`, `send_failed` (the failed hosts whose connection broke during the write), `status` (`complete`, or `interrupted` when the console stopped mid-rollout). `delivered` means written to a host heard from within `-stale-after`, not applied |

### Analysis (viewer and above)

See [analysis.md](analysis.md) for how incidents are scored and what each suggestion does.

| Method | Path | Returns |
|---|---|---|
| GET | `/api/incidents?status=&priority=&host=&limit=` | correlated incidents, open first then by score: `id`, `host`, `group`, `priority` (`P1`–`P4`), `score`, `severity`, `status`, `first_ts`, `last_ts`, `alert_count`, `rules`, `techniques`, `actors`, `campaign_hosts`, `contained`, `summary`, `reasons` (one line per scoring point), `ai` (verdict summary or null). `status` defaults to everything not resolved; `all` for everything |
| GET | `/api/incidents/detail?id=` | one incident plus `alerts`, the full `ai` record and its `suggestions` |
| GET | `/api/analysis/health` | `{"status": "ok"\|"attention"\|"critical", "hosts_live", "sensors_connected", "findings": [{id, severity, category, title, detail, hosts}]}` |
| GET | `/api/analysis/rules` | per rule: `alerts`, `open`, `acknowledged`, `resolved`, `benign`, `hosts`, `programs`, `assessment` (`ok`, `noisy`, `ready_to_enforce`), `advice`, `ai` |
| GET | `/api/suggestions?status=` | suggestions, newest first: `id`, `kind`, `title`, `rationale`, `severity`, `source` (`analysis` or `ai`), `status` (`proposed`, `applying`, `applied`, `accepted`, `failed`, `rejected`, `expired`, `interrupted`), `action`, `required_role` (the role needed to decide it), `can_approve` (whether **your** token may decide it), `evidence`, `decided_by`, `decided_at`, `result`. A curation suggestion that would weaken detection has `action.weakens` (the reason) and says so in its title. Default: waiting for approval; `all` for everything. Paged with `limit` (default 500, max 1000) and `offset`; the body is still an array, with `X-Total-Count` and, while more remain, `X-Next-Offset` response headers. Bad values return `400` |
| GET | `/api/ai/status` | `{"enabled", "reason", "model", "effort", "queued", "used_this_hour", "max_per_hour"}`. `reason` says why the assistant is off (no key, unreadable key or CA file, `-ai=false` …) |

### Deploy (deployer and above)

| Method | Path | Does |
|---|---|---|
| POST | `/api/policy/rollout?action=&group=&percent=` | push `action` (`enforce`, `monitor`, `reload`) to `percent`% (1–100) of `group` (all groups if empty). Each host has a fixed position in the order, so a larger percentage is always a superset of a smaller one. Returns the rollout record |
| POST | `/api/suggestions/decide` | decide a rollout suggestion from the analysis engine (body and rules under Operate, below) |

### Operate (operator and above)

| Method | Path | Does |
|---|---|---|
| POST | `/api/alerts/triage` | body `{"id", "status": "open"\|"acknowledged"\|"resolved", "note"}`; returns the updated alert. Recorded with the caller's name |
| POST | `/api/suggestions/decide` | body `{"id", "decision": "approve"\|"reject", "note"}`. Approving carries the action out; returns the suggestion with its `status` and `result`. A rollout suggestion from the analysis engine needs deployer, every other action operator, and any AI-sourced suggestion (`source: "ai"`) at least operator. `403` names the role needed |
| POST | `/api/incidents/triage` | body `{"id", "status", "note", "alert_ids"}`. With `alert_ids` (the alerts you were shown) only those are triaged; alerts that joined the incident since are left alone and counted in `skipped`. `409` when none of the ids still belong to it (the incident changed: reload it). Without `alert_ids`, every alert in the incident. Returns `{"incident", "status", "updated", "skipped"}` |
| POST | `/api/analysis/run` | run the analysis now; returns `{"proposed"}` (new suggestions) |
| POST | `/api/ai/triage` | body `{"incident"}`. Queues an AI triage; returns the job (`202`). `503` when the assistant is off, `429` when busy or over the hourly cap |
| POST | `/api/ai/curate` | body `{"rule"}`: AI review of one rule |
| POST | `/api/ai/ask` | body `{"question"}` (max 2000 characters): AI answer using read-only tools |
| GET | `/api/ai/jobs[?id=]` | AI jobs (newest 50), or one: `status` (`queued`, `running`, `done`, `failed`), `question` (redacted, as journaled), `result`, `error`, `usage` |
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

With the SDKs. Never approve suggestions in bulk: AI-sourced ones are built
from telemetry an attacker can shape, and rollouts change fleet policy, so
leave both to a person in the console and approve the rest one at a time
after someone has read them:

```python
from wisp import Wisp
w = Wisp("https://console.corp:8080", token=OPERATOR_TOKEN, cafile="/etc/wisp/ca.pem")
for inc in w.incidents(priority="P1"):
    print(inc["id"], inc["host"], inc["summary"])
    print(w.ai_triage(inc["id"])["verdict"])       # waits for the job

for s in w.suggestions():                          # waiting for approval
    if s["source"] == "ai" or s["action"].get("type") == "rollout":
        print("review in the console:", s["id"], s["title"])
        continue
    print(s["id"], s["title"], s["rationale"], s["evidence"])
    if input(f"approve {s['id']}? [y/N] ").strip().lower() == "y":
        w.decide(s["id"], approve=True, note="reviewed by <name>")
```

```ts
import { Wisp } from "./wisp";
const w = new Wisp("https://console.corp:8080", OPERATOR_TOKEN);
for (const s of await w.suggestions()) {
  if (s.source === "ai" || s.action["type"] === "rollout") { console.log("review in console:", s.id, s.title); continue; }
  console.log(s.id, s.title, s.rationale, s.evidence);
  if (reviewed.has(s.id)) await w.decide(s.id, true, "reviewed by <name>");  // ids a person confirmed
}
```

TLS is always verified. For a console with a private CA:

| Client | Private CA | Turn verification off (throwaway dev setups only) |
|---|---|---|
| Python SDK | `cafile=` or `context=` | `insecure_skip_tls_verify=True` (`verify=False` is a deprecated spelling) |
| Python CLI (`python3 sdk/wisp.py`) | `--ca` or `WISP_CA` | `--insecure-skip-tls-verify` |
| TypeScript SDK | `NODE_EXTRA_CA_CERTS=/path/ca.pem`, or a `fetch` bound to your own undici dispatcher | never set `NODE_TLS_REJECT_UNAUTHORIZED=0` |
| MCP server | `WISP_CA` | `WISP_INSECURE_SKIP_TLS_VERIFY=1` |

All of them refuse to send the token over plain `http://` to a non-loopback
host unless explicitly allowed (`allow_plaintext_token=True`,
`{ allowPlaintextToken: true }`, `WISP_ALLOW_PLAINTEXT_TOKEN=1`).

### MCP server

`mcp/wisp_mcp.py` is a stdio MCP server (stdlib only) with read-only tools:
`wisp_fleet`, `wisp_alerts` (default 50, max 500), `wisp_vulns`,
`wisp_incidents`, `wisp_incident`, `wisp_fleet_health`, `wisp_suggestions`
(`status: "all"` pages with `limit`, default 100, and `offset`) and
`wisp_check_package`. It has no approve tool, by design: a coding agent can
see what is suggested but cannot sign off on it. Because an agent can usually
read the server's token from its own MCP configuration, give it a **viewer**
token:

```bash
wisp-console -gen-token viewer:mcp
```

```json
{ "mcpServers": { "wisp": { "command": "python3", "args": ["mcp/wisp_mcp.py"],
    "env": { "WISP_URL": "https://console:8080", "WISP_TOKEN": "<viewer token>", "WISP_CA": "/etc/wisp/ca.pem" } } } }
```

The server asks `/api/me` for its token's role at startup and refuses to start
unless it is `viewer`, and re-checks `X-Wisp-Role` on every response.
`WISP_MCP_ALLOW_PRIVILEGED_TOKEN=1` overrides this with a warning; never set it
where an agent runs. Tool output is redacted and wrapped in a `<fleet_data>`
envelope marked untrusted. `wisp_check_package` reads the catalog and
vulnerability database locally (`WISP_CATALOG`, `WISP_VULNDB`; keep them in
step with the console) and answers `allow`, `deny` or `unknown`; treat
`unknown` (a source could not be read) as not approved.

## Sensor wire protocol

Sensors connect to the ingest port over mutual TLS and send newline-delimited
JSON: `hello` (identity, group, version, trust tier, ephemeral), `heartbeat`
(execs, CPU, memory, mode, active runtimes), `alert`, `inventory` and `bye`.
The console sends control lines back on the same connection:
`{"reload":true}`, `{"mode":"enforce"}`, `{"mode":"monitor"}`. One connection
speaks for one host. Console-only fields (`id`, `status`, triage, rollout
records) are stripped from anything a sensor sends.

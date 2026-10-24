# Configuration reference

- [Sensor: `/etc/wisp/wisp.conf`](#sensor)
- [Console: flags and environment](#console)

Policy files (rules, catalog, network policy, file-integrity watches) have
their own page: [policy.md](policy.md).

## Sensor

`/etc/wisp/wisp.conf` holds `key = value` lines. `#` starts a comment, either
on its own line or after whitespace. Validate after every edit:

```bash
sudo wispd --check-config     # prints a summary; exits 1 with file:line errors
sudo systemctl reload wispd   # applies rules, catalog and network policy without a restart
```

Unknown keys and invalid values (including numbers outside the ranges
below) are reported by `--check-config`, which exits 1. A running sensor logs
them and keeps the default. `--check-config` also fails when `fim.conf` is
missing or unreadable (that would mean no file-integrity monitoring), and when
`console` is set without readable `ca`, `cert` and `key`. Its summary names
configured watch paths that do not exist yet.

### Policy files

| Key | Default | Meaning |
|---|---|---|
| `rules` | `/etc/wisp/rules.conf` | detection and response rules |
| `catalog` | `/etc/wisp/catalog.conf` | curated packages, IDE extensions and AI tools |
| `netpolicy` | `/etc/wisp/netpolicy.conf` | outbound network policy and rate limits |
| `fim` | `/etc/wisp/fim.conf` | file-integrity watched paths. Must exist and be readable |

### Behaviour

| Key | Default | Meaning |
|---|---|---|
| `mode` | `monitor` | `monitor` reports what it would block; `enforce` blocks (kills or quarantines). Individual rules can override it. Prefer changing it fleet-wide with a [staged rollout](console.md#rollouts) |
| `group` | `default` | fleet group shown in the console; rollouts and filters use it |
| `ephemeral` | `0` | `1` for CI runners and short-lived containers: the console retires the host as soon as the sensor exits |
| `telemetry` | `1` | write every exec and network flow to `telemetry.jsonl` (needed for `--search tree=`). The CPU governor suspends it under load |
| `anomaly_learn` | `3600` | seconds spent learning a host's normal programs before a never-seen program raises `ANOM-001`. `-1` disables. The baseline persists in `state_dir` |
| `inventory_interval` | `86400` | seconds between full software-inventory rescans (installs and removals are also watched live) |

### Performance

| Key | Default | Meaning |
|---|---|---|
| `cpu_budget` | `0.05` | hard CPU cap for the sensor's userspace process, as a percentage of one core. Must be a number in (0, 0.05]; anything else is rejected and `0.05` kept |
| `budget_mode` | `budget-first` | how eagerly to shed load to hold the cap. `budget-first` starts early; `security-first` keeps full coverage until actually at the cap. Both only ever sample exact repeats of proven-benign exec contexts. See [operations.md](operations.md#cpu-budget) |
| `coalesce_ms` | `0` (shipped config: `500`) | 0–5000. Under load, drain events in batches this many ms apart. Fewer wakeups mean far lower CPU, at up to this much added detection latency while the host is busy. The first event after an idle period is processed at once. The CPU governor runs on the exec path either way |
| `housekeeping` | `60` | seconds between heartbeats and maintenance ticks, 5–120 (the heartbeat must stay well inside the console's 3-minute stale window) |

### Console connection

| Key | Default | Meaning |
|---|---|---|
| `console` | (none, so standalone) | console ingest address, `host:port` |
| `ca` | | CA certificate that signed the console's certificate. **Required** when `console` is set: without it the sensor refuses to connect (it never talks to an unauthenticated console) |
| `cert` | | this sensor's client certificate |
| `key` | | its private key, or a TPM key blob when `tpm = 1` |
| `tpm` | `0` | `1`: the key is TPM-resident (OpenSSL `tpm2` provider; set `TPM2OPENSSL_TCTI` in the unit's environment) |
| `slack_webhook` | | not used by the sensor: Slack notifications are sent by the console (see below) |

### Paths

| Key | Default | Meaning |
|---|---|---|
| `log_dir` | `/var/log/wisp` | `alerts.jsonl`, `telemetry.jsonl`, `inventory.jsonl`. Rotated by `/etc/logrotate.d/wisp` (create + `SIGHUP`, on which the sensor reopens them; see [operations.md](operations.md#logs)) |
| `state_dir` | `/var/lib/wisp` | host identity seed, anomaly baseline, quarantined files |

## Console

`wisp-console` is configured with flags. The systemd unit reads
`/etc/wisp/console.env` for the listen addresses and any extra flags. Run
`wisp-console -h` for the built-in list.

The unit runs as a dynamic user that cannot read `/etc/wisp/console`, so any
file a flag names must reach it as a systemd credential and be given by its
path under `/run/credentials/wisp-console.service/` (values in `console.env`
are not expanded, so `${CREDENTIALS_DIRECTORY}` does not work there). See
[installation.md](installation.md#3-install-the-console).

### Network

| Flag | Default | Meaning |
|---|---|---|
| `-listen` | `:8750` | sensor ingest (mutual TLS) |
| `-cert`, `-key` | | ingest server certificate and key. Required outside `-dev` |
| `-client-ca` | | CA that signs sensor client certificates. Required outside `-dev` |
| `-http` | `127.0.0.1:8080` | web console and API |
| `-http-cert`, `-http-key` | | serve the web console over HTTPS. Without them, keep `-http` on loopback behind a TLS proxy |
| `-http-local-proxy` | `false` | set when a reverse proxy **on the same machine** carries every user: loopback clients are then exempt from the per-client connection limit (64 of the 1,024 HTTP connections per client address; IPv6 counted per /64). `X-Forwarded-For` is never trusted |
| `-max-sensors` | `16384` | most concurrent sensor connections. Each holds a thread: keep the unit's `TasksMax` above it |
| `-max-hosts` | `100000` | most hosts (not retired) the console tracks; hellos for new hosts past it are refused and logged |
| `-max-hosts-per-cert` | `0` (no limit) | most hosts one sensor client certificate may speak for. Set it to `1` when every sensor has its own certificate |

### Access and state

| Flag | Default | Meaning |
|---|---|---|
| `-roles` | | API token file (see [security.md](security.md#roles)). Required outside `-dev` |
| `-state-dir` | `.` | directory for the journal and vault; the systemd unit uses `/var/lib/wisp-console` |
| `-events` | `events.jsonl` | the event journal, relative to `-state-dir` |
| `-journal-max-mb` | `256` | rotate the journal past this size; one previous segment (`.1`) is kept, so disk use stays under about twice this. `0`: never rotate |
| `-vault` | `vault.json` | encrypted secrets store, relative to `-state-dir` |
| `-vulndb` | (bundled) | vulnerability database JSON; the copy built into the binary is used when empty |

### Fleet lifecycle

| Flag | Default | Meaning |
|---|---|---|
| `-stale-after` | `3m` | a host with no contact for this long is shown as **stale**. Pushes and rollouts to such a host are reported as not delivered |
| `-decommission-after` | `168h` | a persistent host silent this long is **decommissioned**; `0` never, otherwise at least `-stale-after`. Ephemeral hosts are retired as soon as they exit |

### Notifications

| Flag / env | Meaning |
|---|---|
| `-slack` / `WISP_SLACK_WEBHOOK` | Slack incoming-webhook URL; high and critical alerts are posted to it |

### Analysis and AI assistant

| Flag / env | Default | Meaning |
|---|---|---|
| `-analysis-interval` | `1m` | how often the analysis engine looks for new suggestions (min 5s) |
| `-ai` | `true` | set `-ai=false` to disable the AI assistant entirely |
| `-ai-key-file` | | file holding the Claude API key. Otherwise the vault secret `anthropic/api-key`, otherwise `ANTHROPIC_API_KEY`. Without a key the assistant stays off. An unreadable key file turns only the assistant off (the reason is in `/api/ai/status` and the log); the console still starts |
| `-ai-model` | `claude-opus-5-5` | Claude model |
| `-ai-effort` | `high` | `low`, `medium`, `high`, `xhigh` or `max` |
| `-ai-url` | `https://api.anthropic.com` | API base URL (a gateway that speaks the same API); must be `https://`. The certificate is always verified, against its IP SANs for an IP-literal URL |
| `-ai-ca` | | extra CA certificate to trust for `-ai-url` |
| `-ai-max-per-hour` | `60` | cap on Claude API requests per hour, counting every attempt (retries and multi-round questions included). `0` disables the assistant |
| `-ai-fallback` | `true` | server-side refusal fallback (`fallbacks: "default"`); not sent for Haiku models |
| `HTTPS_PROXY`, `NO_PROXY` | | outbound proxy (HTTP CONNECT) for the AI assistant and Slack. `NO_PROXY` takes hosts, domain suffixes, `*.domain` and IPv4 CIDRs |

See [analysis.md](analysis.md).

### Secrets vault key

| Environment | Meaning |
|---|---|
| `WISP_VAULT_KEY` | the vault master key material: at least 32 characters for a new store (`openssl rand -base64 32`) |
| `WISP_VAULT_KEY_FILE` | a file holding it (for example a systemd credential, `/run/credentials/wisp-console.service/vault.key`) |
| (neither) | a random key is generated once into `<vault>.key` with mode 0600 |

If a vault store exists but its key does not, the console refuses to start
rather than mint a new key that would make every stored secret unreadable.

### Other

| Flag | Meaning |
|---|---|
| `-gen-token role[:name]` | print a new API token and its `roles.conf` line, then exit |
| `-version` | print the version and exit |
| `-dev` | **development only**: no API authentication, and plaintext ingest is allowed. Logged loudly at startup |

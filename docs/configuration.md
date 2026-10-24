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

Unknown keys and invalid values are reported by `--check-config`. A running
sensor logs them and keeps the safe default.

### Policy files

| Key | Default | Meaning |
|---|---|---|
| `rules` | `/etc/wisp/rules.conf` | detection and response rules |
| `catalog` | `/etc/wisp/catalog.conf` | curated packages, IDE extensions and AI tools |
| `netpolicy` | `/etc/wisp/netpolicy.conf` | outbound network policy and rate limits |
| `fim` | `/etc/wisp/fim.conf` | file-integrity watched paths |

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
| `cpu_budget` | `0.05` | hard CPU cap as a percentage of one core. Values outside (0, 0.05] are clamped to 0.05 |
| `budget_mode` | `budget-first` | how eagerly to shed load to hold the cap. `budget-first` starts early; `security-first` keeps full coverage until actually at the cap. Both only ever sample programs proven benign. See [operations.md](operations.md#cpu-budget) |
| `coalesce_ms` | `0` (shipped config: `500`) | under load, drain events in batches this many ms apart. Fewer wakeups mean far lower CPU, at up to this much added detection latency while the host is busy. The first event after an idle period is processed at once |
| `housekeeping` | `60` | seconds between heartbeats and maintenance ticks (minimum 5) |

### Console connection

| Key | Default | Meaning |
|---|---|---|
| `console` | (none, so standalone) | console ingest address, `host:port` |
| `ca` | | CA certificate that signed the console's certificate |
| `cert` | | this sensor's client certificate |
| `key` | | its private key, or a TPM key blob when `tpm = 1` |
| `tpm` | `0` | `1`: the key is TPM-resident (OpenSSL `tpm2` provider; set `TPM2OPENSSL_TCTI` in the unit's environment) |
| `slack_webhook` | | not used by the sensor: Slack notifications are sent by the console (see below) |

### Paths

| Key | Default | Meaning |
|---|---|---|
| `log_dir` | `/var/log/wisp` | `alerts.jsonl`, `telemetry.jsonl`, `inventory.jsonl` (rotated by `/etc/logrotate.d/wisp`) |
| `state_dir` | `/var/lib/wisp` | host identity seed, anomaly baseline, quarantined files |

## Console

`wisp-console` is configured with flags. The systemd unit reads
`/etc/wisp/console.env` for the listen addresses and any extra flags. Run
`wisp-console -h` for the built-in list.

### Network

| Flag | Default | Meaning |
|---|---|---|
| `-listen` | `:8750` | sensor ingest (mutual TLS) |
| `-cert`, `-key` | | ingest server certificate and key. Required outside `-dev` |
| `-client-ca` | | CA that signs sensor client certificates. Required outside `-dev` |
| `-http` | `127.0.0.1:8080` | web console and API |
| `-http-cert`, `-http-key` | | serve the web console over HTTPS. Without them, keep `-http` on loopback behind a TLS proxy |

### Access and state

| Flag | Default | Meaning |
|---|---|---|
| `-roles` | | API token file (see [security.md](security.md#roles)). Required outside `-dev` |
| `-state-dir` | `.` | directory for the journal and vault; the systemd unit uses `/var/lib/wisp-console` |
| `-events` | `events.jsonl` | the event journal, relative to `-state-dir` |
| `-journal-max-mb` | `256` | rotate the journal past this size; one previous segment (`.1`) is kept, so disk use stays under about twice this |
| `-vault` | `vault.json` | encrypted secrets store, relative to `-state-dir` |
| `-vulndb` | (bundled) | vulnerability database JSON; the copy built into the binary is used when empty |

### Fleet lifecycle

| Flag | Default | Meaning |
|---|---|---|
| `-stale-after` | `3m` | a host with no contact for this long is shown as **stale** |
| `-decommission-after` | `168h` | a persistent host silent this long is **decommissioned**. Ephemeral hosts are retired as soon as they exit |

### Notifications

| Flag / env | Meaning |
|---|---|
| `-slack` / `WISP_SLACK_WEBHOOK` | Slack incoming-webhook URL; high and critical alerts are posted to it |

### Analysis and AI assistant

| Flag / env | Default | Meaning |
|---|---|---|
| `-analysis-interval` | `1m` | how often the analysis engine looks for new suggestions (min 5s) |
| `-ai` | `true` | set `-ai=false` to disable the AI assistant entirely |
| `-ai-key-file` | | file holding the Claude API key. Otherwise the vault secret `anthropic/api-key`, otherwise `ANTHROPIC_API_KEY`. Without a key the assistant stays off |
| `-ai-model` | `claude-opus-5-5` | Claude model |
| `-ai-effort` | `high` | `low`, `medium`, `high`, `xhigh` or `max` |
| `-ai-url` | `https://api.anthropic.com` | API base URL |
| `-ai-ca` | | extra CA certificate to trust for `-ai-url` |
| `-ai-max-per-hour` | `60` | cap on AI requests per hour |
| `-ai-fallback` | `true` | server-side refusal fallback (`fallbacks: "default"`); not sent for Haiku models |
| `HTTPS_PROXY`, `NO_PROXY` | | outbound proxy (HTTP CONNECT) for the AI assistant and Slack. `NO_PROXY` takes hosts, domain suffixes, `*.domain` and IPv4 CIDRs |

See [analysis.md](analysis.md).

### Secrets vault key

| Environment | Meaning |
|---|---|
| `WISP_VAULT_KEY` | the vault master key material |
| `WISP_VAULT_KEY_FILE` | a file holding it (for example a systemd credential) |
| (neither) | a random key is generated once into `<vault>.key` with mode 0600 |

If a vault store exists but its key does not, the console refuses to start
rather than mint a new key that would make every stored secret unreadable.

### Other

| Flag | Meaning |
|---|---|
| `-gen-token role[:name]` | print a new API token and its `roles.conf` line, then exit |
| `-version` | print the version and exit |
| `-dev` | **development only**: no API authentication, and plaintext ingest is allowed. Logged loudly at startup |

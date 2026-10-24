# Operations

Running Wisp day to day: health, logs, backups, capacity, upgrades and the CPU
budget.

## Health checks

| Check | How |
|---|---|
| Console alive | `GET /healthz` → `200 ok` |
| Console ready (ingest listening, journal open) | `GET /readyz` → `200 ready`, else `503` |
| Sensor running | `systemctl is-active wispd` |
| Sensor policy valid | `wispd --check-config` (exit 0) |
| Sensor reporting | the host is **Active** on the Hosts page; `/api/hosts?state=stale` lists silent ones |
| Sensor within budget | Overview → *Sensor CPU (peak host)*; `/api/summary` → `sensor_cpu.hosts_over_budget` |

Point your monitoring at `/readyz`, at `/api/summary` with a viewer token,
and at the systemd units.

## Logs

**Console**: journald (`journalctl -u wisp-console`). It logs startup
configuration, sensor connects and lifecycle changes, every API state change
and every API error (method, path, status, duration, user), rollouts, and
journal rotation.

**Sensor**: journald for its own messages. Its records go to JSONL files in
`log_dir` (`/var/log/wisp`):

| File | Contents | Rotation (`/etc/logrotate.d/wisp`) |
|---|---|---|
| `alerts.jsonl` | every alert, with the full process context | weekly, 26 kept, or at 100 MiB |
| `telemetry.jsonl` | every exec and outbound connection (when `telemetry = 1`) | daily, 7 kept, or at 200 MiB |
| `inventory.jsonl` | software installs and removals | weekly, 26 kept |

These files are the sensor's local record: `wispd --search` reads them, and
they are the right thing to forward to a SIEM (they are one JSON object per
line).

## Backups

Back up the console's state directory (`/var/lib/wisp-console`, or
`/var/lib/private/wisp-console` with `DynamicUser`) and `/etc/wisp/console/`:

| File | What | Notes |
|---|---|---|
| `events.jsonl`, `events.jsonl.1` | the journal: alerts, triage, inventory, lifecycle, rollouts | append-only; safe to copy while running |
| `vault.json` | encrypted secrets | useless without its key |
| `vault.json.key` | the vault master key, if you did not supply `WISP_VAULT_KEY` | **back up separately** from `vault.json`, or keep the key in your secret manager and pass `WISP_VAULT_KEY_FILE` |
| `/etc/wisp/console/roles.conf` | token hashes | |
| `/etc/wisp/console/*.crt, *.key` | TLS material | |

To restore, put the files back and start the console. It replays the journal
and restores hosts, alert triage and rollout history. Sensors reconnect on
their own.

On sensors, `/etc/wisp/` (policy) belongs in configuration management.
`/var/lib/wisp/seen.bloom` is the learned program baseline. Losing it only
means the host relearns for `anomaly_learn` seconds.

## Retention and capacity

The console keeps bounded windows in memory, and its journal on disk:

| | Limit |
|---|---|
| Alerts in the live view | newest 5,000 |
| Inventory records | newest 5,000 |
| Journal events indexed for search | newest 50,000 |
| Journal on disk | rotates at `-journal-max-mb` (256 MiB); one previous segment kept |

Older history stays in the rotated segment until the next rotation. Archive
`events.jsonl.1` before then if you need it longer. Memory use is set by these
windows, not by fleet size. Wisp has been exercised with about 20 hosts, so
measure before relying on it for large fleets.

## Upgrades

1. Upgrade the console: replace the binary, `systemctl restart wisp-console`.
   The journal format is append-only JSON; new versions read older journals.
2. Roll sensors in waves: replace `/usr/local/sbin/wispd` and restart. A
   restart is a normal stop, so the host briefly shows its last state and
   then **Active** again. It is not decommissioned.
3. Confirm sensor versions on the Hosts page (*Version* column).

## Policy changes

1. Edit the policy in version control. Run `wispd --check-config` in CI.
2. Distribute the files with configuration management.
3. Apply them with a rollout of **Reload policy**, staged by group and
   percentage if the change is risky.

## Moving to enforcement

Use a staged rollout (Rollouts → *Switch to enforce*), starting with a small
percentage of one group. Watch for `kill` responses on that cohort's alerts
before widening. To back out, roll out *Switch to monitor* to the same
percentage. Note that the sensor's `mode` in `wisp.conf` applies again on its
next restart, so make the final mode permanent in configuration too.

## CPU budget

Every sensor holds a hard self-imposed cap: **0.05% of one core** by default
(`cpu_budget`). It measures its own CPU about once a second under load and
sheds work in a fixed order:

1. **Telemetry.** It stops writing per-exec telemetry lines. Detection is
   unaffected.
2. **Sampling proven-benign churn.** It tells the kernel to forward only a
   sample of executions of programs that have run many times without ever
   alerting. Novel programs, and any program that has ever alerted, are
   always evaluated.

It restores full coverage when load eases. Measured on a 4-vCPU microVM:
about 0.002–0.007% of a core idle, and about 0.03% under a sustained storm of
2,000 program executions per second (`make verify` reproduces this). Loading
the eBPF program at sensor start costs about 1 second of CPU once. The budget
covers steady-state operation. See [BENCHMARKS.md](../BENCHMARKS.md).

## Rotating credentials

- **API tokens**: issue a new token with `-gen-token`, add its line to
  `roles.conf`, remove the old line, then `systemctl restart wisp-console`.
- **Sensor certificates**: issue new ones from the same CA, deploy them, and
  restart `wispd`. To revoke a host, re-issue certificates from a new CA.
  The console does not check certificate revocation lists.
- **Vault master key**: there is no in-place re-key. Read every secret out,
  start with a new key and an empty store, and write the secrets back.

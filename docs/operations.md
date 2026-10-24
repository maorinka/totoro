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
| `inventory.jsonl` | software installs and removals | weekly, 26 kept, or at 100 MiB |

Rotation renames each file and creates an empty one; `postrotate` sends the
sensor `SIGHUP`, on which it flushes buffered telemetry to the old file and
reopens every log by name, so no lines are lost (there is no
`copytruncate`). `SIGHUP` also reloads policy. The system runs logrotate
daily; `wisp-logrotate.timer` runs `/etc/logrotate.d/wisp` hourly, so a log
grows at most about an hour of output past its size limit. `alerts.jsonl` is
the only copy of alerts the sensor could not deliver while disconnected.

These files are the sensor's local record: `wispd --search` reads them
(rotated and compressed segments included), and they are the right thing to
forward to a SIEM (they are one JSON object per line). Records carry `start`,
`pstart` and `boot` (process start times and the first 8 hex digits of the
boot ID), so a reused PID is never confused with an earlier process:
`wispd --search tree=PID` shows the newest process that held the PID and lists
the others, and `tree=PID:START[@BOOT]` picks one.

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
| Alerts in the live view | newest 5,000, and at most about 64 MiB (over that, the heaviest host's oldest go first) |
| Inventory records | newest 5,000, same byte bound |
| Journal events indexed for search (Investigate, `/api/events`) | newest 50,000 security records (alerts, triage, rollouts, suggestions, audit) and, separately, newest 50,000 telemetry records (hellos, inventory, flows), each at most about 128 MiB |
| Journal on disk | rotates at `-journal-max-mb` (256 MiB); one previous segment kept |

Older history stays in the journal files until the next rotation, but is no
longer searchable from the console; read `events.jsonl` / `events.jsonl.1`
directly (one JSON object per line), and archive `events.jsonl.1` before the
next rotation if you need it longer.

The windows bound the data held in memory, not the whole footprint: every
connected sensor holds one thread (default 8 MiB virtual stack) and its TLS
state, about 0.1 MB RSS per host as measured with 1,000 idle simulated
sensors. Memory and task count therefore grow linearly with connected hosts.
Size the unit's `TasksMax` (20480 shipped, above `-max-sensors` 16384),
`MemoryMax` and the host's overcommit policy for your fleet. Wisp has been
exercised with about 20 real hosts, so measure before relying on it for large
fleets.

## Upgrades

1. Back up the state directory, then upgrade the console: replace the
   binary, `systemctl restart wisp-console`. The journal is append-only JSON;
   new versions read older journals, but an older console may not read a newer
   one correctly (1.0 ignores 1.1.0's certificate bindings and misreads split
   rollout records), so a rollback means restoring the backup. See [Upgrading to 1.1.0](installation.md#upgrading-to-110).
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

Every sensor holds a hard self-imposed cap on its userspace process:
**0.05% of one core** by default (`cpu_budget`). Under load it re-measures its
own CPU from the exec-processing path (every 250 ms near the budget, every
second otherwise, with or without `coalesce_ms`), and from a 1-second timer
while it is shedding. It sheds work in a fixed order:

1. **Telemetry.** It stops writing per-exec telemetry lines. Detection is
   unaffected.
2. **Sampling proven-benign repeats.** It tells the kernel to forward only a
   sample of exact repeats of exec contexts (program, full command line, uid,
   terminal, parent and grandparent name) that have been evaluated a dozen times
   without an alert. Any other exec is always evaluated, and the set is
   re-proven after every policy reload and every 30 minutes.

It restores full coverage when load eases. What this does not cover:

- Sampling can miss a repeat that a rule would treat differently only because
  of the inherited actor (the same command, same parents, now under an AI
  agent).
- A storm of *distinct* command lines cannot be sampled without losing
  coverage, so it is evaluated in full and the sensor can exceed its budget
  while it lasts. The heartbeat (`cpu_pct`, `sample_n`, `sampled_drops`) and
  the log show it.
- If the kernel's exec ring buffer fills, events are lost and the sensor logs
  `bpf: N exec events lost: ring buffer full`.

 Measured on a 4-vCPU microVM:
about 0.002–0.007% of a core idle, and about 0.03% under a sustained storm of
2,000 program executions per second (`make verify` reproduces this, on a
disposable test machine only). Loading the eBPF program at sensor start costs
about 1 second of CPU once. The budget covers steady-state operation of the
userspace sensor; the eBPF program's in-kernel cost is charged to the
processes that exec, and `make verify` reports it separately (`INFO`). See
[BENCHMARKS.md](../BENCHMARKS.md).

## Rotating credentials

- **API tokens**: issue a new token with `-gen-token`, add its line to
  `roles.conf`, remove the old line, then `systemctl restart wisp-console`
  (`systemctl reload` is enough with systemd 260+; it keeps the old tokens if
  the new file is invalid).
- **Sensor certificates**: issue new ones from the same CA with the **same
  subject**, deploy them, and restart `wispd`. The console accepts a renewal
  (same subject and host identity, no connection left on the old certificate)
  and raises a `HOST-ID-MISMATCH` alert for it; any other certificate change
  is refused control of the host. To revoke a host, re-issue certificates from
  a new CA. The console does not check certificate revocation lists.
- **Vault master key**: there is no in-place re-key. Read every secret out,
  start with a new key and an empty store, and write the secrets back.

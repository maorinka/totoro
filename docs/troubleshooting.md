# Troubleshooting

Start with the logs: `journalctl -u wisp-console -e` on the console, and
`journalctl -u wispd -e` plus `wispd --check-config` on a sensor.

## The console will not start

| Message | Fix |
|---|---|
| `no -roles file: refusing to serve an unauthenticated console` | create tokens with `wisp-console -gen-token admin:<name>` and pass the file with `-roles`. `-dev` disables auth, for local demos only |
| `sensor ingest requires -cert and -key` / `requires -client-ca (mutual TLS)` | give the ingest certificate, key and the CA that signs sensor certificates ([installation.md](installation.md#2-create-the-certificates)) |
| `roles.conf:N: …` | that line is malformed. Each line is `<token or sha256:hex> <viewer\|deployer\|operator\|admin> [name]`, and plaintext tokens must be 16+ characters. `placeholder token (e.g. CHANGE-ME-...)`: replace it with a `wisp-console -gen-token` line |
| `roles file … defines no tokens` | the shipped `roles.conf` holds only comments. Add the lines `-gen-token` prints |
| `vault store … exists but its key … is missing` | restore `vault.json.key` from backup, or set `WISP_VAULT_KEY`/`WISP_VAULT_KEY_FILE`. The console will not mint a new key: that would make every stored secret unreadable |
| `vault store … is corrupt` | restore `vault.json` from backup |
| `vulndb: …` | the `-vulndb` file is missing or not valid JSON. Omit the flag to use the bundled database |
| `wisp-console: listen 127.0.0.1:8080: Address already in use` | another process holds the port. The same message is used for the ingest port (`-listen`, `WISP_INGEST`) and the web port (`-http`, `WISP_HTTP`): check which address it names, then change that one in `/etc/wisp/console.env` |
| `ERROR: … (fix the file and restart the console)` about `-ai-key-file` | the API key file is unreadable. Only the AI assistant is off (see `/api/ai/status`); the console runs |

## I cannot sign in

- **"That token was not accepted"**: the token is not in `roles.conf`, or the
  console has not re-read the file since you added it. Run
  `systemctl restart wisp-console` (with systemd 260+ `systemctl reload` is
  enough; older systemd keeps the old copy of the credential on reload). The
  log line `roles: reloaded … (N token(s))` shows what was loaded.
- **"Your session is no longer valid"**: the token was removed or the console
  was restarted with a different roles file. Sign in again.
- The page stays blank: check the browser console. The UI needs JavaScript and
  loads only from the console itself. A proxy that rewrites responses or adds
  inline scripts will be blocked by its Content-Security-Policy.

## A host does not appear (or is stale)

On the sensor host:

```bash
journalctl -u wispd -e | grep console
```

| Sensor log | Meaning |
|---|---|
| `console: connected to …` | connected. If the host is still missing, check you are looking at the right console and that its state filter includes it |
| `console: '…' is set but 'ca' is not; refusing to connect …` | set `ca =` in `wisp.conf` to the CA that signed the console's certificate. The sensor never connects to an unauthenticated console |
| `console: TLS handshake failed` | certificate problem: the sensor's `ca` must be the CA that signed the **console's** certificate, the console's `-client-ca` must be the CA that signed the **sensor's** certificate, and the console's certificate must name the address in `console =` (subjectAltName) |
| `console: failed to load client cert …` / `client key load failed` | the `cert` / `key` paths in `wisp.conf` are wrong or unreadable (with `tpm = 1`, check `TPM2OPENSSL_TCTI`). A transient TPM key failure is retried |
| no console lines at all | `console =` is not set in `wisp.conf`, so the sensor runs standalone |

Also check that TCP 8750 is reachable from the host to the console.

On the console, `ingest: refused … hello(s) for new hosts` means `-max-hosts`
or `-max-hosts-per-cert` was reached. A `HOST-ID-MISMATCH` alert saying "the
connection was refused control of the host" means the host connected with a
different client certificate than the one recorded for it (see
[security.md](security.md#how-the-console-protects-itself)).

A host shown as **stale** has not been heard from within `-stale-after`
(default 3 minutes): powered off, network-isolated, or the sensor is stopped.
Investigate stale hosts you did not expect. Stopping the sensor is one thing an
attacker with root would do.

## The sensor will not start

| Message | Fix |
|---|---|
| `bpf: load/verify failed` | the kernel lacks BTF (`/sys/kernel/btf/vmlinux` is missing) or is older than 5.8. Use a newer kernel, or build the connector sensor: `SENSOR=connector make -C agent` |
| `bpf: attach failed` | tracefs is not available. The sensor tries to mount it; in a restricted container, mount `/sys/kernel/tracing` from the host |
| `unknown argument` | see `wispd --help` |

## Policy problems

```bash
sudo wispd --check-config
```

prints each problem as `file:line: message` and exits 1. Lines with problems
are **skipped**, never loaded in a more permissive form, so fix them and
reload (`systemctl reload wispd`).

## Too many alerts

Tune in monitor mode before enforcing (see [policy.md](policy.md#recommended-rollout)):
exclude legitimate tools from a rule (`!comm=…`), narrow the condition, or add
an `ignore` rule above it. Acknowledge or resolve what you have reviewed. The
Alerts page defaults to **Open**.

## Sensor CPU above the budget

The Overview's *Sensor CPU* tile turns amber near the budget and red above it.
The sensor's log explains what it is doing:

```
governor: 0.0640% > 0.0500% budget -> telemetry suppressed
governor: cpu …% > …% cap -> forwarding 1-in-3 repeats of proven-benign exec contexts (novel execs are always evaluated)
governor: load eased -> full event coverage restored (… execs sampled out in total)
```

Brief readings above the budget while the governor reacts (about a second)
are expected. Readings that stay above it usually mean a sustained storm of
*distinct* command lines, which cannot be sampled without losing coverage, or
an extreme exec storm on a small VM. Raise `coalesce_ms` to batch more events
per wakeup. `bpf: N exec events lost: ring buffer full` means events were lost
before the sensor saw them.

## A rollout shows failed hosts

"Failed" means the host was in the cohort but was not delivered to: it had
no connection, or had not been heard from within `-stale-after`. Hosts among them
whose connection failed during the write are also listed in `send_failed`.
Those hosts did not get the change. Run the same stage again once they are
back: hosts that already have it just apply it again.

## An alert disappeared

The live alert view holds the newest 5,000 alerts. Older ones can still be
found on **Investigate** (or `/api/events?rule=…`) while they are among the
newest 50,000 indexed security records. Past that they are only in the journal
files (`events.jsonl`, `events.jsonl.1` in the state directory) and in the
sensor's `alerts.jsonl`. Triage applies only to alerts still in the live view.

## An enforced quarantine left the file in place

The alert's response is `kill` and it carries `quarantine_error`. The sensor
refuses to move system and shared files: anything under `/usr`, `/bin`,
`/sbin`, `/lib*`, `/boot` or `/etc` (inside the process's own root), its own
binary or loader, files owned by root (or a container's root) in a directory
only that root and its group can write, root-owned files with other hard
links, files installed by dpkg (checked after the kill; if the dpkg database
cannot be read in full, the quarantine is refused), and anything on FUSE or an
unidentified mount.
A program that had already exited when the rule fired cannot be reached
either. The process is still killed. The rpm database is not checked, but rpm
installs root-owned files into root-owned directories, which are refused
anyway. A kill whose process start time no longer matches (the PID was
reused) is refused; for network policy the action then reads
`block-failed`.

## Python clients reject the console's certificate

Python 3.13+ requires CA certificates to carry a key-usage extension. Issue
your CA with `-addext "keyUsage=critical,keyCertSign,cRLSign"` as shown in
[installation.md](installation.md#2-create-the-certificates).

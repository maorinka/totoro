# Security model

What Wisp trusts, how it protects itself, and its limits.

## Components and trust boundaries

```
 endpoint (root)                      console host                    people / automation
 ┌──────────────┐   mutual TLS     ┌────────────────────┐   HTTPS + token   ┌──────────────┐
 │ wispd + eBPF │ ───────────────▶ │ wisp-console       │ ◀──────────────── │ browser, SDK,│
 │ policy files │ ◀─── control ─── │ journal, vault     │                   │ MCP server   │
 └──────────────┘                  └────────────────────┘                   └──────────────┘
```

- **Sensor ↔ console**: TLS 1.2+, with certificates in both directions. The
  console requires a client certificate signed by `-client-ca`, and the
  sensor verifies the console against `ca`. The console refuses to start
  without both outside `-dev`.
- **People ↔ console**: API bearer tokens. Serve the console over HTTPS
  (`-http-cert`) or keep it on loopback behind a TLS proxy. It warns at
  startup when plain HTTP is exposed beyond loopback.

## Roles

| Role | Read fleet data | Rollouts, approve rollout suggestions | Triage, approve other suggestions, single-host push, ask the AI, vault read | Vault write |
|---|:-:|:-:|:-:|:-:|
| viewer | ✓ | | | |
| deployer | ✓ | ✓ | | |
| operator | ✓ | ✓ | ✓ | |
| admin | ✓ | ✓ | ✓ | ✓ |

`roles.conf` lines are `sha256:<hex digest> <role> <display name>`, written by
`wisp-console -gen-token`. Plaintext tokens of at least 16 characters are
accepted for small setups, but only the hash needs to be on disk. Tokens are
compared in constant time. Every state change (triage, rollout, push, vault
read) is attributed to the token's display name: in the journal, in the
console's access log, and for vault reads as a `VAULT-ACCESS` alert.

## Analysis and the AI assistant

- Suggestions never act on their own. Each needs a person with the role the
  underlying action needs. Each is validated when proposed and again when
  approved (allow-listed action types, live targets, valid percentages and
  alert IDs). Each decision is journaled with the approver's name.
- Sensors cannot inject suggestions, decisions or AI results: those journal
  record types are console-only and are dropped from sensor connections.
- The AI assistant is off without an API key, and only an operator can start a
  request. Telemetry sent to the Claude API is redacted (keys, tokens,
  passwords, credentials in URLs, high-entropy strings) and framed as
  untrusted data, because command lines are attacker-controlled.
- Prompt injection is contained by construction. The model's output is only
  ever a proposal. Proposals are checked against the incident's scope (its
  host, campaign hosts and group). They may not weaken protection. Rule lines
  must parse. Everything waits for a human.
- The API key is read from a file, the encrypted vault or the environment. It
  is sent only to `-ai-url` over verified TLS and never logged or journaled.
- The MCP server exposes analysis read-only. An agent cannot approve its own
  suggestions.

## How the console protects itself

- **No ambient authority.** Without a roles file, or without mutual-TLS
  ingest, the console refuses to start unless explicitly put in `-dev` mode,
  which logs a warning.
- **Safe methods.** Every state change is `POST` (or `PUT` for the vault). A
  link, prefetch or image tag cannot trigger one.
- **Strict browser policy.** The web UI is served from the binary and loads
  nothing else. Responses carry `Content-Security-Policy: default-src 'self'`
  (no inline script or style), `X-Frame-Options: DENY`, `nosniff`,
  `Referrer-Policy: no-referrer`, and HSTS when served over HTTPS. All
  sensor-supplied text is inserted as text, never as markup.
- **Untrusted sensor input.** A sensor is authenticated but not trusted with
  console state. Console-only fields (alert IDs, triage, rollout records)
  are stripped from its messages before anything is journaled. It cannot use
  the reserved name `console`, and one connection speaks for exactly one
  host. Lines are capped at 1 MiB, and silent connections are dropped after
  10 minutes.
- **Identity changes are surfaced.** If a known hostname reconnects with a
  different hardware/platform identity, the console raises
  `HOST-ID-MISMATCH` rather than silently updating the record.
- **Resource limits.** HTTP read, write and idle timeouts; 64 KiB headers;
  1 MiB request bodies; bounded in-memory windows; size-rotated journal.
- **Process isolation (systemd).** The unit runs as an unprivileged dynamic
  user with no capabilities, a private `/tmp`, a read-only system, and
  `MemoryDenyWriteExecute`. TLS keys and `roles.conf` arrive as systemd
  credentials.
- **Secrets at rest.** Vault secrets are AES-256-GCM encrypted with the
  secret's name as associated data, so ciphertexts cannot be swapped between
  names. Writes are atomic. A store whose key is missing is refused rather
  than re-keyed.

## How the sensor protects itself

- It is **not a kernel module**. It loads a verifier-checked eBPF program,
  and the kernel removes it when the sensor exits.
- It runs as root **confined to a capability bounding set** (`CAP_BPF`,
  `CAP_PERFMON`, `CAP_SYS_PTRACE`, `CAP_KILL`, `CAP_DAC_READ_SEARCH`,
  `CAP_NET_ADMIN`), with `NoNewPrivileges`, a read-only system except its own
  log and state directories, and hard limits of 2% CPU and 64 MiB memory.
- **Policy fails closed.** A malformed policy line is reported and skipped,
  never reinterpreted as an allow. `--check-config` catches these before
  deployment.
- **Its own CPU use is capped.** It cannot become the noisy neighbour it is
  watching for (see [operations.md](operations.md#cpu-budget)).

## Limitations

Be aware of these when you deploy Wisp:

- **A root attacker on an endpoint can stop the sensor.** The console shows
  the host going **stale**, which is a signal worth alerting on. But a
  user-space sensor cannot defend itself against root.
- **Sensor certificates are not bound to hostnames.** Any valid client
  certificate can report as any hostname. Identity changes on a known host
  are flagged (`HOST-ID-MISMATCH`), but a brand-new name is accepted. Issue
  one certificate per host and keep the CA key offline.
- **No certificate revocation.** The console does not check CRLs or OCSP.
  To revoke, re-issue from a new CA.
- **The journal is append-only but not tamper-evident.** Someone with write
  access to the console's state directory can edit history. Forward the
  journal or the sensors' JSONL files to write-once storage if you need
  evidential integrity.
- **Network policy works at connection level.** It sees TCP connection
  attempts (destination, port, actor). It does not inspect payloads, and
  rate limits count connections per process, not requests on a kept-alive
  connection.
- **Under extreme exec storms the sensor samples.** To hold its CPU cap it
  samples executions of programs proven benign. Novel and ever-alerted
  programs are always evaluated.
- **Pushes are fire-and-forget.** "Delivered" means the command reached the
  sensor, not that it was applied. A mode pushed from the console lasts until
  the sensor restarts; then `wisp.conf` applies again.
- **macOS and Windows sensors** exist as source (EndpointSecurity, ETW) and
  compile against the platform APIs, but have not been run on those systems.
- **Repository history.** A secrets-vault key used during development was
  committed to this repository's history before 1.0.0. It protected only
  test data. Never reuse a vault created from a pre-1.0 checkout.

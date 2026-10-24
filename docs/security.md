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
  console requires a client certificate signed by `-client-ca` and refuses to
  start without one outside `-dev`. The sensor verifies the console against
  `ca` and refuses to connect when `ca` is not set.
- **People ↔ console**: API bearer tokens. Serve the console over HTTPS
  (`-http-cert`) or keep it on loopback behind a TLS proxy. It warns at
  startup when plain HTTP is exposed beyond loopback. The SDKs and the MCP
  server verify TLS certificates and refuse to send a token over plain HTTP
  to a non-loopback host unless explicitly allowed.

## Roles

| Role | Read fleet data | Rollouts, approve engine rollout suggestions | Triage, approve other and all AI suggestions, single-host push, ask the AI, vault read | Vault write |
|---|:-:|:-:|:-:|:-:|
| viewer | ✓ | | | |
| deployer | ✓ | ✓ | | |
| operator | ✓ | ✓ | ✓ | |
| admin | ✓ | ✓ | ✓ | ✓ |

`roles.conf` lines are `sha256:<hex digest> <role> <display name>`, written by
`wisp-console -gen-token`. Plaintext tokens of at least 16 characters are
accepted for small setups (with a warning), but only the hash needs to be on
disk. Placeholder tokens (`CHANGE-ME-…` and similar), duplicate tokens and a
file with no tokens are refused. Tokens are compared in constant time.
`SIGHUP` re-reads the file and keeps the current tokens if the new one is
invalid. Every state change (triage, rollout, push, vault
read) is attributed to the token's display name: in the journal, in the
console's access log, and for vault reads as a `VAULT-ACCESS` alert.

## Analysis and the AI assistant

- Suggestions never act on their own. Each needs a person with the role the
  underlying action needs (deployer for a rollout, operator otherwise), and
  any AI-sourced suggestion needs at least operator. Each is validated when
  proposed and again when approved (allow-listed action types, live targets,
  a named group for rollouts, valid percentages and alert IDs). Each decision
  is journaled with the approver's name. A triage carried out by an approved
  suggestion is recorded as `<you> via S…` and never counts toward a rule's
  benign tally.
- Sensors cannot inject suggestions, decisions or AI results: those journal
  record types are console-only and are dropped from sensor connections.
- The AI assistant is off without an API key, and only an operator can start a
  request. Fleet data and the operator's question are sent to a third party,
  the Claude API at `-ai-url`; see
  [analysis.md](analysis.md#data-sent-to-the-claude-api) for exactly what is
  sent, what is journaled and how to review it. Everything is redacted
  (keys, tokens, passwords, credentials in URLs and command-line flags,
  high-entropy strings) and framed as untrusted data, because command lines are
  attacker-controlled. Redaction is pattern-based: it cannot recognise every
  secret.
- Prompt injection is contained by construction. The model's output is only
  ever a proposal. Proposals are checked against the incident's scope (its
  host, campaign hosts and the host's own named group). They may not switch
  hosts to monitor. Rule lines must parse and fit the sensor's limits, and a
  proposed rule that would detect less is marked **weakens detection**.
  Everything waits for a human, who must hold at least the operator role.
- The API key is read from a file, the encrypted vault or the environment. It
  is sent only to `-ai-url` over verified TLS and never logged or journaled.
- The MCP server exposes analysis read-only and has no approve tool. That
  alone would not stop an agent that can read the server's `WISP_TOKEN` from
  calling the API itself, so the token must be a **viewer** token
  (`wisp-console -gen-token viewer:mcp`). The server checks its role with
  `/api/me` at startup, and the `X-Wisp-Role` header on every response, and
  refuses to run with anything else. `WISP_MCP_ALLOW_PRIVILEGED_TOKEN=1`
  overrides this with a loud warning; never set it where an agent runs. Its
  tool output is redacted and wrapped as untrusted data.

## How the console protects itself

- **No ambient authority.** Without a roles file, or without mutual-TLS
  ingest, the console refuses to start unless explicitly put in `-dev` mode,
  which logs a warning.
- **Safe methods.** Every state change is `POST` (or `PUT` for the vault). A
  link, prefetch or image tag cannot trigger one.
- **Unambiguous paths.** A request path containing an encoded `/` (`%2F`) is
  refused with `400`, so `/api%2Fvault` cannot slip past a proxy rule that
  matches the raw path. Control characters in a path are refused too.
- **Strict browser policy.** The web UI is served from the binary and loads
  nothing else. Every response, errors included, carries
  `Content-Security-Policy: default-src 'self'` (no inline script or style,
  `frame-ancestors 'none'`), `X-Frame-Options: DENY`, `nosniff`,
  `Referrer-Policy: no-referrer`, `Cross-Origin-Opener-Policy: same-origin`,
  and HSTS when served over HTTPS. All sensor-supplied text is inserted as
  text, never as markup.
- **Untrusted sensor input.** A sensor is authenticated but not trusted with
  console state. Console-only fields (alert IDs, triage, rollout records)
  are stripped from its messages before anything is journaled. It cannot use
  the reserved name `console`, and one connection speaks for exactly one
  host. Lines are capped at 64 KiB and rate-limited per connection, and silent
  connections are dropped after 10 minutes. Audit records are console-only: any
  a sensor sends are dropped, also on journal replay.
- **Hosts are bound to their certificate.** The console records the SHA-256
  fingerprint and subject of the first client certificate each host connects
  with. A connection presenting a different certificate raises
  `HOST-ID-MISMATCH` and never gets the host's control link. A renewal (the
  same subject and host identity, with nothing connected on the recorded
  certificate) is accepted, and alerted. Alerts show a short fingerprint
  hash, not the host identity. A hardware/platform identity change on a known
  hostname also raises `HOST-ID-MISMATCH` rather than silently updating the
  record.
- **Resource limits.** HTTP read, write and idle timeouts; 64 KiB headers;
  1 MiB request bodies; 1,024 HTTP connections, at most 64 per client address
  (IPv6 per /64; loopback included unless `-http-local-proxy`; never based on
  `X-Forwarded-For`); `-max-sensors`, `-max-hosts` and `-max-hosts-per-cert`
  for ingest; bounded in-memory windows; size-rotated journal.
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
- It runs as root **confined to a capability set** (`CAP_BPF`,
  `CAP_PERFMON`, `CAP_SYS_PTRACE`, `CAP_KILL`, `CAP_DAC_READ_SEARCH`,
  `CAP_DAC_OVERRIDE`, `CAP_FOWNER`; `CAP_NET_ADMIN` is in the bounding set
  for the connector sensor only), with `NoNewPrivileges`, a read-only system
  except its own log and state directories, home directories read-only, and
  hard limits of 2% CPU and 64 MiB memory. This sandbox stops accidental
  writes; it is **not a boundary against a compromised sensor**, which as root
  with `CAP_SYS_PTRACE` and `CAP_DAC_OVERRIDE` can reach any file through
  another process's `/proc/<pid>/root`.
- **Responses are safe against PID reuse.** A kill or quarantine acts only on
  the process whose start time matches the event (through a pidfd where the
  kernel has one); a start time of 0 is refused. Quarantine refuses system,
  package-managed and shared files and only kills (the alert carries
  `quarantine_error`; see
  [troubleshooting.md](troubleshooting.md#an-enforced-quarantine-left-the-file-in-place)).
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
- **Sensor certificates are not bound to hostnames in advance.** The
  console binds a host to the first certificate it sees, but any valid client
  certificate can register a brand-new hostname. A certificate shared by the
  whole fleet gives no protection at all. Issue one certificate per host, set
  `-max-hosts-per-cert 1`, and keep the CA key offline.
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
  samples exact repeats of proven-benign exec contexts. Any exec whose context
  differs, or that has ever alerted, is always evaluated, but a sampled repeat
  that a rule would treat differently only because of its actor (the same
  command, now under an AI agent) can be missed. A storm of distinct command
  lines is evaluated in full and can push the sensor over its budget. If the
  kernel ring buffer fills, exec events are lost and logged.
- **Process trees are not airtight.** The sensor freezes a process tree before
  killing it, but a daemonized worker that left the tree before the freeze is
  only logged (as an escapee), not killed, and one that called `setsid` cannot
  be found at all.
- **Program names are the kernel's 15-character `comm`.** A rule with an exact
  `comm=` match on a longer name never matches; use `exe` or `comm^=`.
- **Pushes are fire-and-forget.** "Delivered" means the command was written
  to a live connection from a host heard from within `-stale-after`, not that
  it was applied. A mode pushed from the console lasts until the sensor
  restarts; then `wisp.conf` applies again.
- **macOS and Windows sensors** exist as source (EndpointSecurity, ETW) and
  compile against the platform APIs, but have not been run on those systems.
- **Repository history.** A secrets-vault key used during development was
  committed to this repository's history before 1.0.0. It protected only
  test data. Never reuse a vault created from a pre-1.0 checkout.

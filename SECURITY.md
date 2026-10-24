# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately to the maintainers rather
than in a public issue. Include the affected version (`wispd --version`,
`wisp-console -version`), a description, and steps to reproduce. We aim to
acknowledge reports within three working days.

## Supported versions

| Version | Supported |
|---|---|
| 1.1.x | Yes |
| 1.0.x | Yes |
| 0.x | No |

## Security model in brief

The full model, including what Wisp does **not** protect against, is in
[docs/security.md](docs/security.md). Key properties:

- Sensors authenticate to the console with mutual TLS; the console refuses
  plaintext ingest outside `-dev`.
- Console API access uses bearer tokens mapped to four roles; only token
  hashes are stored. Every state change is journaled with the caller's name.
- The web console loads no third-party code and runs under a strict CSP.
- The sensor runs as root confined to a capability bounding set; it is not
  a kernel module.

## Known limitations

- Rollout and policy pushes are acknowledged by delivery, not by the agent
  confirming it applied the change; check host mode on the Hosts page.
- Network policy is evaluated on TCP connection attempts; it does not
  inspect payloads.
- See [docs/security.md](docs/security.md#limitations) for the full list.

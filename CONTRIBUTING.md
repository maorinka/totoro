# Contributing

## Layout

| Path | What |
|---|---|
| `agent/` | the sensor (C, eBPF). `make -C agent`; `SENSOR=connector` for the non-eBPF fallback |
| `agent/bpf/` | eBPF programs (CO-RE); `vmlinux.h` is generated at build time |
| `console/` | fleet console (C++20: `src/`, tests in `tests/`, embedded UI generator in `tools/`) |
| `console/web/` | the web UI (plain HTML/CSS/JS, embedded into the binary) |
| `config/` | shipped policy and configuration |
| `packaging/` | installer and systemd units |
| `bench/` | verification suite, benchmarks, demo fleet |
| `docs/` | user and operator documentation |
| `sdk/`, `mcp/` | API clients and the MCP server |

## Before you send a change

```bash
make            # sensor + console
make test       # console tests under ASan+UBSan and TSan, UI syntax, shipped policy
                # (the AI tests use an in-process mock of the Claude API; needs the openssl CLI)
make verify     # integration suite; needs root and a BTF kernel
```

`make verify` runs sensors in enforce mode as root. Run it on a disposable
VM or CI runner, never on a production host. It keeps its files in a private
temporary directory and stops only its own processes, and it refuses to run
where Wisp is installed or running unless you pass `VERIFY_FLAGS=--force`.
Quarantine tests may only target copies of binaries inside that scratch
directory, matched by `exe^=` path prefix, never by command line.

- Keep the sensor inside its CPU budget: any change to the per-exec path must
  keep `make verify`'s CPU checks under 0.05% of one core.
- Policy parsing must fail closed: reject and report a malformed line, never
  reinterpret it as something more permissive.
- The console UI must not load anything from the network and must keep
  working under the CSP in `console/src/console.cpp`. Build DOM with the `h()`
  helper (text via `textContent`), never `innerHTML` with data.
- Update `CHANGELOG.md` and the relevant page in `docs/`.

## Trying the console with demo data

```bash
make
./console/wisp-console -gen-token admin:you        # prints a token and a roles.conf line
# save the roles.conf line to ./roles.conf
bash bench/mkpki.sh                                # test certificates in ./pki
./console/wisp-console -cert pki/console.crt -key pki/console.key \
  -client-ca pki/ca.crt -roles roles.conf -state-dir "$(mktemp -d)" &
python3 bench/demo_fleet.py                        # 20 simulated hosts
open http://127.0.0.1:8080                          # sign in with the token
```

UI changes: run the browser smoke test against that console (it fails on any
JavaScript or CSP error, checks every page in both themes and at phone width,
and exercises triage and rollouts):

```bash
WISP_ADMIN_TOKEN=… WISP_VIEWER_TOKEN=… node bench/ui_smoke.js
```

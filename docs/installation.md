# Installation

A Wisp deployment has two parts:

- **`wispd`**, the sensor, on every Linux endpoint, server, CI runner or
  container host you want to protect.
- **`wisp-console`**, the fleet console, on one server that every sensor can
  reach. It stores the event journal and serves the web console and API.

Sensors talk to the console over **mutual TLS** on port 8750. People and
automation use the web console and API on port 8080.

```
  wispd ──mTLS :8750──▶ wisp-console ◀──HTTPS── browser / SDK / MCP
  wispd ──────────────▶   (journal,      (via -http-cert or a TLS proxy)
  wispd ──────────────▶    vault)
```

## Requirements

| | Sensor (`wispd`) | Console (`wisp-console`) |
|---|---|---|
| OS | Linux x86_64: Debian 12+ and Ubuntu 24.04+ are supported. Ubuntu 22.04 and RHEL/Rocky 9 are below the release baseline (informational CI only). arm64 builds with the same Makefile but is not yet tested | Linux, same distributions |
| Kernel | 5.8+ with BTF (`/sys/kernel/btf/vmlinux` exists) for the eBPF sensor. Older kernels: build the connector sensor (`SENSOR=connector`) | any |
| Privileges | root, confined by the systemd unit to `CAP_BPF CAP_PERFMON CAP_SYS_PTRACE CAP_KILL CAP_DAC_READ_SEARCH CAP_DAC_OVERRIDE CAP_FOWNER` | an unprivileged dynamic user |
| Resources | under 0.05% of one core for the userspace process (hard budget), ~8 MiB RAM; unit caps at 2% CPU / 64 MiB | data windows are bounded (see [operations.md](operations.md#retention-and-capacity)), but every connected sensor also holds a thread with its own TLS state: about 0.1 MB RSS and one thread (with a default 8 MiB virtual stack) per connected host, measured with 1,000 idle simulated sensors. Size `TasksMax` (unit: 20480), `MemoryMax` and overcommit policy for that. Disk: the journal (2 × `-journal-max-mb`). Exercised with about 20 real hosts; measure before relying on it for large fleets |
| Network | outbound TCP to the console's ingest port | inbound 8750 from sensors; 8080 from operators |
| Runtime libraries | OpenSSL 3, `libbpf1`, `libelf`, `zlib` | `libssl3`/`libcrypto3` (OpenSSL 3) and `libstdc++` |

Building from source also needs `clang`, `libbpf-dev`, `libelf-dev`,
`zlib1g-dev`, `libssl-dev`, `bpftool` (Ubuntu: `linux-tools-$(uname -r)`), and
for the console a C++20 compiler (g++ 10+ or clang 12+), OpenSSL 3 and
`nlohmann-json3-dev`.

## 1. Get the software

Either download a release tarball and check it:

```bash
sha256sum -c wisp-1.1.0-linux-x86_64.tar.gz.sha256
tar xzf wisp-1.1.0-linux-x86_64.tar.gz && cd wisp-1.1.0-linux-x86_64
```

Release binaries are stripped and built reproducibly; debug symbols are in a
separate `-debug` tarball.

or build it:

```bash
make            # builds agent/wispd and console/wisp-console
make test       # optional: unit tests and policy checks
make dist       # optional: produce the tarball yourself
```

## 2. Create the certificates

Sensors and console authenticate each other with certificates from a CA you
control. Use your existing internal PKI if you have one. Otherwise, a minimal
CA with OpenSSL:

```bash
mkdir pki && cd pki
# the CA (keep ca.key offline once you have issued certificates)
openssl req -x509 -newkey rsa:3072 -nodes -keyout ca.key -out ca.crt -days 1825 \
  -subj "/CN=Wisp CA" -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"

# the console's server certificate: list every name sensors use to reach it
openssl req -newkey rsa:3072 -nodes -keyout console.key -out console.csr -subj "/CN=wisp.example.com"
printf 'subjectAltName=DNS:wisp.example.com\nextendedKeyUsage=serverAuth\n' > console.ext
openssl x509 -req -in console.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out console.crt -days 825 -extfile console.ext

# one client certificate per sensor (recommended) or per fleet group
openssl req -newkey rsa:3072 -nodes -keyout web-01.key -out web-01.csr -subj "/CN=web-01"
printf 'extendedKeyUsage=clientAuth\n' > client.ext
openssl x509 -req -in web-01.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out web-01.crt -days 825 -extfile client.ext
```

`bench/mkpki.sh` does the same with throwaway names, for testing only.

> **Hardware-backed identity.** On hosts with a TPM 2.0 the sensor's private
> key can live in the TPM (`tpm = 1`, OpenSSL `tpm2` provider). The key never
> leaves the chip, and the console records the host's trust tier as `tpm`.
> See `bench/tpm_identity_demo.sh` for the full flow.

## 3. Install the console

```bash
sudo ./packaging/install.sh --console   # from the tarball; or `sudo make install-console` from source
sudo install -m 0640 pki/console.crt /etc/wisp/console/console.crt
sudo install -m 0600 pki/console.key /etc/wisp/console/console.key
sudo install -m 0640 pki/ca.crt      /etc/wisp/console/sensor-ca.crt
```

Create API tokens. The command prints the token once, plus the line to store.
Only the token's SHA-256 hash is ever written to disk:

```bash
wisp-console -gen-token admin:"Ada Lovelace"
wisp-console -gen-token operator:"SOC on-call"
wisp-console -gen-token viewer:grafana
wisp-console -gen-token viewer:mcp          # for the MCP server: viewer only
# put each printed "sha256:... role name" line in /etc/wisp/console/roles.conf
sudo chmod 0600 /etc/wisp/console/roles.conf
```

The shipped `roles.conf` holds only comments, and the console refuses to start
with a file that defines no tokens or contains a placeholder such as
`CHANGE-ME-…`. Roles are described in [security.md](security.md#roles). Then
start it:

```bash
sudo systemctl enable --now wisp-console
curl -s localhost:8080/readyz      # -> ready
```

The unit passes the certificates and `roles.conf` to the service as
**systemd credentials**, runs it as an unprivileged dynamic user, and keeps
state in `/var/lib/wisp-console`. That user cannot read `/etc/wisp/console`:
every file a flag names must be a credential, given by its absolute path under
`/run/credentials/wisp-console.service/`. (`console.env` values are not
expanded, so `${CREDENTIALS_DIRECTORY}` stays literal there.)

`roles.conf` reaches the service as a copy made at start.
`systemctl reload wisp-console` (`SIGHUP`) re-reads it, but systemd refreshes
the copy on reload only from version 260 (`RefreshOnReload=credentials`).
Ubuntu 24.04 (255) and Debian 12 (252) need
`sudo systemctl restart wisp-console` after you edit it. The log line
`roles: reloaded … (N token(s))` shows what was loaded.

The web console listens on **127.0.0.1:8080** by default. To reach it from
other machines, either serve HTTPS directly with the ingest certificate,
which the unit already loads:

```ini
# /etc/wisp/console.env
WISP_HTTP=0.0.0.0:8443
WISP_EXTRA=-http-cert /run/credentials/wisp-console.service/console.crt -http-key /run/credentials/wisp-console.service/console.key
```

or put a TLS-terminating reverse proxy in front. If that proxy runs on the
console host, add `-http-local-proxy` to `WISP_EXTRA`: otherwise all users
share the per-client limit of 64 connections that loopback is subject to.

Any other secret file (a separate HTTPS certificate, the Claude API key, the
vault key) goes in a drop-in, `sudo systemctl edit wisp-console`:

```ini
[Service]
LoadCredential=anthropic.key:/etc/wisp/console/anthropic.key
LoadCredential=vault.key:/etc/wisp/console/vault.key
Environment=WISP_VAULT_KEY_FILE=/run/credentials/wisp-console.service/vault.key
```

and pass `-ai-key-file /run/credentials/wisp-console.service/anthropic.key`
in `WISP_EXTRA`. A vault key must be at least 32 characters of random
material: `(umask 077; openssl rand -base64 32 > /etc/wisp/console/vault.key)`.

Other settings, such as the Slack webhook and retention, are in
[configuration.md](configuration.md#console).

## 4. Install sensors

### One host, interactively

```bash
sudo ./packaging/install.sh
```

This installs `/usr/local/sbin/wispd` (`PREFIX` changes the prefix, and the
installed units follow it), the policy in `/etc/wisp/`, a logrotate policy, the
systemd unit and an hourly `wisp-logrotate.timer`. It validates the policy,
then starts the sensor in **monitor mode**, which reports but blocks nothing.
Re-running it on an upgraded tree restarts a running sensor onto the new
binary; existing policy files are kept and the new versions written as
`*.default`. Point the sensor at the console in `/etc/wisp/wisp.conf`
(`ca`, `cert` and `key` are all required with `console`):

```ini
console = wisp.example.com:8750
ca   = /etc/wisp/pki/ca.crt
cert = /etc/wisp/pki/agent.crt
key  = /etc/wisp/pki/agent.key
group = prod-web
```

then run `sudo systemctl restart wispd`.

### A fleet, unattended (MDM, Ansible, cloud-init, Jamf, Intune scripts)

The installer takes every per-host setting from the environment and never
prompts. Pass certificate material as files (preferred) or as PEM text from
your secret store; it is written mode 0600 under `/etc/wisp/pki`. Never put
PEM text on a `sudo VAR=… ./install.sh` command line: `sudo`'s arguments are
readable by every local user in `/proc`.

```bash
sudo WISP_CONSOLE=wisp.example.com:8750 \
     WISP_GROUP=prod-web \
     WISP_MODE=monitor \
     WISP_CA_PEM_FILE=/run/secrets/ca.crt \
     WISP_CERT_PEM_FILE=/run/secrets/host.crt \
     WISP_KEY_PEM_FILE=/run/secrets/host.key \
     ./packaging/install.sh
```

The install fails before changing anything when `WISP_CONSOLE` is set without
a CA, certificate and key (from the environment or an existing `wisp.conf`),
or when `WISP_TPM=1` is set without a key.

| Variable | Meaning |
|---|---|
| `WISP_CONSOLE` | console `host:port` |
| `WISP_GROUP` | fleet group; drives staged rollouts and filtering |
| `WISP_MODE` | `monitor` (default) or `enforce` |
| `WISP_EPHEMERAL` | `1` for CI runners and short-lived containers (retired from the fleet view on exit) |
| `WISP_CA_PEM_FILE`, `WISP_CERT_PEM_FILE`, `WISP_KEY_PEM_FILE` | mTLS material as files |
| `WISP_CA_PEM`, `WISP_CERT_PEM`, `WISP_KEY_PEM` | the same as PEM text (export it in an already-root environment, such as an MDM secret or `sudo -E`) |
| `WISP_TPM` | `1` when the key is TPM-resident. Give the TSS2 key blob as `WISP_KEY_PEM(_FILE)`, or its path on the host as `WISP_KEY_PATH` |

### Golden images and containers

Install into a staging root without starting anything. The installer
enables the unit inside the image, so the sensor starts on first boot:

```bash
sudo WISP_CONSOLE=… WISP_EPHEMERAL=1 ./packaging/install.sh --root /mnt/image --no-start
```

Every clone learns its own baseline of normal programs. A baseline baked into
an image belongs to another host, so the sensor rejects it.

## 5. Check it worked

- The host appears on the console's **Hosts** page within a few seconds.
- `sudo wispd --check-config` prints `OK`.
- `cat ~/.ssh/id_rsa >/dev/null` (if the file exists) produces a `CRED-001`
  alert under **Alerts**.

Next: tune policy in monitor mode, then move to enforcement with a staged
rollout. See [policy.md](policy.md).

## Upgrading

Replace the binaries and restart. Console state (the journal, triage, rollout
history and vault) and sensor state (the anomaly baseline) carry over. Back up
the console's state directory first (see
[operations.md](operations.md#backups)): a newer console's journal cannot
always be read by an older one.

```bash
sudo install -m0755 bin/wisp-console /usr/local/bin/ && sudo systemctl restart wisp-console
sudo install -m0755 bin/wispd /usr/local/sbin/        && sudo systemctl restart wispd
```

Upgrade the console first. Sensors reconnect automatically.

### Upgrading to 1.1.0

1.1.0 is stricter in several places. Act on these before or while upgrading:

- **roles.conf**: placeholder tokens (`CHANGE-ME-…`, `example`, `<…>`) are
  refused and the console will not start with them, or with a file that
  defines no tokens. Replace them with `wisp-console -gen-token` lines.
- **Sensors need `ca`**: a sensor with `console =` set refuses to connect
  without `ca =` (and `cert =`/`key =`). `--check-config` reports it.
- **Sensor config values are validated**: an out-of-range `cpu_budget`,
  `housekeeping` (5–120) or `coalesce_ms` is rejected and the default kept,
  and a missing `fim.conf` fails `--check-config`.
- **Log rotation**: `/etc/logrotate.d/wisp` now uses `create` and a
  `postrotate` `SIGHUP` (the sensor reopens its logs) instead of
  `copytruncate`, and `wisp-logrotate.timer` checks sizes hourly. Re-run
  `install.sh` or install both files; if you ship your own logrotate policy,
  make the same change. `SIGHUP` also reloads policy.
- **Local reverse proxies**: loopback is no longer exempt from the per-client
  HTTP connection limit. Add `-http-local-proxy` when a proxy on the console
  host carries every user.
- **Host certificate binding**: the console records the first client
  certificate each host connects with. A different certificate later raises
  `HOST-ID-MISMATCH` and does not get control of the host; a renewal (same
  subject and host identity, old certificate not connected) is accepted, and
  alerted all the same. Expect one alert per host when you rotate sensor
  certificates. A certificate shared by the whole fleet gives no protection:
  issue one per host and consider `-max-hosts-per-cert 1`.
- **Journal format 3**: the 1.1.0 console writes format 3 (large rollout
  records split into parts, certificate bindings). It replays 1.0 journals. A
  1.0 console replays a 1.1.0 journal but ignores the certificate bindings and
  treats each part of a split rollout record as a separate, partial rollout. To roll back, restore
  the state directory you backed up before the upgrade.
- **Approvals**: AI-sourced suggestions need at least the operator role,
  including AI rollout suggestions that a deployer could otherwise approve.
- **MCP server**: refuses to start unless its token is a viewer token
  (`wisp-console -gen-token viewer:mcp`).
- **Shipped policy**: the example network rules and the TypeScript version
  pin are commented out, and `LOL-002` now fires on `crontab FILE`, not on
  `crontab -l`. Copy back anything you relied on.
- **Vault**: a new vault store needs at least 32 characters of key material.
- **systemd < 260**: restart (not reload) the console after editing
  `roles.conf`.

## Uninstalling

```bash
sudo ./packaging/install.sh --uninstall      # sensor (honours --root); leaves /etc/wisp, logs and state in place
sudo systemctl disable --now wisp-console && sudo rm /usr/local/bin/wisp-console
```

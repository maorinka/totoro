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
| OS | Linux x86_64 (tested). arm64 builds with the same Makefile but is not yet tested | Linux |
| Kernel | 5.8+ with BTF (`/sys/kernel/btf/vmlinux` exists) for the eBPF sensor. Older kernels: build the connector sensor (`SENSOR=connector`) | any |
| Privileges | root, confined by the systemd unit to `CAP_BPF CAP_PERFMON CAP_SYS_PTRACE CAP_KILL` (+`CAP_DAC_READ_SEARCH`) | an unprivileged dynamic user |
| Resources | under 0.05% of one core (hard budget), ~8 MiB RAM; unit caps at 2% CPU / 64 MiB | modest: memory is bounded by fixed windows (5,000 alerts, 5,000 inventory records, 50,000 indexed events); disk by the journal (2 × `-journal-max-mb`). Tested with ~20 hosts; size up and measure for large fleets |
| Network | outbound TCP to the console's ingest port | inbound 8750 from sensors; 8080 from operators |
| Runtime libraries | OpenSSL 3, `libbpf1`, `libelf`, `zlib` | `libssl3`/`libcrypto3` (OpenSSL 3) and `libstdc++` (present on Ubuntu 22.04+, Debian 12+, RHEL 9+) |

Building from source also needs `clang`, `libbpf-dev`, `libelf-dev`,
`zlib1g-dev`, `libssl-dev`, `bpftool` (Ubuntu: `linux-tools-$(uname -r)`), and
for the console a C++20 compiler (g++ 10+ or clang 12+), OpenSSL 3 and
`nlohmann-json3-dev`.

## 1. Get the software

Either download a release tarball and check it:

```bash
sha256sum -c wisp-1.0.0-linux-x86_64.tar.gz.sha256
tar xzf wisp-1.0.0-linux-x86_64.tar.gz && cd wisp-1.0.0-linux-x86_64
```

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
sudo make install-console        # or copy bin/wisp-console to /usr/local/bin
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
# put each printed "sha256:... role name" line in /etc/wisp/console/roles.conf
sudo chmod 0600 /etc/wisp/console/roles.conf
```

Roles are described in [security.md](security.md#roles). Then start it:

```bash
sudo systemctl enable --now wisp-console
curl -s localhost:8080/readyz      # -> ready
```

The unit passes the certificates and `roles.conf` to the service as
**systemd credentials**, runs it as an unprivileged dynamic user, and keeps
state in `/var/lib/wisp-console`. The web console listens on
**127.0.0.1:8080** by default. To reach it from other machines, either put a
TLS-terminating reverse proxy in front, or serve HTTPS directly:

```ini
# /etc/wisp/console.env
WISP_HTTP=0.0.0.0:8443
WISP_EXTRA=-http-cert /etc/wisp/console/console.crt -http-key /etc/wisp/console/console.key
```

> With `-http-cert`, the key file must be readable by the service. Add it as
> another `LoadCredential=` line with `systemctl edit wisp-console` and point
> `-http-key` at `${CREDENTIALS_DIRECTORY}/…`.

Other settings, such as the Slack webhook and retention, are in
[configuration.md](configuration.md#console).

## 4. Install sensors

### One host, interactively

```bash
sudo ./packaging/install.sh
```

This installs `/usr/local/sbin/wispd`, the policy in `/etc/wisp/`, a logrotate
policy and the systemd unit. It validates the policy, then starts the sensor
in **monitor mode**, which reports but blocks nothing. Point the sensor at the
console in `/etc/wisp/wisp.conf`:

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
prompts. Pass certificate material as PEM text from your secret store. It is
written mode 0600.

```bash
sudo WISP_CONSOLE=wisp.example.com:8750 \
     WISP_GROUP=prod-web \
     WISP_MODE=monitor \
     WISP_CA_PEM="$CA_PEM" WISP_CERT_PEM="$HOST_CERT_PEM" WISP_KEY_PEM="$HOST_KEY_PEM" \
     ./packaging/install.sh
```

| Variable | Meaning |
|---|---|
| `WISP_CONSOLE` | console `host:port` |
| `WISP_GROUP` | fleet group; drives staged rollouts and filtering |
| `WISP_MODE` | `monitor` (default) or `enforce` |
| `WISP_EPHEMERAL` | `1` for CI runners and short-lived containers (retired from the fleet view on exit) |
| `WISP_CA_PEM`, `WISP_CERT_PEM`, `WISP_KEY_PEM` | mTLS material as PEM text |
| `WISP_TPM` | `1` when the key is TPM-resident (omit `WISP_KEY_PEM`) |

### Golden images and containers

Install into a staging root without starting anything. The unit starts the
sensor on first boot:

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
history and vault) and sensor state (the anomaly baseline) carry over.

```bash
sudo install -m0755 bin/wisp-console /usr/local/bin/ && sudo systemctl restart wisp-console
sudo install -m0755 bin/wispd /usr/local/sbin/        && sudo systemctl restart wispd
```

Upgrade the console first. Sensors reconnect automatically.

## Uninstalling

```bash
sudo ./packaging/install.sh --uninstall      # sensor; leaves /etc/wisp in place
sudo systemctl disable --now wisp-console && sudo rm /usr/local/bin/wisp-console
```

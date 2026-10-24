#!/usr/bin/env bash
# Sustained realistic-endpoint exec rate, measuring wispd CPU as % of one
# core over the whole run via /proc/PID/schedstat (nanosecond accurate;
# userspace sensor time only, not the in-kernel eBPF program).
#
#   sudo bench/sustained.sh [RATE] [SECS]
#
# Uses the repository's policy with logs and state in a private mktemp
# directory; starts and stops only its own wispd.
set -u
REPO=$(cd "$(dirname "$0")/.." && pwd)
WISPD=${WISPD:-$REPO/agent/wispd}
RATE=${1:-20}        # execs per second (a busy developer endpoint)
SECS=${2:-15}
W=$(mktemp -d "${TMPDIR:-/tmp}/wisp-sustained.XXXXXXXX") || exit 1
P=""
trap '[[ -n "$P" ]] && kill "$P" 2>/dev/null; rm -rf "$W"' EXIT
sed -e "s|/etc/wisp/|$REPO/config/|g" -e 's/^telemetry = .*/telemetry = 0/' \
    -e "s|^state_dir .*|state_dir = $W/state|; s|^log_dir .*|log_dir = $W/log|" \
    "$REPO/config/wisp.conf" | grep -vE '^[[:space:]]*(console|cert|key|ca)[[:space:]]*=' > "$W/sb.conf"
mkdir -p "$W/state" "$W/log"
"$WISPD" -c "$W/sb.conf" 2>/dev/null & P=$!
sleep 0.5
r0=$(awk '{print $1}' "/proc/$P/schedstat")
t0=$(date +%s.%N)
interval=$(echo "scale=6; 1/$RATE" | bc -l)
endt=$(echo "$(date +%s.%N) + $SECS" | bc -l)
n=0
while (( $(echo "$(date +%s.%N) < $endt" | bc -l) )); do
	/bin/true
	n=$((n+1))
	sleep "$interval"
done
t1=$(date +%s.%N)
r1=$(awk '{print $1}' "/proc/$P/schedstat")
kill "$P" 2>/dev/null; wait "$P" 2>/dev/null; P=""
wall=$(echo "$t1 - $t0" | bc -l)
ns=$((r1 - r0))
pct=$(echo "scale=6; 100 * $ns / ($wall * 1000000000)" | bc -l)
printf "rate=%d/s (achieved %.1f/s)  execs=%d  wall=%.2fs  cpu=%d ns (%.4f core-s)\n" "$RATE" \
	"$(echo "$n / $wall" | bc -l)" "$n" "$wall" "$ns" "$(echo "$ns/1000000000"|bc -l)"
printf "=> wispd used %.4f%% of one core  (budget 0.0500%%)  %s\n" "$pct" \
	"$(echo "$pct < 0.05" | bc -l | grep -q 1 && echo 'PASS' || echo 'OVER')"

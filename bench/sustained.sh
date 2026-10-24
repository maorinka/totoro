#!/usr/bin/env bash
# Sustained realistic-endpoint exec rate, measuring wispd CPU as % of one
# core over the whole run via /proc/PID/schedstat (nanosecond accurate).
set -u
WISPD=${WISPD:-/home/user/wisp-edr/agent/wispd}
RATE=${1:-20}        # execs per second (a busy developer endpoint)
SECS=${2:-15}
sed 's/^telemetry = .*/telemetry = 0/' /etc/wisp/wisp.conf > /tmp/sb.conf
: > /var/log/wisp/alerts.jsonl
"$WISPD" -c /tmp/sb.conf 2>/dev/null & P=$!
sleep 0.5
r0=$(awk '{print $1}' /proc/$P/schedstat)
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
r1=$(awk '{print $1}' /proc/$P/schedstat)
kill $P 2>/dev/null; wait $P 2>/dev/null
wall=$(echo "$t1 - $t0" | bc -l)
ns=$((r1 - r0))
pct=$(echo "scale=6; 100 * $ns / ($wall * 1000000000)" | bc -l)
printf "rate=%d/s  execs=%d  wall=%.2fs  cpu=%d ns (%.4f core-s)\n" "$RATE" "$n" "$wall" "$ns" "$(echo "$ns/1000000000"|bc -l)"
printf "=> wispd used %.4f%% of one core  (budget 0.0500%%)  %s\n" "$pct" \
	"$(echo "$pct < 0.05" | bc -l | grep -q 1 && echo 'PASS' || echo 'OVER')"

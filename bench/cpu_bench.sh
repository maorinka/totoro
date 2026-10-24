#!/usr/bin/env bash
# Measure wispd CPU as a percentage of ONE core, idle and under exec load.
# 0.05% of one core = 0.0005 core-seconds per wall second.
set -u
WISPD=${WISPD:-/home/user/wisp-edr/agent/wispd}
CONF=${CONF:-/etc/wisp/wisp.conf}
CLK=$(getconf CLK_TCK)   # usually 100

cpu_ticks() { awk '{print $14+$15}' "/proc/$1/stat" 2>/dev/null; }  # utime+stime

measure() {   # $1=label  $2=duration_s  $3=load_fn
	local label=$1 dur=$2 loadfn=$3
	local t0 c0 t1 c1
	t0=$(date +%s.%N); c0=$(cpu_ticks "$PID")
	$loadfn "$dur"
	t1=$(date +%s.%N); c1=$(cpu_ticks "$PID")
	local wall cores pct execs
	wall=$(echo "$t1 - $t0" | bc -l)
	cores=$(echo "($c1 - $c0) / $CLK" | bc -l)
	pct=$(echo "scale=6; 100 * $cores / $wall" | bc -l)
	execs=$(( $(wc -l < "$TELE") - BASE_EXEC ))
	BASE_EXEC=$(wc -l < "$TELE")
	printf "%-22s wall=%6.2fs cpu=%8.4f core-s  execs=%-7d => %7.4f%% of 1 core\n" \
		"$label" "$wall" "$cores" "$execs" "$pct"
}

idle()  { sleep "$1"; }

# A steady, *realistic* endpoint exec rate. A busy developer laptop sees a
# few execs/second on average; a quiet server far less. We push harder.
load_light() { local end=$((SECONDS+$1)); while [ $SECONDS -lt $end ]; do /bin/true; sleep 0.2; done; }  # ~5/s
load_busy()  { local end=$((SECONDS+$1)); while [ $SECONDS -lt $end ]; do /bin/true; /bin/true; /bin/true; done; } # as fast as possible

TELE=/var/log/wisp/telemetry.jsonl
: > "$TELE"; : > /var/log/wisp/alerts.jsonl
"$WISPD" -c "$CONF" 2>/var/log/wisp/wispd.err &
PID=$!
sleep 0.5
BASE_EXEC=$(wc -l < "$TELE")
echo "wispd pid=$PID  CLK_TCK=$CLK  RSS=$(awk '/VmRSS/{print $2" "$3}' /proc/$PID/status)"
echo "-----------------------------------------------------------------------------"
measure "idle (30s)"            30 idle
measure "light load ~5 exec/s"  20 load_light
measure "saturating exec loop"  15 load_busy
echo "-----------------------------------------------------------------------------"
echo "final RSS=$(awk '/VmRSS/{print $2" "$3}' /proc/$PID/status)  total execs=$(wc -l < "$TELE")  alerts=$(wc -l < /var/log/wisp/alerts.jsonl)"
kill $PID 2>/dev/null; wait $PID 2>/dev/null

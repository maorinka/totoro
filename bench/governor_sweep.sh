#!/usr/bin/env bash
# Prove the shipped DEFAULT config (governor on, budget-first, cpu_budget=0.05,
# telemetry on) holds < 0.05% of one core at EVERY exec rate. For each rate:
# start wispd, drive an exact-rate exec load, let the governor converge, then
# measure steady-state CPU from /proc/<pid>/schedstat.
set -u
WISPD=${WISPD:-/home/user/wisp-edr/agent/wispd}
RATEGEN=${RATEGEN:-/tmp/rategen}
BUDGET=0.05

cat > /tmp/sweep.conf <<EOF
rules = /etc/wisp/rules.conf
catalog = /etc/wisp/catalog.conf
fim = /tmp/none.conf
log_dir = /var/log/wisp
mode = monitor
telemetry = 1
coalesce_ms = 500
housekeeping = 60
cpu_budget = 0.05
budget_mode = budget-first
EOF

printf "%-10s %-12s %-8s %s\n" "rate/s" "cpu%" "verdict" "governor"
printf -- "---------------------------------------------------------\n"
worst=0
for rate in 10 50 100 200 300 500 1000 2000 5000 10000; do
	for p in $(pgrep -x wispd); do kill "$p" 2>/dev/null; done
	sleep 0.3
	: > /tmp/sweep.log
	"$WISPD" -c /tmp/sweep.conf 2>/tmp/sweep.log &
	P=$!
	sleep 0.6
	# drive load long enough to converge + measure
	dur=$(( rate >= 1000 ? 30 : 22 ))
	"$RATEGEN" "$rate" "$dur" >/dev/null 2>&1 &
	RG=$!
	# converge: wait until governor settles (or a fixed warmup)
	sleep $(( rate >= 1000 ? 12 : 8 ))
	r0=$(awk '{print $1}' /proc/$P/schedstat)
	t0=$(date +%s.%N)
	sleep 9
	r1=$(awk '{print $1}' /proc/$P/schedstat)
	t1=$(date +%s.%N)
	kill "$RG" "$P" 2>/dev/null
	wait 2>/dev/null
	read pct verdict < <(python3 -c "
w=$t1-$t0; p=100*($r1-$r0)/(w*1e9)
print(f'{p:.4f}', 'PASS' if p < $BUDGET else 'OVER')")
	gov=$(grep -oE "sampling 1-in-[0-9]+|telemetry suppressed" /tmp/sweep.log | tail -1)
	printf "%-10s %-12s %-8s %s\n" "$rate" "$pct" "$verdict" "${gov:-passive}"
	worst=$(python3 -c "print(max($worst, $pct))")
done
printf -- "---------------------------------------------------------\n"
python3 -c "print(f'worst case across all rates: {$worst:.4f}%  ->  {\"ALL UNDER 0.05%\" if $worst < 0.05 else \"SOME OVER\"}')"

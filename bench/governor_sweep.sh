#!/usr/bin/env bash
# Prove the shipped DEFAULT config (governor on, budget-first, cpu_budget=0.05,
# telemetry on) holds < 0.05% of one core at EVERY exec rate. For each rate:
# start wispd, drive an exact-rate exec load, let the governor converge, then
# measure steady-state CPU from /proc/<pid>/schedstat (userspace sensor time
# only; the in-kernel eBPF program's cost is not included).
#
# Runs as root on a test machine. Everything it writes (config, logs, the
# load generator) is in a private mktemp directory; it starts and stops only
# its own wispd, never one that is already running.
set -u
REPO=$(cd "$(dirname "$0")/.." && pwd)
WISPD=${WISPD:-$REPO/agent/wispd}
BUDGET=0.05
W=$(mktemp -d "${TMPDIR:-/tmp}/wisp-sweep.XXXXXXXX") || exit 1
P=""; RG=""
cleanup() { [[ -n "$RG" ]] && kill "$RG" 2>/dev/null; [[ -n "$P" ]] && kill "$P" 2>/dev/null; wait 2>/dev/null; rm -rf "$W"; }
trap cleanup EXIT
RATEGEN=${RATEGEN:-$W/rategen}
[[ -x "$RATEGEN" ]] || cc -O2 -o "$RATEGEN" "$REPO/bench/rategen.c" || { echo "cannot build rategen" >&2; exit 1; }

cat > "$W/sweep.conf" <<CONF
rules = $REPO/config/rules.conf
catalog = $REPO/config/catalog.conf
fim = $W/none.conf
netpolicy = $W/none.conf
log_dir = $W/log
state_dir = $W/state
mode = monitor
telemetry = 1
coalesce_ms = 500
housekeeping = 60
cpu_budget = 0.05
budget_mode = budget-first
CONF
: > "$W/none.conf"; mkdir -p "$W/log" "$W/state"

printf "%-10s %-10s %-12s %-8s %s\n" "rate/s" "achieved" "cpu%" "verdict" "governor"
printf -- "-----------------------------------------------------------------\n"
worst=0
for rate in 10 50 100 200 300 500 1000 2000 5000 10000; do
	: > "$W/sweep.log"
	"$WISPD" -c "$W/sweep.conf" 2>"$W/sweep.log" &
	P=$!
	sleep 0.6
	# drive load long enough to converge + measure
	dur=$(( rate >= 1000 ? 22 : 18 ))
	"$RATEGEN" "$rate" "$dur" >"$W/rg.out" 2>&1 &
	RG=$!
	# converge: a fixed warmup for the governor to settle
	sleep $(( rate >= 1000 ? 12 : 8 ))
	r0=$(awk '{print $1}' "/proc/$P/schedstat")
	t0=$(date +%s.%N)
	sleep 9
	r1=$(awk '{print $1}' "/proc/$P/schedstat")
	t1=$(date +%s.%N)
	wait "$RG" 2>/dev/null; RG=""
	kill "$P" 2>/dev/null; wait "$P" 2>/dev/null; P=""
	achieved=$(sed -n 's/.*achieved \([0-9.]*\)\/s.*/\1/p' "$W/rg.out")
	read -r pct verdict < <(python3 -c "
w=$t1-$t0; p=100*($r1-$r0)/(w*1e9)
print(f'{p:.4f}', 'PASS' if p < $BUDGET else 'OVER')")
	gov=$(grep -oE "sampling 1-in-[0-9]+|telemetry suppressed" "$W/sweep.log" | tail -1)
	printf "%-10s %-10s %-12s %-8s %s\n" "$rate" "${achieved:-?}" "$pct" "$verdict" "${gov:-passive}"
	worst=$(python3 -c "print(max($worst, $pct))")
done
printf -- "-----------------------------------------------------------------\n"
python3 -c "print(f'worst case across all rates: {$worst:.4f}%  ->  {\"ALL UNDER 0.05%\" if $worst < 0.05 else \"SOME OVER\"}')"
echo "(check 'achieved': a rate the host could not generate was not tested)"

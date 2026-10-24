#!/usr/bin/env bash
# One-command verification of every Wisp capability that is testable in a
# Linux environment. Prints PASS/FAIL per capability. The items this sandbox
# cannot run (macOS/Windows runtime, hardware TPM, cross-process injection,
# reaching io.security) are reported as SKIP with the reason.
#
#   sudo bash bench/verify.sh [--force]
#
# Run it on a disposable test VM or CI runner, never on a production host.
# It needs root and a BTF kernel because it loads the sensor's eBPF program,
# and it runs sensors in enforce mode. It is built so that it does not damage
# the host it runs on:
#   - everything it writes (configs, logs, state, PKI, helpers such as the
#     load generator) is in a private `mktemp -d` directory, removed at exit
#     (KEEP=1 keeps it for debugging); it never writes /etc/wisp, /var/log/wisp
#     or /var/lib/wisp;
#   - it stops only processes it started itself, never another wispd or
#     wisp-console;
#   - its consoles listen on 127.0.0.1 on non-default ports (WISP_VERIFY_PORT_BASE,
#     default 18000: ingest +750, http +80, mock Claude API +443);
#   - INCIDENT RULE: a quarantine rule may only target private copies of
#     binaries inside the scratch directory (`exe^=<scratch>/...`); every
#     rules file is checked before a sensor starts, and the run aborts on any
#     other quarantine rule. (An earlier test quarantined /usr/bin/bash
#     because its rule matched a command line.)
#   - it refuses to run where a wispd or wisp-console is running or installed,
#     unless --force is given (it then still touches only its own processes,
#     but shares the CPU and the eBPF subsystem with them).
# It changes one global setting while it runs: kernel.bpf_stats_enabled (to
# measure the eBPF program's in-kernel cost); the old value is restored.
set -u
FORCE=0
for a in "$@"; do
  case "$a" in
  --force) FORCE=1 ;;
  -h|--help) sed -n '2,/^set -u/{/^set -u/d;s/^# \{0,1\}//;p}' "$0"; exit 0 ;;
  *) echo "verify.sh: unknown option $a" >&2; exit 2 ;;
  esac
done
[[ $EUID -eq 0 ]] || { echo "verify.sh: run as root (it loads the sensor's eBPF program)" >&2; exit 2; }

if [[ $FORCE -ne 1 ]]; then
  found=""
  pgrep -x wispd >/dev/null && found+=" a running wispd;"
  pgrep -x wisp-console >/dev/null && found+=" a running wisp-console;"
  for f in /etc/systemd/system/wispd.service /etc/systemd/system/wisp-console.service /etc/wisp/wisp.conf; do
    [[ -e $f ]] && found+=" $f;"
  done
  if [[ -n $found ]]; then
    echo "verify.sh: this looks like a host with Wisp installed or running:$found" >&2
    echo "verify.sh: run it on a disposable test machine, or pass --force (it only touches its own" >&2
    echo "           processes and files, but competes with the installed sensor for CPU)." >&2
    exit 2
  fi
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
AG="$ROOT/agent/wispd"; CON="$ROOT/console/wisp-console"
W=$(mktemp -d "${TMPDIR:-/tmp}/wisp-verify.XXXXXXXX") || exit 2
PKI=$W/pki; RG=$W/rategen; LOG=$W/log; NONE=$W/none
mkdir -p "$LOG"; : > "$NONE"
BASE=${WISP_VERIFY_PORT_BASE:-18000}
P_INGEST=$((BASE + 750)); P_HTTP=$((BASE + 80)); P_MOCK=$((BASE + 443))
H=$(hostname)

pass=0; fail=0; skip=0
ok(){ printf "  \033[32mPASS\033[0m  %s\n" "$1"; pass=$((pass+1)); }
no(){ printf "  \033[31mFAIL\033[0m  %s\n" "$1"; fail=$((fail+1)); }
sk(){ printf "  \033[33mSKIP\033[0m  %s — %s\n" "$1" "$2"; skip=$((skip+1)); }
info(){ printf "  INFO  %s\n" "$1"; }

# ---- our own processes only -------------------------------------------------
OURS=()
stop(){ local p; for p in "$@"; do [[ -n $p ]] && kill "$p" 2>/dev/null; done
        for p in "$@"; do [[ -n $p ]] && wait "$p" 2>/dev/null; done; return 0; }
stop_all(){ stop "${OURS[@]}"; OURS=(); sleep 0.3; }

# Incident rule: refuse any quarantine rule that is not confined to $W.
guard_rules(){
  local rules
  rules=$(sed -n 's/^[[:space:]]*rules[[:space:]]*=[[:space:]]*//p' "$1" | tail -1)
  [[ -f $rules ]] || return 0
  if awk -v w="exe^=$W/" '$1 !~ /^#/ && $3 == "quarantine" && index($0, w) == 0 { bad = 1 } END { exit !bad }' "$rules"; then
    echo "verify.sh: ABORT: $rules has a quarantine rule not confined to exe^=$W/ (incident rule)" >&2
    exit 3
  fi
}
# start_agent CONF [STDERR_FILE]: sets AGPID
start_agent(){ guard_rules "$1"; "$AG" -c "$1" 2>"${2:-/dev/null}" & AGPID=$!; OURS+=("$AGPID"); }

STATS_OLD=$(cat /proc/sys/kernel/bpf_stats_enabled 2>/dev/null || echo "")
VSX_CREATED=0
cleanup(){
  stop_all
  [[ -n $STATS_OLD ]] && echo "$STATS_OLD" > /proc/sys/kernel/bpf_stats_enabled 2>/dev/null
  [[ $VSX_CREATED = 1 ]] && rm -rf /root/.vscode
  if [[ ${KEEP:-0} = 1 ]]; then echo "scratch kept: $W"; else rm -rf "$W"; fi
}
trap cleanup EXIT
trap 'exit 130' INT TERM

echo "== build =="
( cd "$ROOT/agent" && make >/dev/null 2>&1 ) && ok "agent builds (eBPF sensor)" || no "agent build"
( cd "$ROOT/agent" && SENSOR=connector make >/dev/null 2>&1 ) && ok "connector fallback builds" || no "connector build"
make -C "$ROOT/console" >/dev/null 2>&1 && ok "console builds" || no "console build"
( cd "$ROOT/agent" && make >/dev/null 2>&1 )  # back to bpf
strings "$AG" | grep -q "exec tracepoint attached" && ok "test binary is the eBPF sensor (not the connector fallback)" || no "test binary is not the eBPF sensor"
cc -O2 -o "$RG" "$ROOT/bench/rategen.c" 2>/dev/null || no "load generator build"
bash "$ROOT/bench/mkpki.sh" "$PKI" >/dev/null 2>&1 || no "test PKI"

echo "== cross-platform backends (compile-check) =="
( cd "$ROOT/agent" && make check-platform 2>/dev/null | grep -q "Windows SDK" ) && ok "Windows ETW backend compiles vs Windows SDK headers" || no "windows compile"
( cd "$ROOT/agent" && make check-platform 2>/dev/null | grep -q "documented ES API" ) && ok "macOS ES backend compiles vs documented API" || no "macos compile"

echo "== detection + enforce =="
VR=$W/vr; mkdir -p "$VR/.ssh"; echo k > "$VR/.ssh/id_rsa"
cat > "$W/vr.rules" <<'EOF'
K critical kill - "k" comm=sleep "cmd*=818181"
CRED-001 high alert T1552.001 "ssh" cmd*=/.ssh/id_ !comm=ssh,git
EOF
echo "deny any:9191" > "$W/vr.net"
printf 'rules=%s/vr.rules\ncatalog=%s/config/catalog.conf\nfim=%s\nnetpolicy=%s/vr.net\nlog_dir=%s\nstate_dir=%s/st\nmode=enforce\ntelemetry=0\n' \
  "$W" "$ROOT" "$NONE" "$W" "$LOG" "$LOG" > "$W/vr.conf"
start_agent "$W/vr.conf"; sleep 0.8
cat "$VR/.ssh/id_rsa" >/dev/null
sleep 818181 & V=$!; sleep 0.8
kill -0 $V 2>/dev/null && { no "enforce kill"; kill $V; } || ok "enforce kills policy-violating process"
grep -q CRED-001 "$LOG/alerts.jsonl" && ok "credential-access detection fires" || no "cred detection"
python3 -c "import socket
s=socket.socket();s.settimeout(0.3)
try: s.connect(('127.0.0.1',9191))
except Exception: pass" 2>/dev/null
sleep 1.5
grep -q NET-POLICY "$LOG/alerts.jsonl" && ok "network data-flow policy fires on denied egress" || no "net policy"
stop_all

echo "== quarantine (a private copy in the scratch directory only) =="
# The target is a copy of sleep under $W, matched by its exact path prefix and
# name, never by command line. Its directory is world-writable+sticky so the
# sensor does not treat it as a root-only system directory (which it refuses).
VQ=$W/q; mkdir -p "$VQ/bin"; chmod 1777 "$VQ/bin"
cp /bin/sleep "$VQ/bin/wispqtarget"
qsum=$(sha256sum < "$VQ/bin/wispqtarget")
printf 'Q high quarantine - "verify quarantine" exe^=%s/bin/ comm=wispqtarget\n' "$VQ" > "$VQ/rules"
printf 'rules=%s/rules\ncatalog=%s\nfim=%s\nnetpolicy=%s\nlog_dir=%s\nstate_dir=%s/st\nanomaly_learn=-1\nmode=enforce\ntelemetry=0\n' \
  "$VQ" "$NONE" "$NONE" "$NONE" "$VQ" "$VQ" > "$VQ/conf"
start_agent "$VQ/conf"; sleep 0.8
"$VQ/bin/wispqtarget" 818383 & QP=$!; sleep 1.5
qalive=0; kill -0 $QP 2>/dev/null && { qalive=1; kill $QP; }
wait $QP 2>/dev/null
stop_all
qcopy=$(find "$VQ/st/quarantine" -type f -name 'wispqtarget.*' 2>/dev/null | head -1)
[[ $qalive = 0 && ! -e "$VQ/bin/wispqtarget" && -n $qcopy ]] && [[ "$(sha256sum < "$qcopy")" = "$qsum" ]] \
  && [[ ! -x $qcopy ]] && grep -q '"quarantined"' "$VQ/alerts.jsonl" \
  && ok "quarantine: process killed, binary moved into the 0700 quarantine dir (not executable), alert says so" \
  || no "quarantine (alive=$qalive copy=${qcopy:-none}: $(grep -o '"quarantine_error":"[^"]*"' "$VQ/alerts.jsonl" 2>/dev/null | head -1))"

echo "== CPU budget (governor holds <0.05% under load) =="
# schedstat measures the sensor's userspace task. The exec tracepoint program
# runs in the context of each exec'ing process, so its cost is measured
# separately (kernel.bpf_stats_enabled + bpftool) and reported as INFO.
VU=$W/cpu; mkdir -p "$VU"
printf 'rules=%s/config/rules.conf\ncatalog=%s/config/catalog.conf\nfim=%s\nnetpolicy=%s\nlog_dir=%s\nstate_dir=%s/st\ntelemetry=1\ncoalesce_ms=500\nhousekeeping=60\ncpu_budget=0.05\nbudget_mode=budget-first\n' \
  "$ROOT" "$ROOT" "$NONE" "$NONE" "$VU" "$VU" > "$VU/conf"
BPFTOOL=$(command -v bpftool 2>/dev/null || ls /usr/lib/linux-tools-*/bpftool 2>/dev/null | head -1)
[[ -n $STATS_OLD ]] && echo 1 > /proc/sys/kernel/bpf_stats_enabled 2>/dev/null
start_agent "$VU/conf"; P=$AGPID; sleep 0.6
bpf_ns(){ [[ -n $BPFTOOL ]] || return 0
  "$BPFTOOL" -j prog show 2>/dev/null | python3 -c 'import sys,json
p=int(sys.argv[1])
try: progs=json.load(sys.stdin)
except Exception: sys.exit(0)
mine=[x for x in progs if any(q.get("pid")==p for q in x.get("pids",[]))]
if mine and all("run_time_ns" in x for x in mine): print(sum(x["run_time_ns"] for x in mine))' "$P"; }
"$RG" 2000 28 > "$W/rg.out" 2>&1 & RGP=$!
sleep 16; r0=$(awk '{print $1}' /proc/$P/schedstat); k0=$(bpf_ns); t0=$(date +%s.%N); sleep 10
r1=$(awk '{print $1}' /proc/$P/schedstat); k1=$(bpf_ns); t1=$(date +%s.%N)
wait $RGP
ach=$(sed -n 's/.*achieved \([0-9.]*\)\/s.*/\1/p' "$W/rg.out"); ach=${ach:-0}
pct=$(python3 -c "print(f'{100*($r1-$r0)/(($t1-$t0)*1e9):.4f}')")
python3 -c "import sys;sys.exit(0 if $pct<0.05 else 1)" && ok "sensor userspace CPU $pct% < 0.05% at ${ach} exec/s (governor)" || no "userspace cpu over at ${ach}/s: $pct%"
python3 -c "import sys;sys.exit(0 if $ach>=1900 else 1)" && ok "load generator reached ${ach} exec/s (target 2000)" \
  || no "load generator reached only ${ach} exec/s of 2000: the CPU check above ran at that rate"
if [[ -n $k0 && -n $k1 ]]; then
  info "in-kernel eBPF cost over the same window: $(python3 -c "print(f'{100*($k1-$k0)/(($t1-$t0)*1e9):.4f}')")% of one core (charged to the exec'ing processes; not part of the userspace budget above)"
else
  info "in-kernel eBPF cost not measured (needs bpftool with pid support and kernel.bpf_stats_enabled)"
fi
r0=$(awk '{print $1}' /proc/$P/schedstat); sleep 10; r1=$(awk '{print $1}' /proc/$P/schedstat)
ipct=$(python3 -c "print(f'{100*($r1-$r0)/10e9:.4f}')")
python3 -c "import sys;sys.exit(0 if $ipct<0.01 else 1)" && ok "CPU $ipct% at idle" || no "idle cpu high: $ipct%"
stop_all

echo "== runtime vulnerability mitigation (cross-process, live, no restart) =="
# Exercises the REAL agent code (agent/patch.c respond_patch/respond_unpatch)
# over a process boundary: the parent ptrace-attaches a separate live child,
# overwrites vulnerable() with the safe stub, detaches; the child keeps running
# but now returns the mitigated value; then the patch is lifted and it reverts.
# The target is an own child (an authorised ptrace relation, like a debugger),
# so it does not require -- and does not attempt -- any RCE-guard bypass.
CP=$W/crosspatch
if cc -O0 -no-pie -fno-pic -o "$CP" "$ROOT/bench/crosspatch_demo.c" "$ROOT/agent/patch.c" 2>/dev/null; then
  out="$("$CP" 2>/dev/null)"
  before=$(printf '%s\n' "$out" | sed -n '/applying live/q;p' | grep -c EXPLOITABLE)
  mitig=$(printf '%s\n' "$out" | awk '/applying live/{f=1} /lifting patch/{f=0} f' | grep -c mitigated)
  after=$(printf '%s\n' "$out" | awk '/lifting patch/{f=1} f' | grep -c EXPLOITABLE)
  [ "$before" -gt 0 ] && [ "$mitig" -gt 0 ] && [ "$after" -gt 0 ] \
    && ok "live-patched a separate running process: EXPLOITABLE -> mitigated -> reverted (no restart)" \
    || no "cross-process live patch (before=$before mitig=$mitig after=$after)"
else
  no "cross-process live patch build"
fi

echo "== API rate limiting + inline correction =="
# limit any:9192 3/s: one process makes 10 connects -> 7 over the limit; a
# second process has its own bucket. Enforce mode kills the offender.
VL=$W/rl; mkdir -p "$VL"
printf 'limit any:9192 3/s\n' > "$VL/net"
conn10='import socket,time
for i in range(10):
    s=socket.socket();s.settimeout(0.2)
    try: s.connect(("127.0.0.1",9192))
    except Exception: pass
    s.close()
time.sleep(2)'
printf 'rules=%s\ncatalog=%s\nfim=%s\nnetpolicy=%s/net\nlog_dir=%s\nstate_dir=%s/st\nanomaly_learn=-1\nmode=monitor\ntelemetry=1\n' \
  "$NONE" "$NONE" "$NONE" "$VL" "$VL" "$VL" > "$VL/conf"
start_agent "$VL/conf"; sleep 0.8
python3 -c "$conn10"; sleep 1.2; stop_all
n=$(grep -c NET-RATE "$VL/alerts.jsonl"); f=$(grep -c '"type":"flow"' "$VL/telemetry.jsonl")
[ "$n" = 7 ] && ok "connection rate limit: 7/10 over a 3/s limit flagged; $f flows recorded" || no "rate limit flagged $n (want 7)"
sed -i 's/mode=monitor/mode=enforce/' "$VL/conf"; : > "$VL/alerts.jsonl"
start_agent "$VL/conf"; sleep 0.8
python3 -c "$conn10" & PY=$!; sleep 1.2
kill -0 $PY 2>/dev/null && { no "rate-limit enforce did not stop the process"; kill $PY; } || ok "enforce: over-limit process corrected inline (stopped)"
stop_all

echo "== behavioral anomalies (first-seen program) =="
VA=$W/an; mkdir -p "$VA"; cp /bin/true "$VA/novel1"; cp /bin/true "$VA/novel2"
printf 'rules=%s\ncatalog=%s\nfim=%s\nnetpolicy=%s\nlog_dir=%s\nstate_dir=%s/st\nanomaly_learn=2\ntelemetry=0\n' \
  "$NONE" "$NONE" "$NONE" "$NONE" "$VA" "$VA" > "$VA/conf"
start_agent "$VA/conf"; sleep 0.8; /bin/true; sleep 2.5; /bin/true; "$VA/novel1"; "$VA/novel1"; sleep 1; stop_all
n1=$(grep ANOM-001 "$VA/alerts.jsonl" | grep -c '"exe":"'"$VA"'/novel1"')
start_agent "$VA/conf"; sleep 0.8; "$VA/novel1"; "$VA/novel2"; sleep 1; stop_all
# Count per program: other tools the harness itself runs (pgrep, ...) may be
# genuinely new to this host and are correctly flagged too.
n1b=$(grep ANOM-001 "$VA/alerts.jsonl" | grep -c '"exe":"'"$VA"'/novel1"')
n2=$(grep ANOM-001 "$VA/alerts.jsonl" | grep -c '"exe":"'"$VA"'/novel2"')
nt=$(grep ANOM-001 "$VA/alerts.jsonl" | grep -c '"exe":"/bin/true"')
[ "$n1" = 1 ] && [ "$n1b" = 1 ] && [ "$n2" = 1 ] && [ "$nt" = 0 ] \
  && ok "never-seen program flagged exactly once; learned programs silent; baseline persists across restart" \
  || no "anomaly novel1=$n1/$n1b novel2=$n2 true=$nt"
# a baseline file from a different host (e.g. baked into an image) is rejected
printf 'OTHERHOST' | dd of="$VA/st/seen.bloom" bs=1 seek=16 conv=notrunc 2>/dev/null
start_agent "$VA/conf" "$VA/relearn.log"; sleep 0.8; stop_all
grep -q "relearning" "$VA/relearn.log" && ok "foreign (image-baked) anomaly baseline rejected; host relearns" || no "foreign baseline imported"

echo "== IDE extension governance (catalog vsx allow-list) =="
# The sensor watches real home directories, so this needs /root/.vscode. It
# runs only when that does not exist (created here, removed afterwards);
# an existing one belongs to someone and is never modified.
if [[ -e /root/.vscode ]]; then
  sk "IDE extension governance" "/root/.vscode exists on this host; not modifying it"
else
  VX=$W/vsx; mkdir -p "$VX"
  XD=/root/.vscode/extensions; VSX_CREATED=1
  mkdir -p "$XD/ms-python.python-2024.8.0" "$XD/zz-verify.miner-1.0.0"
  printf 'rules=%s\ncatalog=%s/config/catalog.conf\nfim=%s\nnetpolicy=%s\nlog_dir=%s\nstate_dir=%s/st\nanomaly_learn=-1\ntelemetry=0\n' \
    "$NONE" "$ROOT" "$NONE" "$NONE" "$VX" "$VX" > "$VX/conf"
  start_agent "$VX/conf"; sleep 1.2; mkdir "$XD/zz-verify.stealer-0.0.1"; sleep 1; stop_all
  nv=$(grep -c 'CAT-VSX' "$VX/alerts.jsonl"); na=$(grep -c 'ms-python' "$VX/alerts.jsonl")
  grep -q 'zz-verify.miner' "$VX/alerts.jsonl" && grep -q 'zz-verify.stealer' "$VX/alerts.jsonl" && [ "$na" = 0 ] \
    && ok "unsanctioned IDE extensions flagged (existing + live install); allow-listed one silent" || no "vsx governance ($nv alerts, allowed flagged: $na)"
  rm -rf /root/.vscode; VSX_CREATED=0
fi

echo "== retrospective forensics (agent) =="
VF=$W/fx; mkdir -p "$VF"
printf 'CRED-001 high alert T1552.001 "ssh" cmd*=/.ssh/id_ !comm=ssh,git\n' > "$VF/rules"
printf 'rules=%s/rules\ncatalog=%s\nfim=%s\nnetpolicy=%s\nlog_dir=%s\nstate_dir=%s/st\nanomaly_learn=-1\ntelemetry=1\n' \
  "$VF" "$NONE" "$NONE" "$NONE" "$VF" "$VF" > "$VF/conf"
start_agent "$VF/conf"; sleep 0.8
cat > "$VF/parent.sh" <<EOF
#!/bin/sh
sleep 0.3
sh -c 'cat "$VR/.ssh/id_rsa" >/dev/null; python3 -c "
import socket
s=socket.socket(); s.settimeout(0.2)
try: s.connect((\"127.0.0.1\",9444))
except Exception: pass"'
EOF
chmod +x "$VF/parent.sh"; "$VF/parent.sh" & R=$!; wait $R; /bin/echo unrelated >/dev/null; sleep 1.2; stop_all
tree="$("$AG" -c "$VF/conf" --search tree=$R 2>/dev/null)"
tt=$(printf '%s\n' "$tree" | grep -o '"type":"[a-z]*"' | sort | uniq -c | tr -s ' ' | tr '\n' ' ')
printf '%s\n' "$tree" | grep -q '"type":"flow"' && printf '%s\n' "$tree" | grep -q CRED-001 \
  && ! printf '%s\n' "$tree" | grep -q '"comm":"echo"' \
  && ok "--search tree=PID reconstructs a process's descendants, alerts and flows ($tt)" || no "forensics tree: $tt"

echo "== fleet console: mTLS, forensics journal, staged rollout, lifecycle, posture =="
VC=$W/con; mkdir -p "$VC"
CONPID=""
# -decommission-after must be 0 or >= -stale-after (the console exits 2 otherwise).
startcon(){ "$CON" -listen 127.0.0.1:$P_INGEST -http 127.0.0.1:$P_HTTP -cert "$PKI/console.crt" -key "$PKI/console.key" \
  -client-ca "$PKI/ca.crt" -dev -state-dir "$VC" -events "$VC/events.jsonl" \
  -stale-after 2s -decommission-after "$1" >>"$VC/console.log" 2>&1 & CONPID=$!; OURS+=("$CONPID"); sleep 0.8; }
api(){ curl -s "127.0.0.1:$P_HTTP$1"; }
startcon 30s
# mTLS negative paths: no client certificate, and one from an untrusted CA.
rogue(){ python3 -I - "$P_INGEST" "$PKI/ca.crt" "$1" "$2" "$3" <<'PY'
import json, socket, ssl, sys
port, ca, cert, key, name = sys.argv[1:6]
ctx = ssl.create_default_context(cafile=ca)
ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT
if cert:
    ctx.load_cert_chain(cert, key)
try:
    s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", int(port)), timeout=3), server_hostname="localhost")
    for o in ({"type": "hello", "host": name, "group": "rogue", "version": "0", "host_id": "id-" + name,
               "trust": "tpm", "ephemeral": False},
              {"type": "heartbeat", "host": name, "group": "rogue", "execs": 1, "cpu_pct": 0, "rss_kb": 1, "mode": "monitor"}):
        s.sendall((json.dumps(o) + "\n").encode())
    s.settimeout(1.5)
    print("open" if s.recv(1) else "closed")
except Exception as e:
    print("refused (%s)" % type(e).__name__)
PY
}
r1=$(rogue "" "" verify-nocert-host); r2=$(rogue "$PKI/rogue.crt" "$PKI/rogue.key" verify-rogue-host); sleep 1
hosts=$(api /api/hosts)
[[ -n $hosts ]] && ! grep -q 'verify-nocert-host\|verify-rogue-host' <<<"$hosts" \
  && ok "ingest refuses a sensor without a client certificate ($r1) and one from a foreign CA ($r2)" \
  || no "mTLS negative path: nocert=$r1 rogue=$r2; hosts: $(grep -o 'verify-[a-z]*-host' <<<"$hosts" | tr '\n' ' ')"
printf 'rules=%s/rules\ncatalog=%s\nfim=%s\nnetpolicy=%s\nlog_dir=%s\nstate_dir=%s/st\nanomaly_learn=-1\ntelemetry=0\nhousekeeping=5\nconsole=127.0.0.1:%s\ncert=%s/agent.crt\nkey=%s/agent.key\nca=%s/ca.crt\ngroup=ci\nephemeral=1\n' \
  "$VF" "$NONE" "$NONE" "$NONE" "$VC" "$VC" "$P_INGEST" "$PKI" "$PKI" "$PKI" > "$VC/agent.conf"
start_agent "$VC/agent.conf"; EA=$AGPID
WISP_CONSOLE=127.0.0.1:$P_INGEST WISP_PKI=$PKI python3 -I "$ROOT/bench/fleetsim.py" 20 prod "$VC/ctl" 8 prod-05 2>/dev/null & SIM=$!
OURS+=("$SIM")
sleep 2; cat "$VR/.ssh/id_rsa" >/dev/null; sleep 1.5
c1=$(api '/api/events?rule=CRED-001&host='"$H" | python3 -c 'import sys,json;print(len(json.load(sys.stdin)))')
[ "${c1:-0}" -ge 1 ] && ok "console /api/events: real agent's alert searchable by field" || no "console events ($c1)"
api /api/hosts | python3 -c '
import sys,json,os
h=sys.argv[1]; mid=open("/etc/machine-id").read().strip() if os.path.exists("/etc/machine-id") else ""
x=next((x for x in json.load(sys.stdin) if x["name"]==h),None)
want={"dmi","machine-id","tpm"} if mid else {"dmi","machine-id","tpm","generated"}
sys.exit(0 if x and x.get("host_id") and x.get("trust") in want else 1)' "$H" \
  && ok "identity: the real sensor reports a host_id and its trust tier ($(api /api/hosts | python3 -c 'import sys,json;h=sys.argv[1];print(next((x.get("trust") for x in json.load(sys.stdin) if x["name"]==h),"?"))' "$H"))" \
  || no "identity: host_id/trust missing for $H"
for p in 10 50 100; do curl -s -X POST "127.0.0.1:$P_HTTP/api/policy/rollout?action=enforce&group=prod&percent=$p" >/dev/null; done
for _ in $(seq 40); do [ "$(ls "$VC"/ctl/*.ctl 2>/dev/null | wc -l)" -ge 20 ] && break; sleep 0.25; done  # simulated hosts write one file each
rodiag=$(api /api/policy/rollout | python3 -c '
import sys,json,glob
rs=sorted(json.load(sys.stdin), key=lambda r: r["ts"])  # API returns newest first
c=[set(r["cohort"]) for r in rs]
got={f.split("/")[-1][:-4] for f in glob.glob(sys.argv[1]+"/ctl/*.ctl")}
okk = len(c)==3 and c[0]<c[1]<c[2] and len(c[2])==20 and got==c[2]
print("ok" if okk else "stages=%s nested=%s files=%d missing=%s extra=%s" % ([(r["percent"],len(r["cohort"]),len(r["delivered"])) for r in rs], len(c)==3 and c[0]<c[1]<c[2], len(got), sorted(c[-1]-got)[:5] if c else "-", sorted(got-c[-1])[:5] if c else "-"))' "$VC")
[ "$rodiag" = ok ] && ok "staged rollout 10%→50%→100%: nested cohorts, all 20 hosts received the push, other groups untouched" || no "staged rollout: $rodiag"
sleep 1.5
api '/api/hosts?state=stale' | grep -q '"prod-05"' && ok "silent host transitions to stale" || no "stale state"
api /api/posture | python3 -c 'import sys,json;p=json.load(sys.stdin);sys.exit(0 if len(p["hosts"])>=20 and p["hosts"][0]["findings"] else 1)' \
  && ok "attack-surface posture: per-host score + findings, fleet roll-up" || no "posture"
# GET never mutates: a GET carrying action= just returns the history, and no
# 4th rollout may appear (mutation is POST only).
nro=$(api "/api/policy/rollout?action=enforce&group=prod&percent=100" | python3 -c 'import sys,json;print(len(json.load(sys.stdin)))')
[ "$nro" = 3 ] && ok "rollout is not triggerable by GET (history unchanged at 3 stages); mutation is POST only" || no "GET with action= changed rollout history ($nro)"
kill $EA; wait $EA 2>/dev/null; sleep 1.2
api '/api/hosts?state=decommissioned' | grep -q '"ephemeral-exit"' && ! api /api/hosts | grep -q "\"$H\"" \
  && ok "ephemeral sensor says goodbye on exit and is decommissioned at once" || no "ephemeral decommission"
# the same host comes back as a PERSISTENT sensor: re-provisioned on hello, and a
# normal stop must leave it to go stale, not retire it
sed 's/^ephemeral=1$/ephemeral=0/' "$VC/agent.conf" > "$VC/agent-persist.conf"
start_agent "$VC/agent-persist.conf"; PA=$AGPID; sleep 1.5
api /api/hosts | grep -q "\"$H\"" && kill $PA && wait $PA 2>/dev/null; sleep 0.8
! api '/api/hosts?state=decommissioned' | grep -q "\"name\":\"$H\"" && sleep 2 && api '/api/hosts?state=stale' | grep -q "\"$H\"" \
  && ok "persistent host re-provisioned on return; a normal stop goes stale, is not decommissioned" || no "persistent host lifecycle"
# console disappears while the agent is connected: shutdown must not crash
start_agent "$VC/agent-persist.conf"; PA=$AGPID; sleep 1.5
wait $SIM 2>/dev/null; kill -9 "$CONPID"; wait "$CONPID" 2>/dev/null; sleep 0.5
kill $PA; wait $PA; rc=$?
[ "$rc" = 0 ] && ok "agent exits cleanly (rc=0) when the console vanished mid-session" || no "agent exit rc=$rc with dead console (139 = segfault in goodbye)"
sleep 0.4
startcon 2s; sleep 1
n=$(api '/api/events?rule=CRED-001' | python3 -c 'import sys,json;print(len(json.load(sys.stdin)))')
[ "${n:-0}" -ge 1 ] && grep -q replayed "$VC/console.log" && ok "forensics journal survives console restart (replayed, still searchable)" || no "journal replay ($n)"
stop_all

echo "== analysis + AI: incidents, suggestions, we suggest / you approve / we solve =="
# The AI assistant runs against bench/mock_claude_api.py (a local stand-in for
# the Claude Messages API that checks every request), so no key or network.
VA=$W/ai; mkdir -p "$VA"
APIKEY="wisp-verify-apikey-$$-sentinel"
SECRET="VerifySecret${RANDOM}x${RANDOM}Zq"   # planted in a command line: must not reach the API
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 -subj /CN=localhost \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" -keyout "$VA/mock.key" -out "$VA/mock.crt" >/dev/null 2>&1
python3 -I "$ROOT/bench/mock_claude_api.py" --port "$P_MOCK" --cert "$VA/mock.crt" --key "$VA/mock.key" --log "$VA/api.jsonl" >/dev/null 2>&1 & MOCK=$!
OURS+=("$MOCK")
NO_PROXY=localhost,127.0.0.1 ANTHROPIC_API_KEY=$APIKEY "$CON" -listen 127.0.0.1:$P_INGEST -http 127.0.0.1:$P_HTTP \
  -cert "$PKI/console.crt" -key "$PKI/console.key" -client-ca "$PKI/ca.crt" -dev -state-dir "$VA" \
  -analysis-interval 5s -ai-url "https://localhost:$P_MOCK" -ai-ca "$VA/mock.crt" >>"$VA/console.log" 2>&1 & CONPID=$!
OURS+=("$CONPID"); sleep 0.8
sed 's/^ephemeral=1$/ephemeral=0/; s/^group=ci$/group=verify/' "$VC/agent.conf" > "$VA/agent.conf"
start_agent "$VA/agent.conf"; PA=$AGPID
# The sensor drops console lines while it is still connecting (it never blocks
# the exec path; the alert stays in its local log), so wait for the session.
for _ in $(seq 40); do api /api/hosts | grep -q '"connected":true' && break; sleep 0.25; done
cat "$VR/.ssh/id_rsa" "--token=$SECRET" >/dev/null 2>&1
for _ in $(seq 20); do INC=$(api "/api/incidents?host=$H" | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d[0]["id"] if d and d[0]["reasons"] else "")'); [ -n "$INC" ] && break; sleep 0.25; done
[ -n "$INC" ] && ok "real agent's detection correlated into a scored incident ($INC)" || no "incident for $H"
job(){ j=$(curl -s -X POST -d "$2" "127.0.0.1:$P_HTTP/api/ai/$1" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("id",""))')
  for _ in $(seq 40); do r=$(api "/api/ai/jobs?id=$j"); echo "$r" | grep -q '"status":"\(done\|failed\)"' && break; sleep 0.5; done; echo "$r"; }
tr=$(job triage "{\"incident\":\"$INC\"}")
echo "$tr" | python3 -c 'import sys,json;j=json.load(sys.stdin);r=j["result"];sys.exit(0 if j["status"]=="done" and r["verdict"] and len(r["suggestions"])>=2 and r["dropped"] else 1)' \
  && ok "AI triage: verdict + in-scope recommendations became suggestions; out-of-scope one dropped" || no "AI triage: $tr"
SID=$(api /api/suggestions | python3 -c 'import sys,json;h=sys.argv[1];print(next((s["id"] for s in json.load(sys.stdin) if s["action"].get("type")=="push" and s["action"].get("host")==h),""))' "$H")
mode_of(){ api /api/hosts | python3 -c 'import sys,json;h=sys.argv[1];print(next((x["mode"] for x in json.load(sys.stdin) if x["name"]==h),""))' "$H"; }
for _ in $(seq 40); do [ -n "$(mode_of)" ] && break; sleep 0.25; done  # first heartbeat reports the mode
[ -n "$SID" ] && [ "$(mode_of)" = monitor ]; pre=$?
curl -s -X POST -d "{\"id\":\"$SID\",\"decision\":\"approve\",\"note\":\"verify\"}" "127.0.0.1:$P_HTTP/api/suggestions/decide" | grep -q '"status":"applied"'
for _ in $(seq 60); do [ "$(mode_of)" = enforce ] && break; sleep 0.25; done
[ "$(mode_of)" = enforce ] && [ $pre = 0 ] \
  && ok "approved suggestion carried out: the real sensor switched monitor → enforce and reports it" || no "suggestion approval did not reach the sensor ($SID)"
python3 -I - "$VA/api.jsonl" <<'PY' && ok "Claude API requests: structured output, fallback beta, key sent" || no "API request shape"
import json, sys
rs = [json.loads(l) for l in open(sys.argv[1])]
b = rs[0]["body"]
sys.exit(0 if rs and b["model"].startswith("claude-") and b["output_config"]["format"]["type"] == "json_schema"
         and b.get("fallbacks") == "default" and all(r["key_present"] for r in rs) and "<fleet_data>" in b["messages"][0]["content"] else 1)
PY
# Redaction: the secret is in the journal (so it was part of the incident's
# data) but in none of the API request bodies, which carry [REDACTED] instead.
# The API key appears in no log or journal.
grep -q "$SECRET" "$VA/events.jsonl" && ! grep -q "$SECRET" "$VA/api.jsonl" && grep -q 'REDACTED' "$VA/api.jsonl" \
  && ok "Claude API requests: a secret planted in a command line is redacted before sending" \
  || no "redaction (secret in journal: $(grep -c "$SECRET" "$VA/events.jsonl"), in API bodies: $(grep -c "$SECRET" "$VA/api.jsonl"))"
! grep -rqs "$APIKEY" "$VA/console.log" "$VA/events.jsonl" "$VA/api.jsonl" \
  && ok "the Claude API key is not logged or journaled" || no "API key found in console.log/events.jsonl/api.jsonl"
kill $PA; wait $PA 2>/dev/null; kill "$CONPID"; wait "$CONPID" 2>/dev/null; sleep 0.5
NO_PROXY=localhost,127.0.0.1 "$CON" -listen 127.0.0.1:$P_INGEST -http 127.0.0.1:$P_HTTP -cert "$PKI/console.crt" -key "$PKI/console.key" \
  -client-ca "$PKI/ca.crt" -dev -state-dir "$VA" -ai=false >>"$VA/console.log" 2>&1 & CONPID=$!
OURS+=("$CONPID"); sleep 0.8
api "/api/suggestions?status=all" | python3 -c 'import sys,json;i=sys.argv[1];sys.exit(0 if any(x["id"]==i and x["status"]=="applied" for x in json.load(sys.stdin)) else 1)' "$SID" \
  && api "/api/incidents/detail?id=$INC" | grep -q '"verdict"' \
  && ok "decisions and AI results survive a console restart (journal replay)" || no "analysis replay"
stop_all

echo "== policy validation (fails closed) =="
VP=$W/policy; mkdir -p "$VP"
sed -e "s|/etc/wisp/|$ROOT/config/|g" "$ROOT/config/wisp.conf" | grep -vE '^[[:space:]]*(console|cert|key|ca)[[:space:]]*=' > "$VP/ok.conf"
"$AG" -c "$VP/ok.conf" --check-config >/dev/null 2>&1 && ok "--check-config accepts the shipped policy" || no "shipped policy fails --check-config"
printf 'allow 10.0.0.0/8:any\ndney any:22\nallow any:443 actor=agent\nallow 10.0.0.300/8:any\n' > "$VP/bad.net"
printf 'rules=%s/config/rules.conf\nnetpolicy=%s/bad.net\ncatalog=%s\nfim=%s\n' "$ROOT" "$VP" "$NONE" "$NONE" > "$VP/bad.conf"
out=$("$AG" -c "$VP/bad.conf" --check-config 2>&1); rc=$?
[ $rc -ne 0 ] && echo "$out" | grep -q "bad.net:2: unknown verb" && echo "$out" | grep -q "bad.net:3: unknown actor" \
  && echo "$out" | grep -q "bad.net:4: bad IPv4" && echo "$out" | grep -q "^netpolicy   1 " \
  && ok "typo'd verb/actor/network rejected with file:line, never loaded as allow" || no "policy validation: $out"

echo "== MDM / image-bake unattended install (staging roots only) =="
inst(){ bash "$ROOT/packaging/install.sh" "$@" >"$W/install.log" 2>&1; }
VM=$W/mdm; mkdir -p "$VM"
WISP_CONSOLE=console.corp:8750 WISP_GROUP='ci|a&b\c' WISP_MODE=enforce WISP_EPHEMERAL=1 \
WISP_CA_PEM_FILE="$PKI/ca.crt" WISP_CERT_PEM_FILE="$PKI/agent.crt" WISP_KEY_PEM_FILE="$PKI/agent.key" \
  inst --root "$VM" --no-start
grep -q '^console = console.corp:8750$' "$VM/etc/wisp/wisp.conf" && grep -q '^ephemeral = 1$' "$VM/etc/wisp/wisp.conf" \
  && grep -qxF 'group = ci|a&b\c' "$VM/etc/wisp/wisp.conf" && [ "$(grep -c '^group' "$VM/etc/wisp/wisp.conf")" = 1 ] \
  && [ "$(stat -c %a "$VM/etc/wisp/pki/agent.key")" = 600 ] && [ -x "$VM/usr/local/sbin/wispd" ] \
  && ok "unattended install from env (no prompts): config written literally, 0600 mTLS material" || no "mdm install: $(tail -3 "$W/install.log")"
[ -L "$VM/etc/systemd/system/multi-user.target.wants/wispd.service" ] \
  && ok "image bake: wispd.service enabled in the staging root (starts on first boot)" || no "image bake: wispd.service not enabled in the staging root"
inst --root "$VM" --uninstall
[ ! -e "$VM/usr/local/sbin/wispd" ] && [ ! -e "$VM/etc/systemd/system/wispd.service" ] \
  && [ ! -e "$VM/etc/systemd/system/multi-user.target.wants/wispd.service" ] && [ -e "$VM/etc/wisp/wisp.conf" ] \
  && ok "--uninstall honours --root (staging root only; config kept)" || no "uninstall with --root"
VM=$W/mdm-prefix; mkdir -p "$VM"
PREFIX=/opt/wisp inst --root "$VM" --no-start
grep -q '^ExecStart=/opt/wisp/sbin/wispd ' "$VM/etc/systemd/system/wispd.service" && [ -x "$VM/opt/wisp/sbin/wispd" ] \
  && ok "PREFIX=/opt/wisp: binary and the unit's ExecStart agree" || no "PREFIX install: $(grep ExecStart "$VM/etc/systemd/system/wispd.service" 2>/dev/null)"
VM=$W/mdm-tpm; mkdir -p "$VM"
WISP_CONSOLE=console.corp:8750 WISP_TPM=1 WISP_CA_PEM_FILE="$PKI/ca.crt" WISP_CERT_PEM_FILE="$PKI/agent.crt" \
  WISP_KEY_PATH=/etc/wisp/pki/agent_tpm.key inst --root "$VM" --no-start
[ -f "$VM/etc/systemd/system/wispd.service" ] && grep -q '^tpm = 1$' "$VM/etc/wisp/wisp.conf" \
  && grep -q '^key = /etc/wisp/pki/agent_tpm.key$' "$VM/etc/wisp/wisp.conf" && [ ! -e "$VM/etc/wisp/pki/agent.key" ] \
  && ok "unattended install with a TPM-resident key (WISP_KEY_PATH): key points at the blob" || no "mdm tpm install: $(tail -3 "$W/install.log")"
VM=$W/mdm-bad; mkdir -p "$VM"
WISP_CONSOLE=console.corp:8750 WISP_TPM=1 WISP_CA_PEM_FILE="$PKI/ca.crt" WISP_CERT_PEM_FILE="$PKI/agent.crt" \
  inst --root "$VM" --no-start; r1=$?
WISP_CONSOLE=console.corp:8750 WISP_CERT_PEM_FILE="$PKI/agent.crt" WISP_KEY_PEM_FILE="$PKI/agent.key" \
  inst --root "$VM" --no-start; r2=$?
[ $r1 -ne 0 ] && [ $r2 -ne 0 ] && [ ! -e "$VM/etc/wisp/wisp.conf" ] \
  && ok "install refuses WISP_TPM=1 without a key and WISP_CONSOLE without a CA (nothing installed)" || no "install accepted an unusable console setup (tpm-no-key rc=$r1, no-ca rc=$r2)"

echo
echo "== not runnable in this sandbox =="
sk "macOS / Windows runtime" "no macOS/Windows host (backends compile-check only)"
sk "hardware TPM key-residency" "no TPM device (shown on software TPM 2.0)"
sk "live io.security parity" "gateway returns 403 for io.security (built to the uploaded spec)"

echo
echo "RESULT: $pass passed, $fail failed, $skip skipped (environmental)"
exit $fail

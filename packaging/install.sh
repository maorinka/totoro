#!/usr/bin/env bash
# Wisp installer -- sensor (default) or console (--console); interactive or
# fully unattended (MDM / image bake).
#
#   sudo ./packaging/install.sh                 # sensor: install + start (monitor mode)
#   sudo ./packaging/install.sh --console       # console: binary, unit, /etc/wisp/console
#   sudo ./packaging/install.sh --uninstall     # remove the sensor (config kept)
#
# Options: --root DIR  install into a staging root (image / container bake)
#          --no-start  install and enable, but do not start now
#
# Unattended sensor rollout (Jamf / Intune / Ansible / cloud-init / any MDM
# that can run a script): no prompts; per-host settings come from the
# environment:
#
#   WISP_CONSOLE=console.corp:8750   fleet console (host:port); needs a CA,
#                                    a client certificate and a key (below)
#   WISP_GROUP=prod-eu               fleet group (drives gradual rollouts)
#   WISP_MODE=monitor|enforce        initial mode (default monitor)
#   WISP_EPHEMERAL=1                 short-lived runner/container: the console
#                                    decommissions it as soon as it exits
#   WISP_CA_PEM_FILE / WISP_CERT_PEM_FILE / WISP_KEY_PEM_FILE
#                                    mTLS material as files (preferred)
#   WISP_CA_PEM / WISP_CERT_PEM / WISP_KEY_PEM
#                                    the same as PEM text. Never put these on a
#                                    `sudo VAR=... ./install.sh` command line:
#                                    sudo's argv is readable by every local user
#                                    in /proc. Export them in an already-root
#                                    environment (MDM secret env, `sudo -E`) or
#                                    use the *_FILE variants.
#                                    Written 0600 under /etc/wisp/pki.
#   WISP_TPM=1                       the client key is TPM-resident: give the
#                                    TSS2 key blob as WISP_KEY_PEM(_FILE), or
#                                    WISP_KEY_PATH=<path of the blob on the host>
#
# Image / container bake:  --root DIR installs into a staging root and enables
# wispd.service there (systemctl --root), so it starts on the image's first boot.
#
# PREFIX (default /usr/local) sets where binaries and docs go; the installed
# units' ExecStart and Documentation paths follow it.
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd)
PREFIX=${PREFIX:-/usr/local}
ROOT=""
START=1
ACTION=sensor

die() { echo "install.sh: $*" >&2; exit 1; }

# Parse every argument first: --root must apply whatever the order.
while [[ $# -gt 0 ]]; do
	case "$1" in
	--uninstall) ACTION=uninstall ;;
	--console) ACTION=console ;;
	--root)
		[[ $# -ge 2 && -n "$2" ]] || die "--root needs a directory"
		ROOT=$(cd "$2" && pwd) || die "--root $2: no such directory"
		shift ;;
	--no-start) START=0 ;;
	-h | --help) sed -n '2,/^set -euo/{/^set -euo/d;s/^# \{0,1\}//;p}' "$0"; exit 0 ;;
	*) echo "unknown option $1" >&2; exit 2 ;;
	esac
	shift
done
[[ "$PREFIX" == /* ]] || die "PREFIX must be an absolute path (got '$PREFIX')"
[[ "$PREFIX" != *[[:space:]\|\&\\]* ]] || die "PREFIX must not contain whitespace, '|', '&' or '\\'"

[[ $EUID -eq 0 || -n "$ROOT" ]] || { echo "run as root" >&2; exit 1; }
ETC="$ROOT/etc/wisp"
UNITDIR="$ROOT/etc/systemd/system"
DOCDIR="$ROOT$PREFIX/share/doc/wisp"

live_systemd() { [[ -z "$ROOT" ]] && command -v systemctl >/dev/null && [[ -d /run/systemd/system ]]; }

# install_unit NAME: the unit from packaging/, with /usr/local replaced by PREFIX.
install_unit() {
	install -d -m0755 "$UNITDIR"
	sed "s|/usr/local/|$PREFIX/|g" "$HERE/packaging/$1" >"$UNITDIR/$1.tmp"
	chmod 0644 "$UNITDIR/$1.tmp"
	mv -f "$UNITDIR/$1.tmp" "$UNITDIR/$1"
}

# enable_unit NAME: enable for boot, in the staging root or on this host.
enable_unit() {
	if [[ -n "$ROOT" ]]; then
		if command -v systemctl >/dev/null && systemctl --root="$ROOT" enable "$1" >/dev/null 2>&1; then
			:
		else # no systemctl on the build host: the same symlink by hand
			local target
			target=$(sed -n 's/^WantedBy=//p' "$UNITDIR/$1" | head -1)
			install -d -m0755 "$UNITDIR/$target.wants"
			ln -sfn "../$1" "$UNITDIR/$target.wants/$1"
		fi
		echo "    $1 enabled in $ROOT (starts on first boot)"
	elif live_systemd; then
		systemctl enable "$1" >/dev/null
		echo "    $1 enabled"
	else
		echo "    no systemd: start $1's ExecStart from your init system"
	fi
}

install_docs() {
	install -d "$DOCDIR/docs"
	install -m0644 "$HERE/README.md" "$DOCDIR/README.md"
	for d in "$HERE"/docs/*.md; do install -m0644 "$d" "$DOCDIR/docs/"; done
}

# ---- uninstall ---------------------------------------------------------------
if [[ $ACTION == uninstall ]]; then
	if live_systemd; then
		systemctl disable --now wispd wisp-logrotate.timer 2>/dev/null || true
	elif [[ -n "$ROOT" ]] && command -v systemctl >/dev/null; then
		systemctl --root="$ROOT" disable wispd.service wisp-logrotate.timer >/dev/null 2>&1 || true
	fi
	rm -f "$ROOT$PREFIX/sbin/wispd" "$UNITDIR/wispd.service" "$UNITDIR/multi-user.target.wants/wispd.service" \
		"$UNITDIR/wisp-logrotate.service" "$UNITDIR/wisp-logrotate.timer" \
		"$UNITDIR/timers.target.wants/wisp-logrotate.timer" "$ROOT/etc/logrotate.d/wisp"
	# The docs are shared with the console; keep them while it is installed.
	[[ -e "$ROOT$PREFIX/bin/wisp-console" ]] || rm -rf "$DOCDIR"
	live_systemd && systemctl daemon-reload 2>/dev/null || true
	echo "wispd uninstalled${ROOT:+ from $ROOT}."
	echo "Left in place: configuration ($ETC), logs ($ROOT/var/log/wisp) and state ($ROOT/var/lib/wisp)."
	if [[ -d "$ROOT/var/lib/wisp/quarantine" ]] && [[ -n "$(ls -A "$ROOT/var/lib/wisp/quarantine" 2>/dev/null)" ]]; then
		echo "NOTE: $ROOT/var/lib/wisp/quarantine holds quarantined (likely malicious) executables;"
		echo "      review them, then remove the directory yourself."
	fi
	exit 0
fi

# ---- console -------------------------------------------------------------------
if [[ $ACTION == console ]]; then
	if [[ -x "$HERE/bin/wisp-console" ]]; then
		CON="$HERE/bin/wisp-console" # release tarball: prebuilt
	else
		echo "==> building console"
		make -C "$HERE/console" >/dev/null
		CON="$HERE/console/wisp-console"
	fi
	echo "==> installing console binary, unit and /etc/wisp/console"
	install -D -m0755 "$CON" "$ROOT$PREFIX/bin/wisp-console"
	install -d -m0755 "$ETC"
	install -d -m0750 "$ETC/console"
	install_unit wisp-console.service
	install_docs
	live_systemd && systemctl daemon-reload
	cat <<EOF

Wisp console installed${ROOT:+ into $ROOT}. Before starting it, put these in /etc/wisp/console
(see docs/installation.md): console.crt, console.key, sensor-ca.crt, and roles.conf
(wisp-console -gen-token admin:<name>). Then:
  systemctl enable --now wisp-console
EOF
	exit 0
fi

# ---- sensor: validate unattended settings before touching anything -----------
# pem VAR: the PEM text from VAR, or from the file named by VAR_FILE.
pem() {
	local text="${!1:-}" file_var="${1}_FILE"
	local file="${!file_var:-}"
	if [[ -n "$file" ]]; then
		[[ -z "$text" ]] || die "set either $1 or $file_var, not both"
		[[ -r "$file" && -s "$file" ]] || die "$file_var=$file: not a readable, non-empty file"
		cat "$file"
	else
		printf '%s' "$text"
	fi
}
CA_PEM=$(pem WISP_CA_PEM)
CERT_PEM=$(pem WISP_CERT_PEM)
KEY_PEM=$(pem WISP_KEY_PEM)
KEY_PATH=${WISP_KEY_PATH:-}
[[ -z "$KEY_PATH" || "$KEY_PATH" == /* ]] || die "WISP_KEY_PATH must be an absolute path"
[[ -z "$KEY_PATH" || -z "$KEY_PEM" ]] || die "set either WISP_KEY_PEM(_FILE) or WISP_KEY_PATH, not both"

# conf_has KEY: the existing wisp.conf (re-install) sets KEY.
conf_has() { [[ -e "$ETC/wisp.conf" ]] && grep -qE "^[[:space:]]*$1[[:space:]]*=[[:space:]]*[^[:space:]#]" "$ETC/wisp.conf"; }

if [[ "${WISP_TPM:-}" == 1 && -z "$KEY_PEM" && -z "$KEY_PATH" ]] && ! conf_has key; then
	die "WISP_TPM=1 needs the TPM key blob: WISP_KEY_PEM / WISP_KEY_PEM_FILE (the TSS2 PEM blob) or WISP_KEY_PATH (where it is on the host)"
fi
if [[ -n "${WISP_CONSOLE:-}" ]]; then
	# The sensor refuses to connect without a CA, and the console rejects a
	# sensor without a client certificate: fail now, not silently on the host.
	[[ -n "$CA_PEM" ]] || conf_has ca ||
		die "WISP_CONSOLE is set but no CA: give WISP_CA_PEM or WISP_CA_PEM_FILE"
	[[ -n "$CERT_PEM" ]] || conf_has cert ||
		die "WISP_CONSOLE is set but no client certificate: give WISP_CERT_PEM or WISP_CERT_PEM_FILE"
	[[ -n "$KEY_PEM" || -n "$KEY_PATH" ]] || conf_has key ||
		die "WISP_CONSOLE is set but no client key: give WISP_KEY_PEM, WISP_KEY_PEM_FILE or (TPM) WISP_KEY_PATH"
fi
case "${WISP_MODE:-monitor}" in monitor | enforce) ;; *) die "WISP_MODE must be monitor or enforce" ;; esac

# ---- sensor install -------------------------------------------------------------
if [[ -x "$HERE/bin/wispd" ]]; then
	WISPD="$HERE/bin/wispd" # release tarball: prebuilt
else
	echo "==> building sensor"
	make -C "$HERE/agent" >/dev/null
	WISPD="$HERE/agent/wispd"
fi

WAS_ACTIVE=0
if live_systemd && systemctl is-active --quiet wispd; then WAS_ACTIVE=1; fi

echo "==> installing binary and config"
install -D -m0755 "$WISPD" "$ROOT$PREFIX/sbin/wispd"
install -d -m0750 "$ETC" "$ROOT/var/log/wisp" "$ROOT/var/lib/wisp"
for f in wisp.conf rules.conf catalog.conf fim.conf netpolicy.conf; do
	if [[ -e $ETC/$f ]]; then
		install -m0640 "$HERE/config/$f" "$ETC/$f.default"
		echo "    $ETC/$f exists; new version written as $f.default"
	else
		install -m0640 "$HERE/config/$f" "$ETC/$f"
	fi
done

# set_key KEY VALUE: set "KEY = VALUE" in wisp.conf, replacing the first
# (possibly commented) KEY line and dropping later active duplicates, or
# append it. The value is passed through the environment and written
# literally (no sed/regex interpretation), and must be one config line.
set_key() {
	local conf="$ETC/wisp.conf"
	[[ "$2" != *$'\n'* && "$2" != *$'\r'* ]] || die "$1: value must be a single line"
	[[ ! "$2" =~ [[:space:]]# ]] || die "$1: value must not contain ' #' (starts a comment in wisp.conf)"
	K="$1" V="$2" awk '
		BEGIN { k = ENVIRON["K"]; v = ENVIRON["V"]; done = 0 }
		{
			s = $0; active = (s !~ /^[[:space:]]*#/)
			sub(/^[#[:space:]]*/, "", s)
			hit = index(s, k) == 1 && substr(s, length(k) + 1) ~ /^[[:space:]]*=/
			if (hit && !done) { print k " = " v; done = 1; next }
			if (hit && active) next
			print
		}
		END { if (!done) print k " = " v }' "$conf" >"$conf.tmp"
	cat "$conf.tmp" >"$conf" # keep the file's mode and owner
	rm -f "$conf.tmp"
	echo "    $1 = $2"
}

if [[ -n "${WISP_CONSOLE:-}${WISP_GROUP:-}${WISP_MODE:-}${WISP_EPHEMERAL:-}${WISP_TPM:-}$CA_PEM$CERT_PEM$KEY_PEM$KEY_PATH" ]]; then
	echo "==> applying unattended settings"
	[[ -n "${WISP_CONSOLE:-}" ]] && set_key console "$WISP_CONSOLE"
	[[ -n "${WISP_GROUP:-}" ]] && set_key group "$WISP_GROUP"
	[[ -n "${WISP_MODE:-}" ]] && set_key mode "$WISP_MODE"
	[[ -n "${WISP_EPHEMERAL:-}" ]] && set_key ephemeral "$WISP_EPHEMERAL"
	[[ -n "${WISP_TPM:-}" ]] && set_key tpm "$WISP_TPM"
	if [[ -n "$CA_PEM$CERT_PEM$KEY_PEM" ]]; then
		install -d -m0700 "$ETC/pki"
		(
			umask 077
			if [[ -n "$CA_PEM" ]]; then printf '%s\n' "$CA_PEM" >"$ETC/pki/ca.crt"; fi
			if [[ -n "$CERT_PEM" ]]; then printf '%s\n' "$CERT_PEM" >"$ETC/pki/agent.crt"; fi
			if [[ -n "$KEY_PEM" ]]; then printf '%s\n' "$KEY_PEM" >"$ETC/pki/agent.key"; fi
		)
	fi
	# Paths as the sensor sees them on the target (no staging root).
	[[ -n "$CA_PEM" ]] && set_key ca /etc/wisp/pki/ca.crt
	[[ -n "$CERT_PEM" ]] && set_key cert /etc/wisp/pki/agent.crt
	[[ -n "$KEY_PEM" ]] && set_key key /etc/wisp/pki/agent.key
	[[ -n "$KEY_PATH" ]] && set_key key "$KEY_PATH"
fi

echo "==> installing documentation"
install_docs

echo "==> validating policy"
# Report problems but still install: a sensor with one bad rule skipped is
# better than no sensor. Fix what is reported and `systemctl reload wispd`.
if [[ -z "$ROOT" ]]; then
	"$PREFIX/sbin/wispd" -c /etc/wisp/wisp.conf --check-config | sed 's/^/    /' ||
		echo "    WARNING: problems above; the lines listed are skipped until fixed"
else
	echo "    (staging root: run 'wispd --check-config' on the target)"
fi

echo "==> installing log rotation"
install -D -m0644 "$HERE/packaging/wisp.logrotate" "$ROOT/etc/logrotate.d/wisp"

echo "==> installing systemd units"
install_unit wispd.service
install_unit wisp-logrotate.service
install_unit wisp-logrotate.timer
live_systemd && systemctl daemon-reload
enable_unit wispd.service
enable_unit wisp-logrotate.timer
if [[ $START -eq 1 ]] && live_systemd; then
	systemctl start wisp-logrotate.timer || true
	if [[ $WAS_ACTIVE -eq 1 ]]; then
		echo "    restarting the running sensor onto the new binary"
		systemctl restart wispd
	else
		systemctl start wispd
	fi
	sleep 1
	systemctl --no-pager --lines=5 status wispd || true
	echo "    installed: $("$PREFIX/sbin/wispd" --version 2>/dev/null || echo '?')"
else
	echo "    not starting now (--no-start, --root, or no systemd)"
fi
echo
echo "Wisp sensor installed (mode: ${WISP_MODE:-monitor})."
echo "  logs:    tail -f /var/log/wisp/alerts.jsonl"
echo "  policy:  /etc/wisp/rules.conf   (edit, then: systemctl reload wispd)"

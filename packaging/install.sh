#!/usr/bin/env bash
# Wisp sensor installer -- interactive or fully unattended (MDM / image bake).
#
#   sudo ./packaging/install.sh                 # install + start (monitor mode)
#   sudo ./packaging/install.sh --uninstall
#
# Unattended rollout (Jamf / Intune / Ansible / cloud-init / any MDM that can
# run a script): no prompts, no changes to the host's code, tools or pipelines;
# per-host settings come from the environment:
#
#   WISP_CONSOLE=console.corp:8750   fleet console (host:port)
#   WISP_GROUP=prod-eu               fleet group (drives gradual rollouts)
#   WISP_MODE=monitor|enforce        initial mode (default monitor)
#   WISP_EPHEMERAL=1                 short-lived runner/container: the console
#                                    decommissions it as soon as it exits
#   WISP_CA_PEM / WISP_CERT_PEM / WISP_KEY_PEM
#                                    mTLS material as PEM text (MDM secrets);
#                                    written 0600 under /etc/wisp/pki
#   WISP_TPM=1                       mTLS key is TPM-resident
#
# Image / container bake:  --root DIR  installs into a staging root, and
# --no-start skips systemd (the unit starts on first boot of the image).
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd)
PREFIX=${PREFIX:-/usr/local}
ROOT=""
START=1

while [[ $# -gt 0 ]]; do
	case "$1" in
	--uninstall)
		systemctl disable --now wispd 2>/dev/null || true
		rm -f "$PREFIX/sbin/wispd" /etc/systemd/system/wispd.service
		systemctl daemon-reload 2>/dev/null || true
		echo "wispd uninstalled (config under /etc/wisp left in place)"
		exit 0 ;;
	--root) ROOT=$2; shift ;;
	--no-start) START=0 ;;
	*) echo "unknown option $1" >&2; exit 2 ;;
	esac
	shift
done

[[ $EUID -eq 0 || -n "$ROOT" ]] || { echo "run as root" >&2; exit 1; }
ETC="$ROOT/etc/wisp"

if [[ -x "$HERE/bin/wispd" ]]; then
	WISPD="$HERE/bin/wispd" # release tarball: prebuilt
else
	echo "==> building sensor"
	make -C "$HERE/agent" >/dev/null
	WISPD="$HERE/agent/wispd"
fi

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

# set_key KEY VALUE: replace "KEY = ..." in wisp.conf, or append it.
set_key() {
	local conf="$ETC/wisp.conf"
	if grep -qE "^[#[:space:]]*$1[[:space:]]*=" "$conf"; then
		sed -i -E "s|^[#[:space:]]*$1[[:space:]]*=.*|$1 = $2|" "$conf"
	else
		echo "$1 = $2" >>"$conf"
	fi
	echo "    $1 = $2"
}

if [[ -n "${WISP_CONSOLE:-}${WISP_GROUP:-}${WISP_MODE:-}${WISP_EPHEMERAL:-}${WISP_CA_PEM:-}${WISP_TPM:-}" ]]; then
	echo "==> applying unattended settings"
	[[ -n "${WISP_CONSOLE:-}" ]] && set_key console "$WISP_CONSOLE"
	[[ -n "${WISP_GROUP:-}" ]] && set_key group "$WISP_GROUP"
	[[ -n "${WISP_MODE:-}" ]] && set_key mode "$WISP_MODE"
	[[ -n "${WISP_EPHEMERAL:-}" ]] && set_key ephemeral "$WISP_EPHEMERAL"
	[[ -n "${WISP_TPM:-}" ]] && set_key tpm "$WISP_TPM"
	if [[ -n "${WISP_CA_PEM:-}" ]]; then
		install -d -m0700 "$ETC/pki"
		(umask 077
		 printf '%s\n' "$WISP_CA_PEM" >"$ETC/pki/ca.crt"
		 if [[ -n "${WISP_CERT_PEM:-}" ]]; then printf '%s\n' "$WISP_CERT_PEM" >"$ETC/pki/agent.crt"; fi
		 if [[ -n "${WISP_KEY_PEM:-}" ]]; then printf '%s\n' "$WISP_KEY_PEM" >"$ETC/pki/agent.key"; fi)
		set_key ca /etc/wisp/pki/ca.crt
		[[ -n "${WISP_CERT_PEM:-}" ]] && set_key cert /etc/wisp/pki/agent.crt
		[[ -n "${WISP_KEY_PEM:-}" ]] && set_key key /etc/wisp/pki/agent.key
	fi
fi

echo "==> installing documentation"
install -d "$ROOT$PREFIX/share/doc/wisp/docs"
install -m0644 "$HERE/README.md" "$ROOT$PREFIX/share/doc/wisp/README.md"
for d in "$HERE"/docs/*.md; do install -m0644 "$d" "$ROOT$PREFIX/share/doc/wisp/docs/"; done

echo "==> validating policy"
# Report problems but still install: a sensor with one bad rule skipped is
# better than no sensor. Fix what is reported and `systemctl reload wispd`.
if [[ -z "$ROOT" ]]; then
	"$PREFIX/sbin/wispd" -c /etc/wisp/wisp.conf --check-config | sed 's/^/    /' ||
		echo "    WARNING: policy problems above; the lines listed are skipped until fixed"
else
	echo "    (staging root: run 'wispd --check-config' on the target)"
fi

echo "==> installing log rotation"
install -D -m0644 "$HERE/packaging/wisp.logrotate" "$ROOT/etc/logrotate.d/wisp"

echo "==> installing systemd unit"
install -D -m0644 "$HERE/packaging/wispd.service" "$ROOT/etc/systemd/system/wispd.service"
if [[ $START -eq 1 && -z "$ROOT" ]] && command -v systemctl >/dev/null && [[ -d /run/systemd/system ]]; then
	systemctl daemon-reload
	systemctl enable --now wispd
	sleep 1
	systemctl --no-pager --lines=5 status wispd || true
else
	echo "    not starting now (--no-start, --root, or no systemd); enable wispd.service on boot"
fi
echo
echo "Wisp sensor installed (mode: ${WISP_MODE:-monitor})."
echo "  logs:    tail -f /var/log/wisp/alerts.jsonl"
echo "  policy:  /etc/wisp/rules.conf   (edit, then: systemctl reload wispd)"

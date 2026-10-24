#!/usr/bin/env bash
# Demonstrate hardware-backed host identity: an mTLS client key that is
# TPM-resident (the private key never leaves the TPM; the TPM signs the
# handshake). Uses a software TPM 2.0 (swtpm) so it is reproducible without
# TPM hardware -- the code path is identical with a hardware TPM, which is
# reached via /dev/tpmrm0 instead of the swtpm socket.
#
# Requires: swtpm, tpm2-tools, tpm2-openssl, the built agent + console.
set -euo pipefail
cd "$(dirname "$0")/.."
PKI=pki
mkdir -p "$PKI" /tmp/swtpm

echo "==> starting software TPM 2.0 (swtpm)"
pkill -x swtpm 2>/dev/null || true
sleep 0.3
swtpm socket --tpmstate dir=/tmp/swtpm --ctrl type=tcp,port=2322 \
  --server type=tcp,port=2321 --tpm2 --flags not-need-init,startup-clear \
  >/tmp/swtpm.log 2>&1 &
sleep 1
export TPM2OPENSSL_TCTI="swtpm:host=127.0.0.1,port=2321"
export TPM2TOOLS_TCTI="$TPM2OPENSSL_TCTI"

echo "==> creating a TPM-RESIDENT EC key (private key stays inside the TPM)"
openssl genpkey -provider tpm2 -provider default -algorithm EC \
  -pkeyopt group:P-256 -out "$PKI/agent_tpm.key"
echo "    key file is a TPM blob, not a raw key:"
head -1 "$PKI/agent_tpm.key"

echo "==> proving the TPM signs (sign a nonce in the TPM, verify with the pubkey)"
echo "nonce-$(date +%s%N)" > /tmp/n.txt
openssl pkeyutl -provider tpm2 -provider default -sign -inkey "$PKI/agent_tpm.key" \
  -rawin -in /tmp/n.txt -out /tmp/n.sig
openssl pkey -provider tpm2 -provider default -in "$PKI/agent_tpm.key" -pubout -out /tmp/n.pub 2>/dev/null
openssl pkeyutl -provider default -verify -pubin -inkey /tmp/n.pub -rawin -in /tmp/n.txt -sigfile /tmp/n.sig

echo "==> issuing an EC CA + console cert, and a CA-signed cert for the TPM key"
openssl ecparam -name prime256v1 -genkey -noout -out "$PKI/ca-ec.key"
openssl req -x509 -new -key "$PKI/ca-ec.key" -out "$PKI/ca-ec.crt" -days 365 -subj "/CN=Wisp EC CA"
openssl ecparam -name prime256v1 -genkey -noout -out "$PKI/console-ec.key"
openssl req -new -key "$PKI/console-ec.key" -out "$PKI/console-ec.csr" -subj "/CN=wisp-console" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
openssl x509 -req -in "$PKI/console-ec.csr" -CA "$PKI/ca-ec.crt" -CAkey "$PKI/ca-ec.key" \
  -CAcreateserial -out "$PKI/console-ec.crt" -days 365 -copy_extensions copy
openssl req -provider tpm2 -provider default -new -key "$PKI/agent_tpm.key" \
  -out "$PKI/agent_tpm_ec.csr" -subj "/CN=vm.tpm-sensor"
openssl x509 -req -in "$PKI/agent_tpm_ec.csr" -CA "$PKI/ca-ec.crt" -CAkey "$PKI/ca-ec.key" \
  -CAcreateserial -out "$PKI/agent_tpm_ec.crt" -days 365

echo
echo "TPM-resident identity ready. To run the sensor with it:"
echo "  TPM2OPENSSL_TCTI=$TPM2OPENSSL_TCTI \\"
echo "  ./agent/wispd -c <conf with tpm=1, cert=$PKI/agent_tpm_ec.crt, key=$PKI/agent_tpm.key>"
echo "The console will show the host with trust=tpm, authenticated by a key it"
echo "cannot extract. (swtpm socket mode is occasionally flaky; a hardware TPM"
echo "via /dev/tpmrm0 is robust -- the agent retries on a transient load error.)"

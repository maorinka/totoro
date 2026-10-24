#!/usr/bin/env bash
# Throwaway test PKI for the console mTLS tests: a CA, a console server cert
# (SAN localhost/127.0.0.1), an agent client cert, and a "rogue" client cert
# from a second, untrusted CA (negative tests: the console must refuse it).
# Only creates what is missing; pki/ is gitignored -- never ship these keys.
set -euo pipefail
D=${1:-$(cd "$(dirname "$0")/.." && pwd)/pki}
mkdir -p "$D"; cd "$D"
[[ -f ca.crt ]] || openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt -days 365 \
  -subj "/CN=wisp-test-ca" -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
issue() { # name cn extfile-lines
  [[ -f $1.crt ]] && return
  openssl req -newkey rsa:2048 -nodes -keyout "$1.key" -out "$1.csr" -subj "/CN=$2" 2>/dev/null
  printf '%b' "$3" > "$1.ext"
  openssl x509 -req -in "$1.csr" -CA ca.crt -CAkey ca.key -CAcreateserial -out "$1.crt" -days 365 -extfile "$1.ext" 2>/dev/null
  rm -f "$1.ext"
}
issue console localhost "subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\nkeyUsage=digitalSignature,keyEncipherment\n"
issue agent wisp-agent "extendedKeyUsage=clientAuth\nkeyUsage=digitalSignature,keyEncipherment\n"
# Rogue: a client certificate the console's -client-ca did NOT sign.
[[ -f rogue-ca.crt ]] || openssl req -x509 -newkey rsa:2048 -nodes -keyout rogue-ca.key -out rogue-ca.crt -days 365 \
  -subj "/CN=wisp-rogue-ca" -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
if [[ ! -f rogue.crt ]]; then
  openssl req -newkey rsa:2048 -nodes -keyout rogue.key -out rogue.csr -subj "/CN=wisp-agent" 2>/dev/null
  printf 'extendedKeyUsage=clientAuth\nkeyUsage=digitalSignature,keyEncipherment\n' > rogue.ext
  openssl x509 -req -in rogue.csr -CA rogue-ca.crt -CAkey rogue-ca.key -CAcreateserial -out rogue.crt -days 365 \
    -extfile rogue.ext 2>/dev/null
  rm -f rogue.ext
fi
chmod 600 ./*.key

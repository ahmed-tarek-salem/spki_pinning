#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
FIX="packages/ssl_public_key_pinning/test/fixtures"
mkdir -p "$FIX"
DAYS=36500

san_cfg() { # $1 = SAN value list
  cat <<EOF
[req]
distinguished_name = dn
x509_extensions = ext
prompt = no
[dn]
CN = localhost
[ext]
subjectAltName = $1
EOF
}

selfsigned() { # $1 name, $2 keyalg args (string), $3 SAN or ""
  local name="$1"; shift
  local keyargs="$1"; shift
  local san="${1:-}"
  if [ -n "$san" ]; then
    san_cfg "$san" > "$FIX/$name.cnf"
    # shellcheck disable=SC2086
    openssl req -x509 -newkey $keyargs -keyout "$FIX/$name.key.pem" \
      -out "$FIX/$name.crt.pem" -days "$DAYS" -nodes -config "$FIX/$name.cnf"
    rm "$FIX/$name.cnf"
  else
    # shellcheck disable=SC2086
    openssl req -x509 -newkey $keyargs -keyout "$FIX/$name.key.pem" \
      -out "$FIX/$name.crt.pem" -days "$DAYS" -nodes -subj "/CN=$name.test"
  fi
  openssl x509 -in "$FIX/$name.crt.pem" -outform der -out "$FIX/$name.crt.der"
}

selfsigned localhost_rsa2048 "rsa:2048" "DNS:localhost,IP:127.0.0.1"
selfsigned ec_p256 "ec -pkeyopt ec_paramgen_curve:P-256" "DNS:localhost,IP:127.0.0.1"
selfsigned rsa4096 "rsa:4096"
selfsigned ec_p384 "ec -pkeyopt ec_paramgen_curve:P-384"
selfsigned ed25519 "ed25519"
selfsigned ca "rsa:2048"

# v1 certificate: CSR signed without extensions -> version 1, no [0] tag.
# Modern OpenSSL 3.x emits v3 even without extensions; macOS system LibreSSL
# still emits v1, so prefer it when present (fixtures are committed, so CI
# never needs to regenerate them).
V1SSL="openssl"
[ -x /usr/bin/openssl ] && /usr/bin/openssl version | grep -q LibreSSL && V1SSL="/usr/bin/openssl"
"$V1SSL" req -new -newkey rsa:2048 -nodes -keyout "$FIX/v1_rsa2048.key.pem" \
  -out "$FIX/v1_rsa2048.csr" -subj "/CN=v1.test"
"$V1SSL" x509 -req -in "$FIX/v1_rsa2048.csr" -signkey "$FIX/v1_rsa2048.key.pem" \
  -days "$DAYS" -out "$FIX/v1_rsa2048.crt.pem"
openssl x509 -in "$FIX/v1_rsa2048.crt.pem" -outform der -out "$FIX/v1_rsa2048.crt.der"
rm "$FIX/v1_rsa2048.csr"

# CA-signed server cert for host "127.0.0.1" (the unpinned channel in tests)
openssl req -new -newkey rsa:2048 -nodes -keyout "$FIX/unpinned_ip.key.pem" \
  -out "$FIX/unpinned_ip.csr" -subj "/CN=127.0.0.1"
printf "subjectAltName=IP:127.0.0.1\n" > "$FIX/unpinned_ip.ext"
openssl x509 -req -in "$FIX/unpinned_ip.csr" -CA "$FIX/ca.crt.pem" \
  -CAkey "$FIX/ca.key.pem" -CAcreateserial -days "$DAYS" \
  -out "$FIX/unpinned_ip.crt.pem" -extfile "$FIX/unpinned_ip.ext"
openssl x509 -in "$FIX/unpinned_ip.crt.pem" -outform der -out "$FIX/unpinned_ip.crt.der"
rm -f "$FIX/unpinned_ip.csr" "$FIX/unpinned_ip.ext" "$FIX/ca.crt.srl" "$FIX/ca.srl"

# Best-effort real-world leaf capture (skipped when offline)
if openssl s_client -connect api.github.com:443 -servername api.github.com \
  </dev/null 2>/dev/null | openssl x509 -outform der \
  -out "$FIX/real_github.crt.der" 2>/dev/null; then
  echo "captured real_github leaf"
else
  rm -f "$FIX/real_github.crt.der"
  echo "offline: skipped real_github capture"
fi

# Expected pins computed by openssl itself (the independent reference)
{
  echo "{"
  first=1
  for der in "$FIX"/*.crt.der; do
    name="$(basename "$der" .crt.der)"
    pin="$(openssl x509 -inform der -in "$der" -pubkey -noout \
      | openssl pkey -pubin -outform der 2>/dev/null \
      | openssl dgst -sha256 -binary | base64)"
    [ $first -eq 1 ] || echo ","
    first=0
    printf '  "%s": "sha256/%s"' "$name" "$pin"
  done
  echo ""
  echo "}"
} > "$FIX/expected_pins.json"
echo "fixtures written to $FIX"

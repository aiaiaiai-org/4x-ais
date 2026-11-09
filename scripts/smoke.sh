#!/bin/sh
# © 2026 aiaiaiai · aiaiaiai.org
# SPDX-License-Identifier: Apache-2.0
# Smoke the built service with throwaway secrets: it answers health, styles,
# discovery and the sign-in page, and refuses what it must refuse.
set -eu

cd "$(dirname "$0")/.."
cargo build --release --locked --quiet
work="$(mktemp -d)"
secret() { head -c 48 /dev/urandom | base64 | tr -d '\n=+/'; }
seed="$(head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=\n')"
AIS_ISSUER=https://auth.aiaiaiai.org \
AIS_SIGNING_KEY="$seed" \
AIS_SECRET="$(secret)" \
AIS_PASSWORD_PEPPER="$(secret)" \
AIS_CLIENTS='[{"client_id":"smoke","name":"Smoke","skin":"cell","redirect_uris":["https://smoke.example/cb"],"secret_sha256":"0000000000000000000000000000000000000000000000000000000000000000"}]' \
AIS_DATABASE_URL="sqlite://$work/ais.db" \
AIS_BIND=127.0.0.1:1927 \
  ./target/release/ais &
server_pid=$!
trap 'kill "$server_pid" 2>/dev/null || true; rm -rf "$work"' EXIT

base=http://127.0.0.1:1927
host='Host: auth.aiaiaiai.org'
ready=0
i=0
while [ "$i" -lt 30 ]; do
  if curl -fsS "$base/healthz" >/dev/null 2>&1; then
    ready=1
    break
  fi
  i=$((i + 1))
  sleep 1
done
[ "$ready" -eq 1 ]

code() { curl -sS --path-as-is -o /dev/null -w '%{http_code}' "$@"; }
test "$(curl -fsS "$base/healthz")" = ok
curl -fsS "$base/" | grep -q 'aiaiaiai AIS'
curl -fsS "$base/static/auth.css" | grep -q 'ecosystem-auth-panel'
curl -fsS "$base/.well-known/openid-configuration" | grep -q '"issuer":"https://auth.aiaiaiai.org"'
curl -fsS "$base/.well-known/jwks.json" | grep -q '"crv":"Ed25519"'
test "$(code "$base/nope")" = 404
test "$(code "$base/static/../Cargo.toml")" = 404
test "$(code -X POST "$base/")" = 405
# The page answers only on the issuer host, and only for a registered client.
test "$(code "$base/authorize?client_id=smoke")" = 404
test "$(code -H "$host" "$base/authorize?client_id=unknown")" = 400
challenge="$(printf %s 'a-pkce-verifier-that-is-long-enough-for-rfc-7636' | openssl dgst -sha256 -binary | base64 | tr '+/' '-_' | tr -d '=')"
page="$(curl -fsS -H "$host" "$base/authorize?response_type=code&client_id=smoke&redirect_uri=https%3A%2F%2Fsmoke.example%2Fcb&scope=openid&state=s&nonce=n&code_challenge=$challenge&code_challenge_method=S256")"
printf %s "$page" | grep -q '>0xf</option>'
printf %s "$page" | grep -q 'autocomplete="username"'
echo "smoke: ok"

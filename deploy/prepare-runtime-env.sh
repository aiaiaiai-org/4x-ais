#!/usr/bin/env sh
# © 2026 aiaiaiai · aiaiaiai.org
# SPDX-License-Identifier: Apache-2.0
#
# Builds AIS's runtime environment on the host that runs it. Infra copies this
# one file next to the workload and runs it before the container starts, with
# the runtime env path to write and a provider env path it does not use.
#
# The three secrets are the service's own and are born here, on the host: no
# GitHub Environment holds them, no envelope carries them, no repository,
# image or log sees them. They are generated once and kept. A value that is
# already there is never replaced, because a new one would be catastrophic:
# a new AIS_SECRET changes every client's `sub`, a new AIS_PASSWORD_PEPPER
# makes every stored password unusable, and a new AIS_SIGNING_KEY invalidates
# every token in flight. A value that is present but malformed stops the
# deploy instead of being rotated.
#
# The registered clients are public configuration and live here, so adding a
# product is a reviewed edit of this file.
set -eu

runtime_env="${1:?runtime environment path is required}"
: "${2:?provider environment path is required}"

umask 077

runtime_dir="$(dirname "$runtime_env")"
mkdir -p "$runtime_dir"
chmod 0700 "$runtime_dir"

read_existing_value() {
  key="$1"
  [ -f "$runtime_env" ] || return 0
  awk -v wanted="$key" '
    index($0, wanted "=") == 1 {
      sub(/^[^=]*=/, "")
      print
      exit
    }
  ' "$runtime_env"
}

generate_hex() {
  od -An -N32 -tx1 /dev/urandom | tr -d ' \n'
}

# A 32-byte Ed25519 seed as unpadded base64url: 43 characters.
generate_seed() {
  head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=\n'
}

signing_key="$(read_existing_value AIS_SIGNING_KEY)"
secret="$(read_existing_value AIS_SECRET)"
pepper="$(read_existing_value AIS_PASSWORD_PEPPER)"

if [ -z "$signing_key" ]; then
  signing_key="$(generate_seed)"
fi
if [ -z "$secret" ]; then
  secret="$(generate_hex)"
fi
if [ -z "$pepper" ]; then
  pepper="$(generate_hex)"
fi

case "$signing_key" in
  *[!A-Za-z0-9_-]*)
    echo "AIS_SIGNING_KEY is present but is not base64url; refusing to replace it" >&2
    exit 1
    ;;
esac
if [ "${#signing_key}" -ne 43 ]; then
  echo "AIS_SIGNING_KEY is present but is not a 32-byte seed; refusing to replace it" >&2
  exit 1
fi
for value in "$secret" "$pepper"; do
  if [ "${#value}" -lt 32 ]; then
    echo "AIS_SECRET and AIS_PASSWORD_PEPPER must be at least 32 bytes; refusing to replace them" >&2
    exit 1
  fi
done
if [ "$secret" = "$pepper" ]; then
  echo "AIS_SECRET and AIS_PASSWORD_PEPPER must be different values" >&2
  exit 1
fi

next_env="$(mktemp "$runtime_dir/.runtime.env.XXXXXX")"
trap 'rm -f "$next_env"' EXIT HUP INT TERM

{
  printf 'AIS_ISSUER=%s\n' 'https://auth.aiaiaiai.org'
  printf 'AIS_SIGNING_KEY=%s\n' "$signing_key"
  printf 'AIS_SECRET=%s\n' "$secret"
  printf 'AIS_PASSWORD_PEPPER=%s\n' "$pepper"
  # 0x1 is a public client: no secret, only PKCE and this exact callback.
  printf 'AIS_CLIENTS=%s\n' '[{"client_id":"nilx-one","name":"0x1","skin":"cell","redirect_uris":["https://nilx.one/api/v1/auth/aiaiaiai/callback"],"pub_dress":true}]'
} >"$next_env"
chmod 0600 "$next_env"
mv "$next_env" "$runtime_env"
trap - EXIT HUP INT TERM

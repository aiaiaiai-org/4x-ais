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
# image or log sees them. They are generated once, when the runtime file does
# not exist at all, and kept. A new value would be catastrophic: a new
# AIS_SECRET changes every client's `sub`, a new AIS_PASSWORD_PEPPER makes
# every stored password unusable, and a new AIS_SIGNING_KEY invalidates every
# token in flight. So nothing is ever generated into a file that already
# exists: if one of the three is missing, empty or malformed (a hand edit, a
# restore from an old copy), the deploy stops. It also refuses to create the
# file while the data volume exists, because a lost secrets file next to a
# surviving database must fail loudly, not start a service whose every
# identifier has changed.
#
# The registered clients are public configuration and live here, so adding a
# product is a reviewed edit of this file.
#
# The runtime file is rewritten whole on every run, from the three kept secrets
# and the fixed settings below. Any other key someone adds to it by hand (an
# AIS_BIND, say) is dropped on the next deploy: a setting belongs in this file's
# source, where it is reviewed, not in the host's copy.
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

fail() {
  echo "$1" >&2
  exit 1
}

if [ -e "$runtime_env" ]; then
  signing_key="$(read_existing_value AIS_SIGNING_KEY)"
  secret="$(read_existing_value AIS_SECRET)"
  pepper="$(read_existing_value AIS_PASSWORD_PEPPER)"
  for name in AIS_SIGNING_KEY AIS_SECRET AIS_PASSWORD_PEPPER; do
    case "$name" in
      AIS_SIGNING_KEY) value="$signing_key" ;;
      AIS_SECRET) value="$secret" ;;
      *) value="$pepper" ;;
    esac
    [ -n "$value" ] || fail "$name is missing or empty in the existing runtime file; refusing to mint a new one"
  done
else
  data_volume="${AIS_DATA_VOLUME:-4x-ais-data}"
  command -v docker >/dev/null 2>&1 || fail "docker is required to check that the data volume $data_volume does not exist yet"
  if volume="$(docker volume inspect "$data_volume" 2>&1)"; then
    fail "the data volume $data_volume exists but the secrets file does not; new secrets would change every sub and make every password unusable. Restore the file from its copy, or remove the volume only if it is known to hold no data"
  fi
  case "$volume" in
    *[Nn]o\ such\ volume*) ;;
    *) fail "cannot tell whether the data volume $data_volume exists; refusing to create secrets" ;;
  esac
  signing_key="$(generate_seed)"
  secret="$(generate_hex)"
  pepper="$(generate_hex)"
fi

case "$signing_key" in
  *[!A-Za-z0-9_-]*) fail "AIS_SIGNING_KEY is present but is not base64url; refusing to replace it" ;;
esac
[ "${#signing_key}" -eq 43 ] || fail "AIS_SIGNING_KEY is present but is not a 32-byte seed; refusing to replace it"
# 32 bytes fill 43 characters with two spare bits, which must be zero: only 16
# characters can end a canonical seed, and the service's strict decode refuses
# any other, so a deploy that accepted it would start a crash-looping container.
last_character="$(printf '%s' "$signing_key" | tail -c 1)"
case "$last_character" in
  [AEIMQUYcgkosw048]) ;;
  *) fail "AIS_SIGNING_KEY is not a canonical 32-byte seed; refusing to replace it" ;;
esac
for value in "$secret" "$pepper"; do
  [ "${#value}" -ge 32 ] || fail "AIS_SECRET and AIS_PASSWORD_PEPPER must be at least 32 bytes; refusing to replace them"
done
[ "$secret" != "$pepper" ] || fail "AIS_SECRET and AIS_PASSWORD_PEPPER must be different values"

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

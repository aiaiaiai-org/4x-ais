<!-- © 2026 aiaiaiai · aiaiaiai.org -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Runtime: configuration and the host-owned secrets

The service reads its whole configuration from the environment at start and
refuses to start when a setting is missing or unsafe.

## Who holds what

- **This repository defines every setting** and ships
  `deploy/prepare-runtime-env.sh`, the one script that builds the runtime
  environment.
- **The host generates the secrets.** Infra copies that script next to the
  workload and runs it on the server before the container starts. The three
  secrets below are born there, once, and kept in a private file only the host
  reads. No GitHub Environment holds them, no sealed envelope carries them, and
  no repository, image or log sees them.
- **Infra only carries and runs.** `aiaiaiai-org/infra` owns access to the
  servers; it never generates, stores or edits a value.
- **The runtime file is rewritten whole on every deploy** from the three kept
  secrets and the settings in the script. A key added to the host's copy by
  hand is dropped on the next deploy: a setting belongs in the script, where it
  is reviewed.
- **They are generated once and never replaced.** The script generates only
  when the runtime file does not exist, and only while the data volume does
  not either. A rerun, as on every deploy, changes none of the three. If the
  file exists but one of them is missing, empty or malformed, or the file is
  gone while the volume survives, the deploy stops instead of minting a new
  value, because a new value is damage, not a fix (below).

## Settings

| Name                  | Secret | Meaning                                                                                                                                       |
| --------------------- | ------ | --------------------------------------------------------------------------------------------------------------------------------------------- |
| `AIS_ISSUER`          | no     | The https origin, `https://auth.aiaiaiai.org`. Becomes `iss`, and the page answers only on this host.                                         |
| `AIS_SIGNING_KEY`     | yes    | Base64url 32-byte Ed25519 seed that signs every `id_token`. Its public half is served at `/.well-known/jwks.json`.                            |
| `AIS_SECRET`          | yes    | At least 32 bytes. Derives the pairwise-subject key and the key that seals form fields and cookies. Rotating it rotates every client's `sub`. |
| `AIS_PASSWORD_PEPPER` | yes    | At least 32 bytes, the Argon2id secret. Rotating it invalidates every password.                                                               |
| `AIS_CLIENTS`         | no     | JSON array of registered clients (below).                                                                                                     |
| `AIS_DATABASE_URL`    | no     | Default `sqlite:///data/ais.db`, on the workload's volume.                                                                                    |
| `AIS_BIND`            | no     | Default `0.0.0.0:1927`.                                                                                                                       |

`AIS_SECRET` and `AIS_PASSWORD_PEPPER` are independent values. They are
generated once and kept: a new `AIS_SECRET` changes every client's `sub`, a new
`AIS_PASSWORD_PEPPER` makes every stored password unusable, and a new
`AIS_SIGNING_KEY` invalidates every token in flight. **Nothing backs the file
up.** After the first deploy the owner copies it off the host once; it never
changes afterwards, so one copy is enough. Without it a lost file means a new
set of secrets and a service whose every identifier has changed.

## Clients

```json
[
  {
    "client_id": "nilx-one",
    "name": "0x1",
    "skin": "cell",
    "redirect_uris": ["https://nilx.one/api/v1/auth/aiaiaiai/callback"],
    "pub_dress": true
  }
]
```

- **`skin`** is presentation only. `cell` shows the whole prefix `0x0`–`0xf` as
  one choice; `slug` shows the name alone, and AIS assigns the prefix.
- **`pub_dress`** allows the client to ask for the address in the token.
- **`secret_sha256`** is optional. A client that has none is a **public
  client**: it holds no secret and names itself with `client_id` at `/token`.
  What binds its code to it is PKCE (S256, required of every client) and the
  exact redirect URI: a stolen code is useless without the verifier, which
  never leaves the client's own transaction. The 0x1 host is registered this
  way, so no secret is generated, stored or carried for it. A client that
  does hold a secret (lowercase hex SHA-256 of it; AIS never keeps the secret)
  must present it, and a public client that presents one is refused.
- **Redirect URIs** must match exactly and be https.
- **The registry lives in `deploy/prepare-runtime-env.sh`.** The clients are
  public configuration, so adding a product is a reviewed edit of that file.
  The test `host_env_tests.rs` runs the script and feeds what it writes to this
  service's own configuration parser.

## What the service does not do yet

- the one-time prefix change on first entry into a `cell` product;
- provider sign-in (Telegram, Discord, GitHub) and connected accounts;
- an issuer session across products: every product sign-in asks for the
  password, which a password manager fills;
- the change-event outbox.

Each comes as its own change.

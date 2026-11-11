<!-- © 2026 aiaiaiai · aiaiaiai.org -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Runtime: configuration and the secret envelope

The service reads its whole configuration from the environment at start and
refuses to start when a setting is missing or unsafe.

## Who holds what

- **This repository is the producer.** It defines every setting below and
  produces the secret values.
- **Infra only carries them.** `aiaiaiai-org/infra` owns access to the
  servers. It receives the sealed envelope from the producer that publishes the
  image, and hands it to the workload unopened. It never generates, stores or
  edits a value.
- No value lives in a repository, an image or a log.

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
generated once and kept: a new value logs everyone out of every product and
makes every stored password unusable.

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

## What the service does not do yet

- the one-time prefix change on first entry into a `cell` product;
- provider sign-in (Telegram, Discord, GitHub) and connected accounts;
- an issuer session across products: every product sign-in asks for the
  password, which a password manager fills;
- the change-event outbox.

Each comes as its own change.

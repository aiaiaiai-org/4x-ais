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
    "client_id": "0x1",
    "name": "0x1",
    "skin": "cell",
    "redirect_uris": [
      "https://nilx.one/api/v1/auth/aiaiaiai/callback",
      "https://nilx.one/api/v1/telegram/login/callback"
    ],
    "pub_dress": true,
    "telegram_binding_redirect_uri": "https://nilx.one/api/v1/telegram/login/callback"
  }
]
```

- **`skin`** is presentation only. `cell` shows the whole prefix `0x0`–`0xf` as
  one choice; `slug` shows the name alone, and AIS assigns the prefix.
- **`pub_dress`** allows the client to ask for the address in the token.
- **`telegram_binding_redirect_uri`** names the client's Telegram chat login,
  which must be one of its redirect URIs. Only an authorization request on
  exactly that redirect may ask for the scope `telegram_binding`, and it must
  send `telegram_binding_hint`. The hint is base64url (unpadded) of
  `SHA-256("ais-telegram-binding-hint-v1" 0x00 nonce 0x00 decimal-telegram-id)`
  for the account the client expects, here the sender of `/login`. The ID
  token then carries `"telegram_binding": true` if and only if the person's
  linked Telegram account is that account and the PKCE code exchange supplies
  the same `telegram_binding_hint` in the token request. Otherwise the claim
  is absent.

  What this guarantees: AIS discloses one bit about an account the client
  already named, never the linked account or anything derived from it. A
  request on any other redirect, or a client without the field, gets
  `invalid_scope`; a missing or malformed hint, or a hint without the scope,
  gets `invalid_request`. What it does not guarantee: the hint travels in the
  authorization URL next to the nonce, so anyone who sees that URL can test
  guesses of the account id against it. For a chat login, the URL goes to that
  account's own chat. No product key or client credential is involved: the
  claim rides in the ID token the client already verifies.
- **Telegram chat login page.** A request on `telegram_binding_redirect_uri`
  renders the page with Telegram's Mini App SDK and `/static/telegram.js`. No
  other page has script. When the page runs inside Telegram, the script copies
  `Telegram.WebApp.initData` into a hidden `telegram_init_data` field (at most
  4 KiB). AIS holds no bot token and cannot verify it. It only returns the
  value as `telegram_init_data` in the token response, never inside the ID
  token, and only to the client that redeems the code with its PKCE verifier.
  The client verifies it with its own bot token: it is the client's proof of
  which Telegram account signed in, used when AIS has no Telegram link yet.
  Outside Telegram the field stays empty and nothing is returned.
- **`secret_sha256`** is optional. A client that has none is a **public
  client**: it holds no secret and names itself with `client_id` at `/token`.
  What binds its code to it is PKCE (S256, required of every client) and the
  exact redirect URI: a stolen code is useless without the verifier, which
  never leaves the client's own transaction. The 0x1 host is registered this
  way, so no secret is generated, stored or carried for it. A client that
  does hold a secret (lowercase hex SHA-256 of it; AIS never keeps the secret)
  must present it, and a public client that presents one is refused.
- **Redirect URIs** must match exactly and be https. A product that only
  speaks to other products (Prism Hub) may have none.
- **`product`** makes the client a family product under `hub.v1`
  ([hub protocol](hub-protocol.md)): it may ask `/token` for a product token
  with `grant_type=client_credentials` and a `private_key_jwt` assertion.

  ```json
  "product": {
    "keys": [{ "kid": "m1", "x": "<base64url Ed25519 public key>" }],
    "tokens": { "prism-hub": ["hub.call", "hub.events"] },
    "relay": false
  }
  ```

  `keys` are one to four public keys by `kid`; two at once let a product
  rotate without a gap. The private keys never leave the products. `tokens`
  names the other registered products it may get a token for, and the scopes
  it may hold for each; nothing listed, nothing granted. `relay` (Prism Hub
  only) lets it name, as `actor`, the product whose request it carries; the
  token then holds `act.sub`. The audience `ais` is AIS itself: a relay with
  `"ais": ["pass.issue"]` may ask `POST /family/pass` for person passes;
  `accounts.put` and `link.read` open `POST /family/accounts` and
  `POST /family/link` (the family link). No client may be named `ais`.
- **The registry lives in `deploy/prepare-runtime-env.sh`.** The clients are
  public configuration, so adding a product is a reviewed edit of that file.
  The test `host_env_tests.rs` runs the script and feeds what it writes to this
  service's own configuration parser.

## What the service does not do yet

- the one-time prefix change on first entry into a `cell` product;
- provider sign-in (Telegram, Discord, GitHub) and connected accounts;
- an issuer session across products: every product sign-in asks for the
  password, which a password manager fills;
- the change-event outbox;
- `resolve` by provider evidence, subject translation for events and
  `identity.providers` (`hub.v1`).

Each comes as its own change.

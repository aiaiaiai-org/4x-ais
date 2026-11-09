<!-- © 2026 aiaiaiai · aiaiaiai.org -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# aiaiaiai AIS: the auth identity service

Status: first identity runtime implemented (sign-in, registration, both skins, OIDC issuer); not deployed.
Host: `auth.aiaiaiai.org` (edge-prod-2; activation pending).
Parent: [ECO-0001](https://github.com/aiaiaiai-org/.github/blob/main/ecosystem/identity/DESIGN.md),
and `nilx-one/web` `docs/unified-auth.md` and `docs/identity-boundary.md`.

## What exists today

Facts as of 2026-11-09. This repository now holds the identity runtime (`src/`, [runtime](runtime.md)): native sign-in and registration, the `cell` and `slug` skins, and the OIDC issuer whose tokens `nilx-one/core`'s client verifies. The `nilx-one/web` issuer below is the earlier implementation it replaces.

**`nilx-one/web`, `services/identity`** (the identity service that also runs
0x1 today):

- Native sign-in and registration: `pub_dress` + password, Argon2id, sessions,
  remembered Bond hint, rate limits (`api.rs`).
- Provider sign-in: Telegram (OIDC, PKCE), Discord, GitHub (identity only).
  Provider bindings and refusals (`browser_web_auth.rs`, Core's
  `provider_link`).
- The aiaiaiai issuer (`issuer.rs`, PR #593, merged): discovery, JWKS, a
  server-rendered `/authorize` (sign in or create), `/token`, EdDSA `id_token`s,
  pairwise `sub` per client. Contract 17.
- The 0x1 site's routes `/api/v1/auth/aiaiaiai/{config,start,callback}`. They
  only forward to Core's `SignInFlow`.
- Off until configured. Environment variables are not yet in
  `prepare-runtime-env.sh`.

**`nilx-one/core`**:

- `aiaiaiai_sign_in` (PRs #91, #92, merged): the 0x1 client of the issuer:
  `SignInFlow` (start, finish), `complete` (token exchange, JWKS, `id_token`
  verification, EdDSA only), and `resolve_aiaiaiai_account` with the
  `aiaiaiai_accounts` table (migration 0042).
- `client_pairwise_subject`: the per-client digest of the private subject.

**`aiaiaiai-org/infra`**: `auth.aiaiaiai.org` resolves to edge-prod-2, the
same address as `aiaiaiai.org` (DNS only). The route is on infra `master`
([infra#90](https://github.com/aiaiaiai-org/infra/pull/90) and
[infra#94](https://github.com/aiaiaiai-org/infra/pull/94)): workload `4x-ais`
on `aiaiaiai-edge`, port 1927, health `/healthz`. The edge skips the workload
while its container is absent. The workload has no automatic delivery yet: it
is added in its own infra change once this repository has published an
attested image and `aiaiaiai-org/infra` can read the package, because a tag
the planner cannot read or verify aborts delivery of every other workload on
the edge. Not deployed.

**`nilx-one/web` docs**: `unified-auth.md` (contract), `identity-boundary.md`
(the split: identity keeps people, 0x1 keeps the game, the seeds wallet moves
to 0x1, one admin role `gm`, a full wipe of existing users announced through
the Telegram bot).

**Not yet built**: the one-time prefix change, provider sign-in, the issuer
session, the event outbox, the wipe, and the 0x1 host switching to this issuer.

## What it owns

Only what makes a person one person across products:

- the public `pub_dress` (`0x` + one hex digit + slug) and its uniqueness;
- the native password (Argon2id with a pepper, the same policy as today);
- sessions, and the one-session-per-client rule (Single Active Client);
- provider bindings (Telegram, Discord, GitHub, later others);
- the OpenID Connect issuer: authorization code + PKCE (S256), pairwise `sub`
  per client, EdDSA `id_token`s, discovery and JWKS.

It owns no game state. Avaia, locations, seeds, xPing and businesses belong to 0x1
and stay there.

## Stack

Rust, axum, SQLite through sqlx, Argon2id, Ed25519 (`ed25519-dalek`). The same
choices as `services/identity` today, so the proven code (issuer, sessions,
rate limits, cookie signing, and the end-to-end tests) moves across rather than
being rewritten.

## Presentation: one flow, several skins

The security rules and the flow are the same for every client. A client differs
only in presentation, set by the server's client registry (ECO-0001 §4):

| Skin   | Who                                        | Header               | Prefix                                                           |
| ------ | ------------------------------------------ | -------------------- | ---------------------------------------------------------------- |
| `cell` | 0x-friendly products: 0x1, 0xda-market     | aiaiaiai AIS × 0x1   | the person sees and chooses the whole prefix, one of `0x0`–`0xf` |
| `slug` | serious clients: Prism, and other products | aiaiaiai AIS × Prism | never shown; the service assigns it                              |

The header names the product, as `aiaiaiai AIS × <product>`. The prefix is a
presentation choice only: the same `pub_dress` format and the same identity
underneath.

## Prefix rules

- Any hex digit `0`–`f` is valid, so there are sixteen prefixes, `0x0`–`0xf`.
- **The prefix is chosen as a whole.** The person picks one of the sixteen
  prefixes (`0x0`, `0x1`, …, `0xf`) as a single choice, not a fixed `0x`
  followed by a separate digit. The address grammar does not change
  (`0x` + one hex digit + slug); only what the person picks does. The same
  applies to the one-time change below: the offer lists whole prefixes.
- **`cell` products:** a new person picks the prefix and the slug.
- **`slug` products:** the service assigns the prefix. For now at random.
  Later it will derive a suggestion from the mailbox, for example
  `freezbylove@gmail.com` → `0xf` + `reezbylove`. That is a suggestion the
  person confirms, never an automatic choice (ECO-0001 §2).
- **One-time change:** on the first entry into a `cell` product, a person whose
  prefix was assigned sees the offer, **once**:

  > Ми підібрали вам `{prefix}`, виберіть інший, якщо цей не ок.

  The flag lives on the identity, not on a product, so it cannot be used again
  elsewhere. The English copy is written with the same meaning when the page
  is localized.
  - Assumption to confirm: a person who already chose a prefix in a `cell`
    product gets no second change.
  - A change keeps the identity and its `sub`; only the public address moves.

### Follow-up outside this repository

`packages/auth-view` in `nilx-one/web` still renders a fixed `0x` and a
separate digit selector (`.address-prefix`, `.digit-selector`). The 0x1 entry
point keeps that until the component is changed to a whole-prefix selector,
in its own change there. `static/auth.css` here skins the component as it is
today.

## Cross-service: no tunnel

The earlier plan assumed a tunnel between the servers. That was not needed. A
sign-in already uses public HTTPS: the browser goes to `auth.aiaiaiai.org`,
and Core calls `/token` and fetches JWKS over the same HTTPS. Cross-service
traffic is therefore:

1. **Sign-in:** the signed `id_token`, verified against cached JWKS. No call
   from 0x1 to the issuer per request.
2. **Back-office calls** (rare): OAuth `client_credentials` over HTTPS, with a
   client secret or a client-held key, scoped per client.
3. **Changes** (rename, prefix change, deletion, unlink): signed events. The
   issuer writes each event to an outbox in the same transaction as the change,
   and delivers it to the subscribed client with an HMAC over the body and a
   timestamp. Delivery is at least once; the receiver deduplicates by event id.
   Events carry only the pairwise `sub` of that client, never the private
   identifier.

Nothing about this needs new infrastructure. If event volume later justifies a
broker, NATS JetStream can replace the webhook without changing the events.

## Scope of the first release

1. The native flow: `pub_dress` + password, sign-in and registration, with the
   two skins.
2. The issuer endpoints, so 0x1 can use it as it does now.
3. The random prefix for `slug` products, and the one-time prefix change.
4. Events: `identity.created`, `identity.prefix_changed`, `identity.deleted`.

Not in the first release: passkeys, email sign-in, the mailbox suggestion,
provider connections beyond the ones already in `services/identity`, and any
game concept.

## Data

The new service starts with an empty database. Existing users are not migrated:
the owner has authorized a full wipe, announced to users through the Telegram
bot first (`docs/identity-boundary.md` in `nilx-one/web`).

## Repository conventions

- Branches: `feat/*`, `fix/*`, `docs/*`. No `claude/*` names.
- Gates: `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test`.
- Licensed under Apache-2.0 (`LICENSE`, `NOTICE`), as `4x-errors`. Every new
  file carries the copyright header and `SPDX-License-Identifier: Apache-2.0`.

## Open questions

1. Confirm the one-time prefix rule above, including the second-change case.
2. Confirm the stack choice (Rust, as above).
3. The name of the first `slug` product that integrates, to test the second skin.

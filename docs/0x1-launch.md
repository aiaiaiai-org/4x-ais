<!-- © 2026 aiaiaiai · aiaiaiai.org -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# AIS → 0x1: launch contract and acceptance

Status: integration in progress; not accepted as complete.
Evidence date: 2026-11-12. Scope: AIS and 0x1 only.
This page is the current launch-status entry point. Earlier “not deployed”
statements in design documents are historical, not current production evidence.

## What AIS means

**aiaiaiai Identity Service** is the identity authority shared by otherwise
independent products. `4x-ais` is its repository name and workload name;
`auth.aiaiaiai.org` is its public HTTPS origin and OIDC issuer.
Authentication proves identity. A product separately decides what that identity
may do, stores its own state and issues its own session.

A Bond is a 0x1 product identity. Avaia, XP, positions, wallets, subscriptions,
businesses and game permissions remain 0x1 responsibilities. AIS can record an
authorized product-account link; it does not become the owner of that account's
contents. Matching `pub_dress` never proves ownership of an existing Bond.

## Verified baseline

Source revisions inspected:

| Repository | Revision | Relevant source |
| --- | --- | --- |
| `4x-ais` | `065853c35047d4e3203389d3b7aefd22dab76586` | `src/issuer.rs`, `src/page.rs`, `deploy/prepare-runtime-env.sh` |
| `nilx-one/core` | `85031293ef9576b430e5d66b782dc69162df8234` | `aiaiaiai_sign_in`, `public_info`, `docs/ais-public-info.md` |
| `nilx-one/web` | `039f585670e19217f0e46121a9cd89a6e150e9df` | `services/identity/src/product_sign_in.rs`, `main.rs` |

These are inspected source revisions, **not verified deployed image digests**.
Public probes did not submit credentials, create an account, migrate data or
activate a release. No cookies, authorization codes or transaction values are
recorded here.

| Public check | Observed result | What it proves |
| --- | --- | --- |
| AIS `/healthz` | `ok` | Public workload health responds |
| AIS `/.well-known/openid-configuration` | Issuer `https://auth.aiaiaiai.org`, code grant, S256, EdDSA, pairwise subjects | Public discovery is present |
| AIS `/` | HTTP 200, “Sign in from a product” | Landing exists; general account sign-in is not implemented by this page |
| 0x1 `/api/v1/auth/aiaiaiai/config` | `enabled: true`, AIS issuer | Host configuration is enabled |
| 0x1 `/api/v1/auth/aiaiaiai/start?return=%2F` | HTTP 303 to AIS `/authorize` | Start adapter constructs the OIDC transaction |
| Redirect parameters | `client_id=nilx-one`, exact 0x1 callback, `openid pub_dress`, S256, state and nonce | Current public client contract |
| Transaction cookie | Secure, HttpOnly, SameSite=Lax, Path=/, 900 seconds | Browser transaction cookie is issued |
| Following the authorization redirect | HTTP 200, product-specific form for 0x1 | AIS accepts the initial request |

No successful credential submission, code exchange, authenticated product
session, game access, logout or existing-Bond preservation was verified by
these probes. Discovery availability alone does not prove JWKS/token exchange.

## Two entry points

- **General AIS:** `/` without a product should provide the general service
  entry. Current code is a landing page only; a genuine issuer account/session
  flow remains work. Do not silently choose a product for this entry.
- **Product sign-in:** the product starts a transaction and sends the browser
  to `/authorize` with `client_id`, exact registered `redirect_uri`,
  `response_type=code`, scopes, state, nonce and an S256 challenge. A bare
  `/authorize?client_id=0x1` is an illustration of context, not a working login
  link. The registry chooses presentation; query parameters cannot confer
  identity, privilege or permission to redirect elsewhere.

## End-to-end ownership

1. 0x1 starts the transaction through Core's `SignInFlow`, storing the signed
   transaction cookie and a validated same-origin return path.
2. The browser enters credentials on AIS. AIS checks credentials or registers
   an identity, binds a short-lived code to the client, callback and PKCE.
3. The browser returns to
   `https://nilx.one/api/v1/auth/aiaiaiai/callback`.
4. Core verifies the transaction/state, exchanges the code at AIS `/token`,
   obtains JWKS and verifies EdDSA, issuer, audience, nonce and token times.
5. `PublicInfoService` resolves or creates a 0x1 profile using verified
   `(issuer, pairwise sub)`. `pub_dress` is a display snapshot, never a lookup
   that attaches someone else's Bond.
6. Web issues `__Host-0x1_product`; product endpoints restore the server-side
   session binding. The browser never supplies an authoritative profile object.
7. Game access must resolve the intended Bond and enforce product permissions.
   This final step must be demonstrated; a newly created profile alone does
   not prove existing game state is accessible.

The product cookie is deliberately distinct from legacy
`__Host-0x1_session`. Do not mint a native session by matching a public name.
The current product adapter exposes session, sign-out, public-profile and
experience endpoints. It does not establish that every legacy game endpoint
accepts the product session.

OIDC sign-in, discovery, code exchange and JWKS remain direct HTTPS to AIS.
Peer-service domain requests use Prism Hub, as [hub-protocol.md](hub-protocol.md)
specifies. Hub must not retain identity payloads. Completing this browser
integration does not require implementing every future Hub operation.

## Identifier transition: do not break existing bindings

The 2026-11-11 target is `client_id=0x1`. The inspected AIS registry, Core
allowlist, Web client constructor and observed live redirect still use
`nilx-one`. This is an outstanding coordinated change, not a completed rename.

Pairwise subjects depend on the client id. Before changing it, establish whether
AIS has issued subjects or 0x1 has persisted profiles/bindings. The earlier
assumption that AIS is not live cannot justify an empty-database transition.
Then choose and test a compatibility/migration strategy, update all three
components and their tests together, and validate existing identity continuity.
Never silently recreate a profile, attach by name or discard data to make a
renamed client appear to work. Keep the current identifier until that transition
is reviewed and activation is authorized.

## Existing Bonds

The current tracked migration work is:

- [Core #116](https://github.com/nilx-one/core/pull/116): open draft migration
  contract; not an implementation or accepted migration.
- [Core #115](https://github.com/nilx-one/core/issues/115): proof-bound migration
  implementation, dependent on the contract.
- [Web #621](https://github.com/nilx-one/web/issues/621): thin migration flow,
  gated off by default, dependent on Core.

Migration must prove control of both the legacy Bond and AIS identity, bind the
confirmation to a short-lived transaction, and preserve Bond identity, XP,
Avaia, subscriptions, roles and wallet ownership. Conflicts, concurrent attempts,
replay and partial failure must not attach or overwrite another account.

Earlier wipe prose is **not an instruction to delete production data**.
Resolve the tracked migration contract before dependent implementation; do not
close migration tasks on the strength of a new-profile sign-in test. Any wipe
would require its own explicit decision and authorization.

## Remaining work and closure gates

| Work | Owner | Closure evidence |
| --- | --- | --- |
| General AIS entry | AIS | A usable non-product account flow with defined session/logout behavior |
| Client-id transition | AIS + Core + Web | Coordinated contract and tests; existing issued identities accounted for |
| Existing-Bond attachment | Core + Web | Accepted migration contract, implementation and preservation/conflict tests |
| Browser and game integration | Web + Core | User-visible entry, callback recovery, session restore, private game access and logout |
| Runtime reproducibility | AIS + Web + Infra | Reviewed configuration reproduces the verified public behavior; deployed digests recorded |
| Launch acceptance | All three code owners + Infra | Exact-head CI, deploy validation, authorized activation and observed E2E evidence |

Native browser sign-in and provider/Mini App sign-in are different acceptance
paths. AIS provider sign-in is listed as unimplemented in runtime documentation;
working legacy Telegram authentication must not be reported as AIS integration.
Keep provider migration visible if “0x1 connected” includes the Telegram host.

Acceptance must record environment, revisions/image digests, date, scenario and
result, without credentials or tokens:

- New native user: register at AIS, return to 0x1, restore the same profile
  after refresh and access the intended protected product surface.
- Returning user: same identity resolves the same account, without duplicates.
- Existing Bond: both proofs attach the correct Bond; its state is preserved;
  conflicts and retries cannot attach by public name.
- Security failures: bad state/nonce, expired or replayed code, wrong audience,
  wrong PKCE, foreign return URL and unavailable AIS fail without opening a
  session or changing an account. Cancellation permits a fresh attempt.
- Product session: private access rejects unauthenticated/expired sessions;
  sign-out revokes the session; mutations enforce CSRF.
- Identity continuity: rename does not change product ownership; client-id
  transition does not orphan bindings; deletion/revocation behavior is explicit
  and tested rather than inferred from a successful login.
- Telegram/Mini App: separately verify provider identity and return/session
  behavior before claiming this host has moved to AIS.

Completion requires the applicable rows above, not merely HTTP health or a
merged PR. This documentation change does not rename the client, activate
migration, alter live settings, merge, deploy or authorize destructive work.

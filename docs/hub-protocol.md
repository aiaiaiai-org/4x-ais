<!-- © 2026 aiaiaiai · aiaiaiai.org -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# AIS in `hub.v1`

Status: product tokens built; the rest proposed. Not deployed.
The protocol itself lives in Prism Hub, which orchestrates the family:
[`aiaiaiai-org/prism-hub` `docs/hub-protocol.md`](https://github.com/aiaiaiai-org/prism-hub/blob/master/docs/hub-protocol.md).
This page is only what AIS owes it.

## Peer-service routing (owner decision, 2026-11-12)

AIS is a peer service behind Prism Hub, not a gateway above it. All
cross-service AIS operations are addressed by logical service ID and routed
through Hub, including requests *to* AIS and AIS-originated events. Callers
know Hub's endpoint, not AIS's internal endpoint; Hub knows the route.
The front door below is the one exception.
AIS remains the sole identity authority and performs its own domain-level
authorization. Hub authenticates callers and checks target/operation grants.

Example: `0xda-market → Hub → AIS → Hub → 0xda-market` for
`identity.providers.list`. AIS returns only the provider names/status
authorized for the requesting product and Bond; it must not disclose
credentials, provider tokens, or arbitrary bindings. A verified person
context and explicit scope are required; a bare `pub_dress` or Telegram
ID is insufficient.

Hub must not durably store requests, responses, signed provider evidence,
passes or event payloads. Only transient in-memory relay and minimal
non-sensitive routing/correlation metadata are permitted. Durable retries
use AIS's own identity outbox; Hub retries or routes a source-owned reference,
never a retained copy. An unavailable target yields an explicit failure.

## The front door stays direct

Three things are served at AIS's public address, `https://auth.aiaiaiai.org`,
and never through Hub:

1. **The sign-in page**, opened by the person's browser.
2. **Discovery, the code exchange at `/token`, and JWKS.** A token names its
   issuer's own address, and a client fetches the keys from that address.
   This is the contract `nilx-one/core` `aiaiaiai_sign_in` verifies today;
   `hub.v1` does not change it.
3. **Product tokens** (`client_credentials` at `/token`): a product needs one
   before it can speak to Hub, and Hub needs the JWKS to check it.

So a Hub outage never blocks a sign-in. Everything else below is a routed
operation and answers only to Hub.

## What AIS does in the family

AIS stays the identity: people, `pub_dress`, password, sessions, provider
bindings, pairwise `sub`. It holds no money, items or product state, and it
does not route requests between products; the hub does.

On top of sign-in ([service design](service-design.md)) it adds:

1. **Product tokens** (built, [runtime](runtime.md#clients)).
   `client_credentials` with `private_key_jwt`: each product signs its
   assertion (`iss` = `sub` = its `client_id`, `aud` the issuer or its
   `/token`, `exp` ≤ 5 minutes, a single-use `jti`) with its own Ed25519 key.
   AIS holds the public keys in the registry, inline, so it fetches nothing
   to check them; a product rotates by registering a second key first. The
   request names `audience` (another registered product) and may narrow
   `scope`. The answer is an EdDSA JWT, `typ` `at+jwt`, `sub` the product,
   `aud` the audience, `scope`, `exp` 5 minutes, signed with the key AIS
   publishes in its JWKS. A relay (Prism Hub) may add `actor`, which becomes
   `act.sub`. No shared secrets: a secret is refused on this grant.
2. **Person passes** (built, by the asker's own `sub`). A short JWT that
   says "for this one operation, this person is product B's `sub` X":
   `typ` `pass+jwt`, `aud` B, `sub` B's pairwise subject, `azp` the asker, a
   `purpose` (`claims` or `order:<id>`), `exp` 15 minutes, a `jti`. Only a
   relay (Prism Hub) asks, at `POST /family/pass`, with an AIS product token
   for the audience `ais` holding `pass.issue` and naming the asking product
   as `actor`. The body is `{subject, audience, purpose}`: the asker names the
   person by its own pairwise `sub`, and AIS answers only for a person it gave
   the asker that subject (`unknown_subject` otherwise). To find the person
   again, AIS keeps `issued_subjects`: client id, pairwise `sub`, person;
   nothing else. It fills it at every sign-in and for every pass it issues, so
   B can later name the person back by the `sub` the pass gave it. The pass
   goes back to the asker, which keeps it with its order. Naming the person by
   fresh provider evidence comes with provider bindings. No consent screen: confirming the
   purchase is consent (owner decision, 2026-11-11).
3. **The family link** (built, by the asker's own `sub`; owner decision 8 in
   the hub protocol). AIS keeps which account a person holds in each product
   (`family_links`: person, product, account, its `pub_dress`, `as_of`), and
   nothing about the account itself. Seeds and every other account fact stay
   with the product (decision 9).
   - `POST /family/accounts` (`accounts.put`, scope `accounts.put`): a product
     reports `{subject, account, pub_dress, as_of}` for a person it names by
     its own `sub`. The account always belongs to the reporting product. A
     report older than the one AIS holds is answered `stale` and changes
     nothing; an account already linked to another person is `account_taken`.
   - `POST /family/link` (`people.link`, scope `link.read`): a product asks
     `{subject, product}` and gets `{sub, accounts: {<product>: {account,
     pub_dress, as_of}}}`, or `unknown`. The answer names the account, never
     the other product's pairwise subject. For 0x1 the account is the Bond.
   Naming the person by fresh Telegram evidence instead of a `sub` comes with
   Telegram bindings.
4. **Subject translation for events.** The hub asks AIS to turn one product's
   `sub` into another's when it fans an event out; the answer is used once and
   not stored by the hub.
5. **`identity.providers`.** For a person named by a pass, the names and
   status of bound providers the asking product may see. Never credentials,
   provider tokens or other bindings.
6. **The AIS-owned identity outbox** (first-release scope): `identity.created`,
   `identity.prefix_changed`, `identity.deleted`, delivered to the hub.

## Authority verification and BondChain boundary (proposed)

**One AIS, no second authority service.** Authority and delegation verification
are responsibilities to develop within `4x-ais`, using its existing identity
and family-link boundaries. They are **not** a deployed generalized Bond
signing/authorization API merely because the existing product tokens and
person passes work.

AIS MAY issue narrowly scoped, signed attestations about a verified identity's
Bond-key binding, authorized active signing device or delegated Business Bond
representative **only after** the corresponding product and business authority
contracts define their source of truth, key lifecycle, subject binding, issuer,
audience, operation, key epoch, expiry, revocation and replay behavior.
Such attestations MUST NOT independently grant authority that the owning
product or Bond contract has not established. AIS remains a source of identity
evidence; it cannot infer a Bond's cryptographic signing key from Telegram
`initData`, an OIDC session or a product token.

The distinctions are deliberate:

- **Authentication:** which person/product authenticated in the AIS scope.
- **Authorization/authority:** which product operation or Bond-representative
  capacity is valid for the exact subject, under the owning contract.
- **Commitment:** an authorized Bond (or valid Business Bond representative)
  signs an exact canonical Interaction action using the permitted signer.
- **Completion:** each participating `nilx-one/core` independently verifies
  the contract-required reciprocal actions and result evidence. No AIS
  `close` endpoint, central Chain signature or operator-owned relationship
  history is permitted.

AIS MUST NOT custody human `sk_bond`, generate a missing counterparty
signature, sign a terminal `bond.chain` in place of either Bond, or treat
a product's `verified` claim as proof of human consent. A BBond service's
product token proves its service identity, **not** representative authority.

AIS generally needs the minimum operation, subject, audience, authority
metadata and canonical action digest necessary to evaluate a specifically
defined authority contract. A complete Intent body, private counterpart
payload or full pairwise Chain MUST NOT be retained as an identity artifact.
An attestation MAY be reused only within its exact audience, purpose and
validity limits; it MUST NOT become an unrestricted cross-product pass.

Under the current `hub.v1` topology, product tokens and OIDC bootstrap
still come directly from AIS. Ordinary product queries for additional
identity/authority evidence MUST be routed through Prism transit using
a product token and specific target/operation grants. Transit MUST verify
AIS issuer signatures locally where the token contract permits; it MUST NOT
accept a literal `verified: true` field as a substitute. No general
per-Interaction request to AIS is required merely to validate an
already-verifiable, in-scope attestation.

This contract boundary does **not** enable new Bond-key registration,
delegated business signing, automatic purchase completion, or any new
production endpoint. Their exact schemas and enforcement remain explicit
future implementation work in the respective owning contracts.

## One identifier per product

The 0x1 client is registered as `0x1`, the same identifier the orders already
use as issuer, instead of `nilx-one` (owner decision, 2026-11-11). The
`client_id` grammar already allows it. The pairwise `sub` depends on the
`client_id`, so the rename must happen before AIS goes live and before the
legacy Bond migration (`nilx-one/core#116`) is activated: that migration
stores `(iss, pairwise sub)` against an existing Bond, and a later rename
would orphan every such binding. Nobody signed in through `nilx-one`, so it
was retired without a migration (owner decision, 2026-11-22): the registry in
`deploy/prepare-runtime-env.sh` names only `0x1`, and `nilx-one/core` accepts
only `0x1`.

## Telegram Special purchase authorization

Two operations use the existing product signing keys and the Hub relay. The
product token for Hub and the relay token for AIS must both carry the scope
for the operation. The runtime registry must grant these scopes explicitly.

- `POST /family/telegram-link` (`telegram.link.put`): 0x1 reports a verified
  Telegram binding as `{subject, telegram_id, revision}` using its AIS pairwise
  subject. The revision must increase for that person. Send an explicit
  `null` Telegram ID when the link is removed. AIS keeps the last revision
  after removal, rejects older reports and prevents a Telegram account from
  being bound to two people. Market has no binding write access.
- `POST /family/telegram-purchase` (`telegram.special.purchase`): the
  authenticated product supplies the confirmed
  `{telegram_id, order_id, sku, quantity, price_id, amount_minor}`. AIS
  resolves the person and checks that they have a linked 0x1 account. This
  endpoint accepts one `0x1_special_1m` in seeds. It returns a two-minute
  `purchase+jwt` signed by AIS, addressed to 0x1, with its pairwise subject,
  Telegram ID, requesting product and the exact confirmed order terms.

A permit identifies the buyer and authorizes submission of these terms. It
does not attest a price, balance, or completed payment. The receiving 0x1
operation must verify the signature, issuer, audience, expiry, product and
current Telegram binding, validate the price revision against the authoritative
offer, and atomically settle the wallet and subscription. It must persist one
result per requesting product and order ID, reject mismatched retries and
return the original result for identical retries. The bot must only report a
completed purchase after that result comes back.

The wallet order key is not the raw `order_id`. AIS accepts a product-local ID
of 1 to 128 bytes, while 0x1 settlement accepts 8 to 128 bytes and deduplicates
on one ID. 0x1 must derive a bounded key from the verified `azp` and `order_id`
under a checkout namespace, so short and maximum-length IDs both settle and the
same local ID from two products cannot collide. Permits name audience `0x1` in
every environment, so the receiver must pin its own environment's AIS issuer,
signing keys and authorized product identities. A development permit must be
rejected by production settlement.

Trust boundary: AIS does not check that the Telegram user is present. It trusts
the `telegram_id` the requesting product asserts, under that product's key and
explicit grant. A compromised product key can obtain permits for any linked
Telegram account, limited to this SKU. The limits are enforced by 0x1: the
price check against the authoritative offer, one result per requesting product
and order ID, and the current binding check.

Both endpoints fail closed until the registry carries the grants above:
today's production `0x1` client has no product block, so calls answer 401 or
`bond_unlinked`. The grants are a precondition for enabling checkout.

Development must use its own product grants, issuer and wallet. These endpoints
alone do not deliver Telegram link reports, relay the purchase to 0x1, or
activate checkout in any environment.

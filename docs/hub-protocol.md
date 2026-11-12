<!-- © 2026 aiaiaiai · aiaiaiai.org -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# AIS in `hub.v1`

Status: proposed. Not built.
The protocol itself lives in Prism Hub, which orchestrates the family:
[`aiaiaiai-org/prism-hub` `docs/hub-protocol.md`](https://github.com/aiaiaiai-org/prism-hub/blob/master/docs/hub-protocol.md).
This page is only what AIS owes it.

## Peer-service routing (owner decision, 2026-11-12)

AIS is a peer service behind Prism Hub, not a gateway above it. All
cross-service AIS operations are addressed by logical service ID and routed
through Hub, including requests *to* AIS and AIS-originated events. Callers
know Hub's endpoint, not AIS's internal endpoint; Hub knows the route.
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

## What AIS does in the family

AIS stays the identity: people, `pub_dress`, password, sessions, provider
bindings, pairwise `sub`. It holds no money, items or product state, and it
does not route requests between products; the hub does.

On top of sign-in ([service design](service-design.md)) it adds:

1. **Product tokens.** `client_credentials` with `private_key_jwt`: each
   product signs its assertion with its own Ed25519 key, published at a
   registered `jwks_uri`. The token is an EdDSA JWT, `aud` the product being
   called (usually `prism-hub`), `exp` ≤ 5 minutes. No shared secrets.
2. **Person passes.** A short JWT that says "for this one operation, this
   person is product B's `sub` X", with `aud` B, `azp` the asker, a `purpose`,
   `exp` 15 minutes and a single-use `jti`. Only the hub may ask for one, on
   behalf of a product whose grant allows it. No consent screen: confirming the
   purchase is consent (owner decision, 2026-11-11).
3. **Resolve.** Given fresh signed provider evidence (Telegram `initData` or a
   Telegram login payload, never a bare id), answer `unknown` or the asker's
   pairwise `sub` and, when asked, a pass. AIS never says more than that.
4. **Subject translation for events.** The hub asks AIS to turn one product's
   `sub` into another's when it fans an event out; the answer is used once and
   not stored by the hub.
5. **The AIS-owned identity outbox** (first-release scope): `identity.created`,
   `identity.prefix_changed`, `identity.deleted`, delivered to the hub.

## One identifier per product

The 0x1 client is registered as `0x1`, the same identifier the orders already
use as issuer, instead of `nilx-one` (owner decision, 2026-11-11). The
`client_id` grammar already allows it. The pairwise `sub` depends on the
`client_id`, so the rename must happen before AIS goes live: today it is not
deployed and existing users are wiped, so nothing live moves. The rename is its
own change here, in `deploy/prepare-runtime-env.sh`, and in `nilx-one/core`'s
client configuration, together.

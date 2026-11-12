<!-- © 2026 aiaiaiai · aiaiaiai.org -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# 4x-ais — aiaiaiai Identity Service

**4x-ais** is the shared **aiaiaiai Identity Service** for the aiaiaiai ecosystem.
It serves the common sign-in and registration experience at
[`auth.aiaiaiai.org`](https://auth.aiaiaiai.org) and issues identities to
registered product clients. **AIS means _aiaiaiai Identity Service_, not
“Authorization Identity Service.”**

## Sign-in and product context

| Entry point | Purpose |
| --- | --- |
| `https://auth.aiaiaiai.org/` | General AIS sign-in, without a product context (target behavior) |
| `/authorize?client_id=nilx-one` | 0x1-specific client context |
| `/authorize?client_id=0xda-market` | 0xda-market-specific client context |
| `/authorize?client_id=prism-hub` | Prism Hub context **only if** it needs an interactive user sign-in |

The root route must not implicitly select any product. Until the general AIS\nsign-in page is available, the currently specified temporary behavior for\n`GET /` is **HTTP 301** redirecting to `https://aiaiaiai.org/`. This\nredirect is not the final sign-in UX; because 301 may be cached, reassess\nits permanence before rollout. The redirect is a stated requirement, not\na live HTTP verification or evidence of deployment.\n\nThese are **illustrative client identifiers and entry points**, not a claim
that all three clients are registered or enabled in the current runtime.
The client registry determines which `client_id` values are valid and which
presentation skin applies. A product-specific presentation does **not**
create a separate person or identity database.

The table abbreviates the authorization URL for readability. A real
OpenID Connect authorization request also needs the registered
`redirect_uri`, `response_type=code`, `scope=openid`, `state`,
`code_challenge` and `code_challenge_method=S256` (and `nonce` when
required by the client). Never treat an arbitrary `client_id` or
`redirect_uri` supplied in the query as trusted: validate both against
the server-side client registry.

## Service boundaries

- **4x-ais owns identity:** `pub_dress`, native credentials, identity
  sessions, provider bindings and the OIDC issuer. It authenticates the
  person and issues client-scoped, pairwise subjects.
- **Product services own product policy and state:** 0x1, 0xda-market,
  Prism and future clients implement their own domain permissions and data.
  Client scopes and grants do not replace product-level authorization.
- **Prism Hub orchestrates service-to-service communication:** it routes
  requests between services, including identity queries, without retaining
  the routed payload. A normal relay request does not require Prism Hub
  to initiate an interactive user sign-in.
- **Browser-based OIDC sign-in is distinct from service-to-service calls:**
  the browser redirects to the issuer; the client exchanges the code and
  verifies the signed token. The hub's orchestration contract governs
  service-to-service integration and does not imply routing every browser
  redirect through the hub.

## Current implementation and status

This is a Rust service (axum, SQLite) with native sign-in and registration,
`cell` and `slug` presentation skins, and an OpenID Connect issuer
(authorization code + PKCE, pairwise `sub`, EdDSA `id_token`).
The 0x1 integration contract is verified by `nilx-one/core`'s
`aiaiaiai_sign_in` client. See [service design](docs/service-design.md)
for implemented versus planned capabilities, including the client registry
and provider integration.

Configuration and host-owned secrets are described in
[runtime documentation](docs/runtime.md); the hub relationship is described
in [hub protocol](docs/hub-protocol.md).

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
bash scripts/smoke.sh
```

`.github/workflows/publish.yml` publishes
`ghcr.io/aiaiaiai-org/4x-ais:<commit>` from public `master` and attests it.
While the repository is private, it stops before the push.
`auth.aiaiaiai.org` is configured to route to the `4x-ais` workload
on edge-prod-2 (`aiaiaiai-org/infra`); deployment is not yet verified.

Licensed under Apache-2.0 (`LICENSE`, `NOTICE`).

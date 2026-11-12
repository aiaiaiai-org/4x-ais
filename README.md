<!-- © 2026 aiaiaiai · aiaiaiai.org -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# aiaiaiai Identity Service (AIS)

**AIS is the shared identity authority for aiaiaiai products.** This repository,
`aiaiaiai-org/4x-ais`, implements it at <https://auth.aiaiaiai.org>.
The name means **aiaiaiai Identity Service**. A person authenticates with AIS;
each product owns its own account, sessions, permissions and product data.

The immediate delivery scope is **launch AIS and complete 0x1 integration**.
Start with [the 0x1 launch contract](docs/0x1-launch.md): it records verified
behavior, ownership, the browser flow, remaining blockers and acceptance checks.
It distinguishes implemented code, observed public behavior and unverified E2E.

## Responsibilities

| Component | Responsibility |
| --- | --- |
| AIS (`4x-ais`) | Identity, unique `pub_dress`, native credentials, OIDC issuer; provider bindings and issuer sessions remain planned capabilities |
| 0x1 Core (`nilx-one/core`) | Verify AIS tokens, resolve the product profile by `(iss, sub)`, own Bond/game behavior and migration rules |
| 0x1 Web (`nilx-one/web`) | Browser entry, callback, product-session cookies, HTTP/CSRF handling and UI |
| Infra (`aiaiaiai-org/infra`) | Deliver verified artifacts and route public HTTPS to the workloads |
| Prism Hub | Route authorized peer-service operations; it is not in the browser OIDC sign-in path |

AIS holds no XP, Avaia, seeds, subscriptions or game roles. `pub_dress` is a
public name, not proof that someone owns an existing Bond. Products receive
client-specific pairwise subjects, never AIS's private identity identifier.

## Current state

Public checks on **2026-11-12** found AIS health/discovery available and the
0x1 AIS sign-in configuration enabled. Starting sign-in on 0x1 redirects to
AIS and renders its product-specific form. **This is not proof of a successful
credential-to-game E2E flow or preservation of an existing Bond.**

The live OIDC `client_id` is still `nilx-one`; the agreed target name `0x1`
requires a coordinated transition because it changes pairwise subjects.
Do not rename it as a cosmetic configuration edit.

`https://auth.aiaiaiai.org/` is the intended general AIS entry without product
context. Today it renders “Sign in from a product”, not a general account
session. `/authorize` is the product-context flow and requires the complete
OIDC request, not merely `?client_id=...`.

## Read next

- [0x1 launch and acceptance](docs/0x1-launch.md): current delivery contract.
- [Service design](docs/service-design.md): identity behavior and earlier design.
- [Runtime](docs/runtime.md): settings, client registry and host-owned secrets.
- [Hub protocol](docs/hub-protocol.md): peer-service routing and OIDC exception.

## Development

Rust, axum, SQLite, Argon2id and Ed25519. AIS tests exercise the Core token
verifier. Run the repository gates:

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
bash scripts/smoke.sh
```

`.github/workflows/publish.yml` publishes and attests the service image from
public `master`; it stops before publishing while the repository is private.
Infra owns activation on edge-prod-2. 0x1 workloads stay on edge-prod-1.
Merge and deployment are separate, explicitly authorized actions.

Licensed under Apache-2.0 (`LICENSE`, `NOTICE`).

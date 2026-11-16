<!-- © 2026 aiaiaiai · aiaiaiai.org -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# 4x-ais

The aiaiaiai auth identity service: the one sign-in page every product sends
people to, at `auth.aiaiaiai.org`. Scope and decisions are in
[docs/service-design.md](docs/service-design.md); configuration and the
host-owned secrets are in [docs/runtime.md](docs/runtime.md); its part in the
family protocol run by Prism Hub is in [docs/hub-protocol.md](docs/hub-protocol.md).

A Rust service (axum, SQLite). It owns people, their `pub_dress` and native
password, and the OpenID Connect issuer (code + PKCE, pairwise `sub`, EdDSA
`id_token`). It owns no product state.

The bare issuer origin `https://auth.aiaiaiai.org/` temporarily sends browsers
to `https://aiaiaiai.org/` with a fixed 301 response; a direct `/0x1`
visit shows the scoped 0x1 entry. Real sign-in always starts from the 0x1
host with state, nonce, exact callback and PKCE before continuing at AIS. 0x1 reaches it only through
`nilx-one/core`'s `aiaiaiai_sign_in` client; the token contract here is the
one that client verifies, and the tests run that verifier.

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
bash scripts/smoke.sh
```

`.github/workflows/publish.yml` publishes `ghcr.io/aiaiaiai-org/4x-ais:<commit>`
from public `master` and attests it. While the repository is private it stops
before the push. `auth.aiaiaiai.org` routes to the `4x-ais` workload on
edge-prod-2 (`aiaiaiai-org/infra`); it is not deployed.

Licensed under Apache-2.0 (`LICENSE`, `NOTICE`).

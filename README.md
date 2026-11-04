<!-- © 2026 aiaiaiai · aiaiaiai.org -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# 4x-ais

The aiaiaiai auth identity service. Scope and open questions are in
[docs/service-design.md](docs/service-design.md).

The identity service is not implemented. `server.py` is a temporary landing
page: `GET /`, `GET /healthz`, and `GET /static/auth.css`. It has no sign-in,
registration, session, or issuer. `.github/workflows/publish.yml` publishes
`ghcr.io/aiaiaiai-org/4x-ais:<commit>` from public `master` and attests that
image. A private repository on this org's plan cannot attest, so the workflow
does not push until the repository is public.

`auth.aiaiaiai.org` is on edge-prod-2 and is not activated. The route is
[aiaiaiai-org/infra#91](https://github.com/aiaiaiai-org/infra/pull/91).
[infra#90](https://github.com/aiaiaiai-org/infra/pull/90) is superseded.

Licensed under Apache-2.0 (`LICENSE`, `NOTICE`).

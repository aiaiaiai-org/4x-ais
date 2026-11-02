<!-- © 2026 aiaiaiai · aiaiaiai.org -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Future public address allocation and collision handling

Status: documented product decision; **not in the scope of PR #1 implementation**.
Related: [service design](service-design.md), section “Prefix rules”.

## Decision

When AIS proposes a public address (`pub_dress`), it must first try to find an
available address that satisfies the established address format and prefix
rules. If the preferred candidate is occupied, it should try other eligible
candidates before changing the readable slug.

If no suitable candidate is available, AIS may append a randomly generated
suffix to an otherwise suitable address, retrying until a unique valid
`pub_dress` can be allocated. The suffix must preserve the established
address grammar, length constraints and product-specific prefix rules.

Availability is not a reservation: final allocation must enforce uniqueness
atomically in storage. Concurrent registration collisions must trigger a
bounded retry rather than silently overwriting an existing identity.

## Boundaries

- Never rename an existing person's public address to resolve a new
  registration collision.
- Do not change the stable private subject or pairwise client subjects as a
  side effect of allocating or changing a public address.
- Keep prefix presentation differences between `cell` and `slug` clients.
- The one-time prefix-change policy remains a separate open question in the
  service design; this decision does not settle it.
- The exact candidate ordering, suffix alphabet/length, retry budget and
  exhaustion response belong to a later implementation contract and tests.

No runtime change, migration, account wipe, or deployment is authorized by
this document.

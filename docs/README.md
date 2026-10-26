<!-- SPDX-FileCopyrightText: 2026 Anonce Contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Documentation

Audience: readers choosing the appropriate project reference.

## Project status

**Implemented:** Git hooks, repository wording and identity inspection, commit grammar
checks, REUSE licensing, documentation checks, local Go HTTP infrastructure, and a
read-only web shell with race, lint, fuzz, delivery, and security checks described
in [testing](testing.md).
**Designed:** the application, cryptographic composition, product UI, database boundaries,
and release infrastructure. **Unavailable:** any live protocol, usable submission product,
screenshots, production deployment, or protocol security test results.

The references distinguish implemented infrastructure from the intended application.
Local process instructions are in [deployment](deployment.md#local-development).
Update the relevant topic directly when requirements change.

## Requirements coverage

The following scope is required for the baseline application, not optional work.
Detailed requirements live in the linked references. Implementation must include
the corresponding tests and operational evidence before a capability is claimed.

| Requirement | Owning reference | Required acceptance evidence |
| --- | --- | --- |
| Verified membership, local keys, certificate issuance and revocation | [Protocol](protocol.md#enrollment-and-authentication), [cryptography](cryptography.md#membership-and-authorization) | CSR, expiry, revocation, challenge replay, and atomic code-use tests |
| Protected signer and encrypted device backups | [Key management](key-management.md) | Signer authorization, bounded import, wrong-password rejection, native/WASM compatibility |
| Administrator-set response allowance per eligible member and round | [Protocol](protocol.md#round-response-limit), [database](database.md#privileges-and-transactions) | Validated immutable common limit; bounded concurrent issuance, reserved-slot recovery, and no token transcripts |
| One accepted ciphertext per token | [Database](database.md#privileges-and-transactions) | Concurrent spending, immutable payload binding, and crash/outbox recovery |
| Identity and submission isolation, with no identifying submission logs | [Architecture](architecture.md), [deployment](deployment.md#production-separation) | Real PostgreSQL grants, separate credentials, request capture, and infrastructure log inspection |
| Reviewed signatures, blind authorization, and authenticated encryption | [Cryptography](cryptography.md) | Standards vectors, malformed-input and cross-context rejection |
| Cohorts, forms, signed round lifecycle, thresholds, and retention policy | [Protocol](protocol.md), [UI design](ui-design.md) | Import, schema, schedule, bulletin substitution, and release-policy tests; response count is not distinct participant count |
| Role-scoped multifactor administration | [Architecture](architecture.md#administrative-access), [API](api.md#authentication-and-caching) | Role, session, CSRF, recovery, replay, and reauthentication tests |
| Local reviewer decryption, charts, and safe exports | [Protocol](protocol.md#review-and-replies), [UI design](ui-design.md) | No plaintext endpoint or upload; authorized round access and local export tests |
| Encrypted private replies and anonymous abuse controls | [Protocol](protocol.md#review-and-replies) | Capability, expiry, replay, cross-round authorization, and privacy tests |
| Inclusion receipts, consistency checking, and separate anchored audit events | [Cryptography](cryptography.md#encryption-and-public-proofs), [architecture](architecture.md#administrative-access) | Independent proof verification, split-view and audit-mutation tests |
| Controlled-copy retention and truthful destruction limits | [Key management](key-management.md#retention-and-destruction), [threat model](threat-model.md) | Copy inventory and restore tests; no guaranteed-erasure or threshold-confidentiality claim |
| Shared Go CLI/WASM, self-hosted assets, accessible responsive UI | [Architecture](architecture.md#client-and-server-contract), [UI design](ui-design.md) | Cross-client vectors, matching loader, keyboard/browser checks, no third-party requests |
| Portable local stack and real security validation | [Deployment](deployment.md), [testing](testing.md), [CI/CD](ci-cd.md) | Genuine Make targets, race/fuzz/database/browser checks, at least 24 independent dummy members |
| Open-source licensing, compatibility, and verifiable releases | [Dependencies](dependencies.md), [versioning](versioning.md), [releasing](releasing.md) | REUSE, reviewed public changes, signed artifacts, source, SBOM, provenance, and repeat-build hashes |

The [roadmap](roadmap.md) separates implementation priorities, optional extensions,
and unresolved design questions. Independent security review remains a prerequisite
for real use. Optional extensions must preserve the baseline boundaries.

Contribution rules: [AGENTS.md](../AGENTS.md) and [CONTRIBUTING.md](../CONTRIBUTING.md).

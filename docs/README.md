<!-- SPDX-FileCopyrightText: 2026 Anonce Contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Documentation

Audience: readers choosing the appropriate project reference.

## Project status

| Status | Scope |
| --- | --- |
| Implemented | Repository and documentation checks; local HTTP services and read-only shell; device-backup encryption, local member/reviewer keys, in-memory member sessions, offline key CLI, public-only WASM request verification, and a separate local member-session WASM bridge. See [testing](testing.md) |
| Designed | Browser-only account/review workflow and automatic encrypted key custody; application, cryptography, product UI, database boundaries, releases. Vault wrapping/recovery and browser compatibility remain unresolved |
| Unavailable | Working protocol/product, screenshots, production deployment, protocol security results |

[Run locally](deployment.md#local-development). Update requirements in their owning reference.

## Requirements coverage

All rows are required baseline scope. Before claiming a capability, implement it
and supply the [acceptance tests](testing.md#attack-simulation-matrix),
[security evidence](threat-model.md#required-security-evidence), and operational
evidence required by its reference.

| Requirement | Reference |
| --- | --- |
| Browser-only accounts, review links/dashboard, automatic key management; no required install or CLI | [User workflow](ui-design.md#account-and-review-workflow) |
| Encrypted member-key server backups, local unlocking, distinct account/key recovery | [Browser vault](key-management.md#browser-account-vault), [acceptance](testing.md#browser-account-and-vault-acceptance) |
| Membership, local keys, certificates, enrollment, revocation | [Protocol](protocol.md#enrollment-and-authentication) |
| Protected signer and encrypted device backups | [Key management](key-management.md) |
| Administrator-set per-member/round allowance | [Protocol](protocol.md#round-response-limit) |
| One accepted ciphertext per token; atomic quota/spending | [Database](database.md#privileges-and-transactions) |
| Identity/submission isolation; no identifying submission logs | [Architecture](architecture.md), [deployment](deployment.md#production-separation) |
| Reviewed signatures, blind tokens, authenticated encryption | [Cryptography](cryptography.md) |
| Cohorts, forms, signed lifecycle, release thresholds, retention | [Protocol](protocol.md) |
| Role-scoped multifactor administration | [Architecture](architecture.md#administrative-access), [API](api.md#authentication-and-caching) |
| Local review, charts, safe exports, encrypted replies, anonymous abuse controls | [Protocol](protocol.md#review-and-replies), [UI design](ui-design.md) |
| Inclusion receipts, consistency, separate anchored audits | [Cryptography](cryptography.md#encryption-and-public-proofs), [architecture](architecture.md#administrative-access) |
| Controlled-copy retention and accurate destruction limits | [Key management](key-management.md#retention-and-destruction), [threat model](threat-model.md) |
| Shared device-side Go/WASM and optional CLI; self-hosted, accessible, responsive UI | [Architecture](architecture.md#client-and-server-contract), [UI design](ui-design.md) |
| Portable local stack and real security validation | [Deployment](deployment.md), [testing](testing.md), [CI/CD](ci-cd.md) |
| Open-source licensing, compatibility, verifiable releases | [Dependencies](dependencies.md), [versioning](versioning.md), [releasing](releasing.md) |

See [roadmap](roadmap.md) for priorities, optional extensions, and open questions.
Extensions must preserve baseline boundaries. Independent security review is required before real use.

Contribution rules: [AGENTS.md](../AGENTS.md) and [CONTRIBUTING.md](../CONTRIBUTING.md).

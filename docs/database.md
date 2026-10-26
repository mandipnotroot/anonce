<!-- SPDX-FileCopyrightText: 2026 Anonce Contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Database design

Audience: storage implementers, database reviewers, and operators.

Status: proposed logical schema; no database or migrations exist in this checkout.
PostgreSQL 18 with pgx is the accepted target.

## Storage boundary

Use independent identity and ciphertext PostgreSQL instances under the
[deployment separation contract](deployment.md#production-separation). No shared
identity key, database link, foreign data wrapper, or cross-service query is allowed.
Infrastructure administrators remain inside the [collusion analysis](threat-model.md).

## Identity database

| Relation | Intended fields and invariants |
| --- | --- |
| `admin_users`, `admin_roles` | Password hashes, role bindings, status; no plaintext passwords |
| `admin_credentials`, `admin_sessions` | Passkey metadata, protected TOTP state, hashed session identifiers |
| `cohorts`, `members`, `cohort_members` | Eligibility data and necessary delivery addresses; unique membership constraints |
| `enrollment_codes` | Random-code digest, expiry, consumed marker; no retained printable code |
| `certificates`, `revocations` | Serial, public certificate, validity, revocation reason and publication state |
| `auth_challenges` | Challenge digest/context, expiry, consumed marker |
| `round_eligibility`, `issuances` | Member/round eligibility, published limit and bulletin digest, reserved allowance count; unique member/round ledger; no token or blinded transcript |
| `issuance_slots` | Identity-side reservation status; unique member/round/slot; slot index within the published allowance; no token or signature |
| `audit_events` | Minimal action record, predecessor commitment, checkpoint publication status |

Apply a declared retention policy to identities, delivery addresses, consumed codes,
challenges, sessions, and issuance participation. A round ID may be common public
context; a member or per-request identity reference may not appear in the ciphertext
database.

## Submission database

| Relation | Intended fields and invariants |
| --- | --- |
| `round_bulletins` | Public signed schema, key references, times, profile, response limit, release policy, and immutable digest |
| `spent_tokens` | Canonical spend digest and round; unique constraint arbitrates concurrency |
| `submissions` | Random record ID, ciphertext envelope, commitment, durable acceptance status |
| `log_outbox`, `log_entries` | Idempotent commitment publication and public tree indexing |
| `reply_mailboxes`, `encrypted_replies` | Random capabilities/digests and ciphertext only |
| `abuse_flags` | Anonymous token reference, reason category, reviewer authorization evidence |

Do not store identity fields, authentication sessions, IP addresses, user agents,
fine-grained activity analytics, or issuer correlation identifiers. Retain arrival
time only at the minimum precision and duration justified by scheduling and abuse
policy; do not expose precise per-record times publicly.

## Privileges and transactions

Each database has a non-login schema owner, a migration login allowed to assume
that owner, and a non-owner runtime login. Runtime roles have no superuser,
`CREATEDB`, `CREATEROLE`, `BYPASSRLS`, extension-installation, or public-schema write
privileges. Revoke unnecessary database `CONNECT`, schema `CREATE`, and default
function privileges. Do not place administrator passwords in Compose files.

RLS may help isolate administrative cohorts, but policy predicates must be tested
under the actual runtime role. Owners and privileged roles can bypass RLS. It does
not replace service/database isolation.

Reserve an issuance slot and increment the member/round reserved count in one
transaction under a lock or equivalent proven concurrency control. Enforce a unique
member/round/slot and a reserved count no greater than the published limit; a unique
member/round row alone does not enforce that limit. Reservation records and counts
must agree after failures and recovery. Refuse reuse or refund of a reserved slot
without a reviewed recovery mechanism. Track quota by membership, not by certificate
or session, so re-enrollment and concurrent devices cannot reset the allowance.

Do not copy slot indices, member quota counters, or issuance-operation identifiers
into submission storage. Consume each token and persist its bound ciphertext plus
log outbox record in one transaction. Use bounded transactions and explicit retry
rules; do not retry a partial issuance blindly.

## Migration and restoration contract

Use separate Goose SQL directories and version tables. Published migrations are
immutable. New schema changes use additive migrations where possible and document
rollback feasibility, lock duration, data retention, and compatibility. Reject a
database newer than the supported application range. Dangerous down migrations are
not an automatic recovery mechanism.

Tests must apply each database's migrations from empty state, validate expected
privileges, reject cross-service access, and restore an encrypted backup into an
isolated disposable environment. Follow [deployment](deployment.md) for operational
backup separation. Database encryption cannot substitute for device-side content
encryption.

<!-- SPDX-FileCopyrightText: 2026 Anonce Contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Database design

Audience: storage implementers, database reviewers, and operators.

Status: proposed logical schema; no database or migrations exist in this checkout.
PostgreSQL 18 with pgx is the accepted target.

## Storage boundary

Use [independent identity and ciphertext instances](deployment.md#production-separation).
No shared identity key, database link, foreign data wrapper, or cross-service query.
Infrastructure administrators remain a [collusion risk](threat-model.md).

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

Declare retention for identities, delivery addresses, consumed codes, challenges,
sessions, and issuance participation. A round ID may be shared public context;
member or per-request identity references must not enter ciphertext storage.

## Submission database

| Relation | Intended fields and invariants |
| --- | --- |
| `round_bulletins` | Public signed schema, key references, times, profile, response limit, release policy, and immutable digest |
| `spent_tokens` | Canonical spend digest and round; unique constraint arbitrates concurrency |
| `submissions` | Random record ID, ciphertext envelope, commitment, durable acceptance status |
| `log_outbox`, `log_entries` | Idempotent commitment publication and public tree indexing |
| `reply_mailboxes`, `encrypted_replies` | Random capabilities/digests and ciphertext only |
| `abuse_flags` | Anonymous token reference, reason category, reviewer authorization evidence |

Never store identity fields, authentication sessions, IPs, user agents, fine-grained
activity analytics, or issuer correlation IDs. Minimize arrival-time precision and
retention to scheduling/abuse needs. Never publish precise per-record times.

## Privileges and transactions

**Privileges:**

- Per database: non-login schema owner, migration login allowed to assume ownership,
  and non-owner runtime login.
- Runtime roles: no superuser, `CREATEDB`, `CREATEROLE`, `BYPASSRLS`, extension
  installation, or public-schema writes. Revoke unnecessary `CONNECT`, schema `CREATE`,
  and default function privileges. No administrator passwords in Compose files.
- Optional cohort RLS must be tested as the actual runtime role. Owners/privileged
  roles can bypass it; RLS does not replace service/database isolation.

**Transactions:**

- Atomically reserve an issuance slot and increment the member/round count using
  a lock or equivalent proven concurrency control.
- Enforce unique member/round/slot and count ≤ published limit. A unique member/round
  row alone is insufficient. Counts and reservations must agree after failure/recovery.
- No reserved-slot reuse/refund without reviewed recovery. Track quota by membership,
  not certificate/session, so re-enrollment and parallel devices cannot reset it.
- Never copy slots, member quota counters, or issuance-operation IDs into submission storage.
- Atomically consume a token and persist bound ciphertext plus log outbox record.
  Bound transactions and define retries; never blindly retry partial issuance.

## Migration and restoration contract

- Separate Goose SQL directories and version tables. Published migrations are immutable.
- Prefer additive changes. Document rollback feasibility, lock duration, retention,
  and compatibility. Reject databases newer than the supported range.
- Do not use dangerous down migrations as automatic recovery.
- Test migrations from empty state, grants, cross-service rejection, and encrypted
  backup restoration in an isolated disposable environment.
- Follow [deployment](deployment.md) for backup separation. Database encryption
  does not replace device-side content encryption.

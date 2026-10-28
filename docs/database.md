<!-- SPDX-FileCopyrightText: 2026 Anonce Contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Database design

Audience: storage implementers, database reviewers, and operators.

Status: local PostgreSQL 18.6 bootstrap plus separate Goose migration histories and
an operator-only pgx runner. Only a storage-boundary marker is migrated. The account,
vault, and protocol schemas below are proposed; HTTP persistence is not implemented.

## Storage boundary

Use [independent identity and ciphertext instances](deployment.md#production-separation).
No shared identity key, database link, foreign data wrapper, or cross-service query.
Infrastructure administrators remain a [collusion risk](threat-model.md).

## Local container bootstrap

The [Compose stack](deployment.md#container-stack) uses independent PostgreSQL
instances and volumes for `identity` and `submission`. The shared
`deploy/postgres/bootstrap.sql` runs transactionally only when
each volume is empty. It creates no proposed application tables, migration version
table, vault records, or submission state.

Each instance has its own admin password and separate migration/runtime passwords:

| Role | Initial authority |
| --- | --- |
| `identity_admin` or `submission_admin` | Upstream bootstrap superuser, available only to the database container/operator, never the application |
| `anonce_owner` | Non-login owner of the database and its empty `anonce` schema |
| `anonce_migrator` | Non-superuser login; requires explicit `SET ROLE anonce_owner` before creating owned objects; ownership is not inherited |
| `anonce_runtime` | Non-owner login with database `CONNECT` and schema `USAGE`; migration 1 explicitly grants only marker `SELECT` |

Runtime roles cannot create databases, roles, schemas, temporary tables, extensions,
or public-schema objects, assume ownership, bypass RLS, or replicate. Public access
to the application/default databases and public-schema writes is revoked. Future
owner-created functions do not grant `EXECUTE` to `PUBLIC` by default. Runtime
statements have a five-second timeout and idle transactions a 30-second timeout.
These choices follow PostgreSQL 18's [role grants](https://www.postgresql.org/docs/18/sql-grant.html)
and [default privileges](https://www.postgresql.org/docs/18/sql-alterdefaultprivileges.html)
(consulted 2026-10-28).

TCP authentication uses SCRAM-SHA-256. Upstream initialization uses trusted Unix-socket
administration inside each database container; no database socket or secret directory
is mounted into applications. This is a local operator boundary, not protection
against database-container or host compromise. Data volumes follow the PostgreSQL 18
[official image layout](https://hub.docker.com/_/postgres) (consulted 2026-10-28).

Bootstrap SQL neither upgrades nor repairs existing volumes. Separate embedded
Goose histories are applied explicitly as described below. Evidence and limits live in
[container checks](testing.md#container-infrastructure-checks); quota/spend transactions
and encrypted restoration remain unimplemented.

## Identity database

| Relation | Intended fields and invariants |
| --- | --- |
| `admin_users`, `admin_roles` | Password hashes, role bindings, status; no plaintext passwords |
| `admin_credentials`, `admin_sessions` | Passkey metadata, protected TOTP state, hashed session identifiers |
| `accounts`, `account_credentials`, `account_sessions` | Account status, credential public metadata, protected session references and expiry; membership binding distinct from login; no PRF output or vault unlock secret |
| `member_key_backups` | Owner account, public/enrollment binding, bounded encrypted backup, reviewed format metadata and concurrency version; no plaintext private key or per-submission state |
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

The [browser vault](key-management.md#browser-account-vault) requires owner-scoped
read/write/delete authorization and tested concurrent-update behavior. Do not store
answers, tokens, receipts, mailbox identifiers, reply capabilities, or an account's
submission history in these relations. Available-round dashboard data comes from
eligibility and public schedules, not a join against anonymous records.
Final vault fields, replacement/recovery transactions, rollback handling, and
retention remain unresolved; this table is not a migration or fixed wire format.
Reviewer-key backup is excluded until a separate retention policy is reviewed.

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

### Local migration runner

`migrations/identity/` and `migrations/submission/` are embedded in the operator-only
`cmd/migrate` binary. Each starts at version 1 and creates `anonce.storage_boundary`
with exactly one service-specific row. Runtime gets `SELECT` only. The separate
`anonce.identity_schema_version` and `anonce.submission_schema_version` Goose tables
and their sequences remain owner-only. No identity or submission records are added.

The runner accepts exactly `identity` or `submission`, connects to that fixed
Compose hostname/database as `anonce_migrator`, checks the database name and
unprivileged login, and explicitly assumes `anonce_owner`. A single physical
connection holds PostgreSQL session advisory lock `4097083626` across history
inspection, version-table initialization, and migration application. Reconnection
must reacquire the lock and repeat preflight. Each SQL migration and its version
entry use Goose's transaction. No down/reset or out-of-order option is exposed.

Supported histories are an absent ledger or an applied version 0 baseline followed
optionally by version 1. Future, negative, duplicate, unapplied, or missing-baseline
records fail before migration. Already-current runs also require the correct
single marker row. When adding a migration, extend this explicit supported-history
range and its tests. Published SQL must never be edited; the ledger records versions,
not checksums, and is not protection against a privileged operator changing data.

The total deadline is 60 seconds, connection timeout five seconds, statement timeout
30 seconds, lock wait five seconds, and idle transaction timeout 30 seconds. SQL
diagnostics are discarded. Password bytes are cleared after use; immutable driver
and runtime copies cannot be erased. The fixed plaintext TCP connection is admitted
only for the isolated local stack, not production deployment.

This follows [Goose 3.29.0 SQL transaction/version semantics](https://github.com/pressly/goose/blob/v3.29.0/README.md#migrations)
and PostgreSQL 18 [session advisory locks](https://www.postgresql.org/docs/18/explicit-locking.html#ADVISORY-LOCKS)
(consulted 2026-10-28). See [operator commands](deployment.md#local-database-migrations)
and [executable evidence](testing.md#database-migration-checks). Encrypted restoration,
application concurrency, and full `db-test` remain unavailable.

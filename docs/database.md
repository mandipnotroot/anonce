<!-- SPDX-FileCopyrightText: 2026 Anonce Contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Database design

Audience: storage implementers, database reviewers, and operators.

Status: local PostgreSQL 18.6 bootstrap plus separate Goose migration histories and
an operator-only pgx runner. Identity version 2 adds account/session persistence
and version 3 adds an internal encrypted member-backup slot;
submission version 1 contains only its storage-boundary marker. Product vault,
credential, membership, and protocol integration remain proposed; HTTP persistence is not implemented.

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

### Implemented account storage

`internal/identity/accounts` is an internal pgx foundation, not a sign-in service.
Identity migration `00002_accounts.sql` adds two owner-created tables:

| Relation | Implemented fields and grants |
| --- | --- |
| `accounts` | Random 16-byte primary key, active/disabled state, creation time, optional disable time; runtime can select/insert and update state/disable time only |
| `account_sessions` | 32-byte SHA-256 token digest primary key, account foreign key, creation/absolute-expiry timestamps; runtime can select/insert/delete, never update or extend expiry |

No identifiers, sessions, or account tables enter submission storage. These two
tables have no credential, vault, member, role, answer, receipt, IP, or user-agent columns. Account
creation grants no eligibility, and disabling changes no membership quota. The
[session storage profile](cryptography.md#account-session-storage-profile) fixes
secret sizes and development lifetime limits without selecting a browser transport.

The caller supplies a pool configured for the unprivileged identity runtime login,
without query/parameter tracing, and retains connection ownership. Construction
checks the database, role, boundary marker, and table presence. Each operation has
a five-second deadline. Driver errors are discarded, retaining only operation
context and cancellation. Failed session creation returns no token; an uncertain
commit may leave an unreachable session until expiry, never a safe automatic retry.

`StartSession` requires authentication already verified by its trusted caller.
It admits at most `MaxSessionsPerAccount` (16) unexpired sessions per account.
After locking the active account, a fresh Read Committed statement counts up to
the limit using the database clock. Concurrent starts across pools serialize on
that lock; committed starts, revocation, and expiry during a lock wait are observed
before admission. At or above capacity, `ErrSessionLimit` returns no token or session
and leaves existing sessions unchanged. Missing/disabled accounts still return
`ErrUnavailable`. Expired rows do not count and are not deleted by admission.
Revocation or expiry frees capacity; rotation replaces one row and remains available
at capacity without extending expiry. No automatic eviction or retry is performed.

This fixed development bound follows the application-policy approach in
[OWASP simultaneous-session guidance](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#simultaneous-session-logons)
and PostgreSQL 18's
[Read Committed semantics](https://www.postgresql.org/docs/18/transaction-iso.html#XACT-READ-COMMITTED)
(consulted 2026-10-28). It is a package admission rule, not a database constraint:
direct runtime SQL, older application versions, restored data, or clock rollback
can exceed it. Existing excess sessions are not recalled; new starts fail until
capacity is available. It does not bound expired-reference growth, account counts,
authentication attempts, or total database resources. Hosts still need cleanup,
rate limits, reviewed product policy, and a safe session-management UX.

`Resolve` always joins the account and checks absolute expiry using PostgreSQL's
clock; it does not refresh expiry or authorize sensitive actions. `Revoke` locks
the account before removing one digest. `RevokeAll` and `Disable` serialize with new sessions by locking the
account row before deleting sessions in a transaction. After disable commits, a
new lookup fails and no concurrent session creation can leave a usable session.
Already-resolved requests are not recalled. Revoke-all does not prevent a later,
separately authenticated session. Disabling is idempotent; no re-enable API exists.
Lock ordering follows PostgreSQL 18 [row-lock semantics](https://www.postgresql.org/docs/18/explicit-locking.html#LOCKING-ROWS)
(consulted 2026-10-28).

`RotateSession(ctx, id, token)` requires fresh authentication independently verified
by its trusted caller for `id` and bound to this operation. It is not a bearer-only
refresh method or an authentication verifier. It locks that active account, then
rechecks token ownership and expiry in a fresh statement before atomically deleting
the old digest and inserting a fresh random digest. The new creation timestamp
records reauthentication admission; absolute expiry is preserved, not extended.
Sibling sessions are unchanged. Competing rotations of one token have at most one
winner; revocation/disable ordered first prevents rotation. No caller-selected
timestamp, replacement token, or new lifetime is accepted. Failure returns no
secret or session; an uncertain commit may invalidate the old token and leave the
new one unreachable.
Require fresh sign-in rather than retrying that operation automatically.

Revocation removes live session references immediately. Expired references remain
until `PurgeExpired` is called, bounded to 1–1000 rows per call. No cleanup scheduler,
account deletion, production retention policy, backup restoration, authentication
ceremony or HTTP integration exists. Product retention and recovery must be reviewed
before real data is admitted. See the
[real PostgreSQL account checks](testing.md#account-storage-checks).

### Session-scoped session inventory

`ListSessions(ctx, token)` derives the account from the bearer session, locks the
active account, then rechecks the same token's existence, nonfuture creation, and
absolute expiry in a fresh Read Committed statement. The five-second transaction
uses the same account-first lock order as session changes and member-backup access.
Revocation, rotation, or disable committed first denies a queued lookup. Expiry is
checked using the database clock after lock waits, not transaction-start time.

The returned `SessionInfo` entries contain creation and absolute-expiry timestamps
and a `Current` marker only. No account ID, token, digest, device ID, IP, user agent,
or anonymous activity is returned or added to storage. Entries are ordered newest
first, with expiry and an internal digest tie-breaker; digests never leave the store.
This is session metadata, not a list of devices or a supported HTTP format.

The query returns at most 16 live, nonfuture entries as of authorization admission.
It fetches at most one extra entry to detect excess sessions from direct SQL, older
writers, or restoration. Excess returns `ErrSessionLimit` without a partial list
or eviction. Malformed, unknown, future-dated, expired, revoked, and disabled bearer
sessions share `ErrUnavailable` and return no metadata. Older live sessions may
list without recent authentication. Cancellation or transaction failure returns
no list. Results are returned only after commit and can immediately become stale;
cleanup may remove references that expire after admission. Already returned data
is not recalled by revocation. Hosts still need authentication, protected delivery,
CSRF protection, and rate limits before exposing session management.

This follows the existing PostgreSQL 18
[row-lock](https://www.postgresql.org/docs/18/explicit-locking.html#LOCKING-ROWS) and
[Read Committed](https://www.postgresql.org/docs/18/transaction-iso.html#XACT-READ-COMMITTED)
contract (consulted 2026-10-29). No migration, grant, credential ceremony, or browser
transport is introduced. See [account checks](testing.md#account-storage-checks).

### Proposed identity relations

The following table describes the intended complete service, not implemented
credentials, enrollment, or protocol tables. The member-backup slot is the limited
internal implementation described below, not a complete vault service.

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
Product vault fields, recovery transactions, rollback handling, and production
retention remain unresolved; this table is not a fixed wire format.
Reviewer-key backup is excluded until a separate retention policy is reviewed.

### Local member-backup storage contract

`internal/identity/memberbackup` uses identity migration
`00003_member_key_backups.sql` and one slot per account in `member_key_backups`.
Each slot holds an owner account reference, a 32-byte public-key binding, an
encrypted 108-byte [member backup](cryptography.md#member-key-payload-profile-1), and a positive
revision. Access requires an active account. Runtime gets select/insert and update
of ciphertext/revision only, never row deletion, ownership changes, or public-key
updates. Only the existing password profile is admitted. Envelope checks cannot
authenticate ciphertext or prove that it contains the declared key; device-side
decryption, typed validation, and independently trusted expected-key matching
remain mandatory. No unlock secret is accepted by the storage API.

The trusted caller supplies the authenticated owner account, never a request's
unchecked account identifier. This internal contract does not select an HTTP
authorization or recent-authentication mechanism. It must not be exposed directly.
Runtime credentials have access to all identity rows; account scoping is enforced
by the package, not by per-account database roles or RLS.

Creation requires expected revision zero. Replacement requires the current
revision and the unchanged public key. Deletion clears the live ciphertext and
increments the revision, retaining a tombstone with the public binding. Recreating
the slot requires that tombstone's revision and the same key, preventing stale
create/update/delete operations from succeeding after deletion. Key rotation and
rebinding are excluded. Revisions never wrap and are not cryptographic rollback
protection against a malicious server or restored database.

Writes lock the account row before touching its slot, serializing with account
disable and other slot writes. Reads join the current active account; an already
returned result is not recalled by disable. No automatic retry follows an uncertain
commit. Hosts must reread state before deciding whether to try again.

This is a development retention policy: one live ciphertext, no application
history, and a retained tombstone until a future reviewed account-deletion policy.
Disable denies access but does not erase the slot. PostgreSQL WAL, dead tuples,
snapshots, and operator backups may retain earlier ciphertext. Production retention,
write admission/rate limits, verified authentication ceremonies, enrollment binding,
recovery, and encrypted database restoration remain prerequisites for product
integration.
Reviewer backups and all per-submission state remain excluded.

The store borrows a pool under the same checked boundary, five-second operation
deadline, and secret-free error rules as the account store. `Get` returns current
public/encrypted material or a tombstone. `Put` returns the committed new revision;
`Delete` returns the committed tombstone revision. Invalid inputs fail before SQL;
stale revisions or changed bindings return `ErrConflict`, without current data.
Missing/disabled owners return `ErrUnavailable`. See the separate
[real PostgreSQL checks](testing.md#member-backup-storage-checks).

The concurrency contract follows PostgreSQL 18
[row locks](https://www.postgresql.org/docs/18/explicit-locking.html#LOCKING-ROWS)
and [transaction isolation](https://www.postgresql.org/docs/18/transaction-iso.html)
(consulted 2026-10-28).

### Session-scoped member-backup access

`GetForSession`, `PutForSession`, and `DeleteForSession` accept a 32-byte bearer
session secret instead of an owner ID. Only its existing SHA-256 digest reaches
PostgreSQL. The owner is derived from the session, never selected by request data;
all revision, public-binding, envelope, and tombstone rules above still apply.
Tokens remain caller-owned and must not change until return; clear them after use.

Each operation discovers the session's owner, locks the active account, then checks
session existence, nonfuture creation, and absolute expiry in a fresh Read Committed
statement using the database clock. It accesses the slot in that same five-second
transaction and returns material or a revision only after commit. Individual
revocation, revoke-all, disable, and all package backup writes use the same
account-first lock order.
An invalidator ordered first denies queued access; an access transaction ordered
first commits before invalidation. Session rotation uses this same lock order.
Delivery of its prepared result can race invalidation. Expiry is checked at
admission after the account lock, not continuously during the bounded operation.
Already returned data is not recalled.
Expired-reference cleanup may remove an expired session without this account lock;
it grants no access or extension of an already admitted operation.

Malformed, unknown, expired, revoked, or disabled sessions and absent read slots
share `ErrUnavailable`; failed authorization returns no slot data or revision.
Invalid write envelopes/revisions still fail as `ErrInvalidInput` before SQL.
Cancelled or failed transactions return no result; uncertain commits must not be
retried blindly.

`PutForSession` and `DeleteForSession` additionally require the session creation
timestamp to be strictly newer than the database admission time minus five minutes
and no later than admission. The fixed `RecentAuthenticationWindow` applies to
creation, replacement, tombstone restoration, and deletion, before any slot lookup
or revision conflict. An older live session returns `ErrReauthenticationRequired`
with no revision or mutation, while `GetForSession` still permits reading. Unknown,
future-dated, expired, revoked, and disabled sessions return `ErrUnavailable` instead.
The age check runs after account-lock waits, at admission rather than continuously
during bounded work. Clock rollback can affect this policy, as it can expiry.

`StartSession` and `RotateSession` must only follow independently verified
authentication by a trusted caller. Row creation time is a storage assertion by
that caller, not proof of a ceremony. There is no endpoint that grants freshness
from token possession alone, and no API to edit existing session timestamps.
Owner-ID methods remain trusted internal operations without this age gate, not
endpoint adapters. A future host still needs verified login/reauthentication,
operation/account binding, CSRF protection, and rate limits before product use.
No HTTP route, browser transport, migration, or grant change is introduced.

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
and their sequences remain owner-only. Identity version 2 adds the account/session
tables described above, initially empty. Identity version 3 adds the member-backup
slot with narrow runtime update grants. No membership or anonymous records are added.

The runner accepts exactly `identity` or `submission`, connects to that fixed
Compose hostname/database as `anonce_migrator`, checks the database name and
unprivileged login, and explicitly assumes `anonce_owner`. A single physical
connection holds PostgreSQL session advisory lock `4097083626` across history
inspection, version-table initialization, and migration application. Reconnection
must reacquire the lock and repeat preflight. Each SQL migration and its version
entry use Goose's transaction. No down/reset or out-of-order option is exposed.

Supported histories are an absent ledger or a contiguous, ordered applied version
0 baseline through at most identity version 3 or submission version 1. Existing
version-1/version-2 identity databases upgrade additively without editing published SQL.
Future, negative, duplicate, out-of-order, gapped, unapplied, or missing-baseline
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
quota/spend concurrency, and full `db-test` remain unavailable.

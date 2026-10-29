<!-- SPDX-FileCopyrightText: 2026 Anonce Contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Threat model

Audience: security reviewers, implementers, and organizations considering adoption.

Status: design analysis, not a completed security assessment.

## Current controls and limits

These controls cover local development only. They do not establish the protocol
properties described below.

### HTTP services and shell

- [Local services](deployment.md#local-development) reject non-loopback binds by default,
  read no request bodies, and discard HTTP diagnostics that could expose peer
  addresses or panic values. Protocol operations, signing, account credentials,
  and application database integration remain unavailable.
- The shell serves public HTML and local CSS without forms or browser execution.
  Mocks require explicit development mode. [Browser and manual checks](ui-design.md#current-local-shell)
  remain outstanding.
- These controls do not isolate local users, browser-initiated requests, host
  compromise, or externally configured proxies.
- The separate [synthetic browser-test host](testing.md#member-worker-browser-checks)
  exists only in test binaries on an ephemeral loopback origin. It rejects foreign
  hosts/origins and unread bodies, verifies bounded assets, and separates page and
  worker CSP. Product services remain inert. This is neither product custody nor
  a boundary against hostile local code or a malicious browser distributor.

### Local container infrastructure

- The [Compose stack](deployment.md#container-stack) separates database instances,
  volumes, passwords, and internal networks. Runtime SQL roles do not own schema
  objects and cannot assume the migration owner. Applications receive no database
  credentials until a storage integration exists. Bootstrap is not a migration runner.
- Explicit `-container-network` allows only the additional IPv4 wildcard; native
  defaults stay loopback-only. Compose publishes HTTP ports only on host loopback.
  Per-application edge bridges are needed for publication and allow outbound traffic;
  they are not a network-anonymity or egress-control mechanism.
- Non-root users, read-only roots, dropped capabilities, configured resource limits,
  and disabled Docker logging reduce local exposure. SQL checks use file-based
  credentials without reflecting passwords or database error bodies. Secret files
  remain plaintext on the host and readable by the authorized database container.
- Host/daemon administrators can read both instances and observe traffic. Containers
  are not independent operators or proof of anonymity. The stack has no TLS,
  production authentication, encrypted database backup/restore evidence, container
  vulnerability scan, or SBOM. It must not receive real data.
- The [local migration runner](database.md#local-migration-runner) is a separate
  operator image with only one database network and migration credential. It
  explicitly assumes ownership, serializes application with a bounded session lock,
  and rejects unsupported histories. Runtime can read the boundary marker and has
  explicit identity account/session/member-backup grants, never migration-state access. The runner
  has schema-owner authority; its SQL and image are
  trusted operator inputs. Version records are not tamper evidence or checksums.
  Password buffers are cleared where owned, but driver/runtime copies remain.
  Plaintext database TCP is local-only, with no hostile-host or production TLS claim.

### Identity account storage

- The [internal store](database.md#implemented-account-storage) stores random session
  secrets only as SHA-256 digests, with absolute expiry and account-status checks
  on each lookup. Raw secrets are caller-owned and must be cleared after protected
  delivery. SQL and driver diagnostics are not returned. Read-only digest theft
  does not directly reveal bearer secrets; stolen secrets or application/database
  write compromise still permit impersonation.
- Session creation/rotation, individual/all-session revocation, and disabling take the account row lock first.
  Disable atomically removes sessions and prevents new ones. An already-authorized
  in-flight request is not recalled; no distributed revocation or browser logout
  claim is made. Database clock rollback can affect expiry and authentication-age admission.
- This package trusts its caller to verify authentication and authorize changes.
  Session starts admit at most 16 unexpired references per account, rechecking
  committed state and database-clock expiry after the account lock. Denial does
  not evict existing sessions; rotation at capacity preserves absolute expiry.
  `session-limit`, `concurrent-session-limit`, and `session-limit-after-lock-wait`
  check capacity, cross-pool races, expiry/revocation, and cancellation against real
  PostgreSQL. Direct SQL, older writers, restored data, or clock rollback can exceed
  this package-only bound. It limits neither total accounts nor expired rows and
  does not replace cleanup or abuse controls.
  No login route, credentials, CSRF/cookie handling, rate limiting,
  authentication ceremony, recovery, browser vault access, or membership binding is
  supplied. It must not be exposed directly to requests. Its pool must remain on
  the checked runtime role/database, without parameter tracing. Storage tests do
  not establish a secure account workflow or authorize anonymous submissions.

The [session inventory](database.md#session-scoped-session-inventory) derives its
owner from the live bearer and rechecks authorization after account-lock waits.
It returns bounded creation/expiry metadata, independent non-secret row selectors,
and a current-session marker,
never tokens/digests or another account's sessions. Excess rows fail without a
partial list. `session-inventory` and `inventory-after-lock-wait` cover scope,
invalid/future/expired bearers, invalidation, expiry during waits, and cancellation
against real PostgreSQL. A stolen live bearer can read that owner's session times;
returned metadata can become stale and is not recalled. This is not device
identification, browser logout, or an authentication ceremony. `session-selectors`
checks stable per-row selectors, replacement on rotation, constraint/grant
enforcement, and rejection of selectors as credentials. The migration target checks
backfill without changing existing tokens or timestamps, repeated application, and
transactional failure. Selectors remain identity-side linkable metadata and must
not enter anonymous requests, logs, or tracking systems.

The [sibling-revocation operation](database.md#session-scoped-sibling-revocation)
uses the same derived owner and lock, requiring authentication admission within
five minutes after any lock wait. Old live bearers cannot evict siblings or gain
freshness from possession alone. A recently stolen bearer can still evict legitimate
sessions; age is not proof of user intent. Revocation leaves the caller's token and
absolute expiry unchanged, affects no other account, and denies later backup access
by removed bearers. Already admitted operations, returned ciphertext, and local
device keys are not recalled or erased. Later independently authenticated starts
remain possible. `revoke-other-sessions`, `concurrent-revoke-other-sessions`,
`revoke-others-after-lock-wait`, and `revoke-others-cancellation-and-rollback` map
scope, competing bearers, rotation/invalidation, post-lock age/expiry, and rollback
to real PostgreSQL checks. This adds no browser logout or credential ceremony.

[Selected sibling revocation](database.md#session-scoped-selected-revocation) uses
independent inventory selectors, never bearer digests, and the same owner-derived
recent-authentication gate. Current, missing, stale, and foreign selectors cannot
remove the current session or another account's row; rotation invalidates the old
selector without exposing a successor. `selected-session-revocation`,
`concurrent-selected-session-revocation`, `selected-session-after-lock-wait`, and
`selected-session-rollback` cover scope, competing bearers, rotation, post-lock
authorization/age/expiry, and cancelled deletion. Member-backup `revoke-selected`
cases cover denied subsequent access and serialization with admitted backup work.
This does not lock a remote device, erase returned data, or establish user intent.

[Session-scoped sign-out everywhere](database.md#session-scoped-sign-out-everywhere)
derives ownership from the bearer, rechecks the same recent-admission gate after
account-lock waits, and removes the current session as well as siblings. A stolen
recent bearer can deny legitimate users access; this is not proof of user intent.
`session-scoped-sign-out`, `concurrent-session-scoped-sign-out`,
`sign-out-after-lock-wait`, and `sign-out-rollback` map owner isolation, invalid/old
bearer denial, concurrent starts/rotation/invalidation, post-lock authorization,
and rollback to real PostgreSQL checks. Member-backup `session-sign-out` cases
cover serialization and denial of subsequent access. Fresh independently verified
logins remain possible; local keys, membership, and already admitted work are not
revoked. No browser logout or credential ceremony is implemented.

### Internal member-backup storage

- The [development store](database.md#local-member-backup-storage-contract) scopes
  owner-ID operations to a trusted caller-supplied owner and checks account status.
  Account locks serialize writes with disable; revisions reject stale concurrent
  writes, and tombstones prevent stale creation after deletion. Reads already in
  flight or returned before disable are not recalled. No HTTP owner authorization,
  write rate limit, or browser integration exists. Owner-ID methods have no
  authentication-age gate and must not be exposed as endpoint adapters.
- [Session-scoped access](database.md#session-scoped-member-backup-access) derives
  ownership from an existing session and holds the account lock through backup
  access and commit. A fresh post-lock query rejects expired or revoked sessions,
  including revocation committed during a lock wait. Individual/all-session
  revocation and disable serialize with this access; a transaction admitted first
  commits before invalidation, but its result delivery can race invalidation.
  Expiry after admission does not recall
  bounded in-flight work. A stolen live token can access that owner's ciphertext.
  Mutations require a nonfuture session created within five minutes of database
  admission, rechecked after lock waits. An older token cannot mutate or obtain
  freshness without a separately verified authentication ceremony. A recently
  stolen token can still mutate during this window; age is not operation intent.
- Session rotation trusts its caller to bind fresh authentication to the same
  account and operation. It replaces one live token atomically without extending
  absolute expiry or changing sibling sessions. It serializes with invalidation
  and backup access, but cannot recall already returned material. A compromised
  trusted caller/runtime role can bypass the policy. No ceremony verification,
  browser logout, key unlocking, or recovery authority is established.
- The runtime role can access all identity slots. Package scoping is not RLS and
  cannot contain a compromised identity application. Public bindings are linkable
  metadata, never anonymous-request fields. Stored ciphertext can be guessed
  offline; storage admission verifies only public envelope structure, not encrypted
  payload validity or key binding.
- Fixed public bindings prevent accidental rebinding through the API, not malicious
  server substitution. Revisions are concurrency controls, not rollback proofs.
  Deletion clears the live ciphertext but retains public binding/revision metadata;
  WAL, dead tuples, snapshots, and backups can retain old ciphertext. Disable does
  not erase backups. Production retention, account deletion, recovery, trusted
  enrollment binding, and encrypted database restoration remain unimplemented.

### Device keys and backups

- [Device-backup profile 2](cryptography.md#device-backup-profile-2) authenticates
  bounded secrets and headers. Imports cannot choose KDF costs, but a structurally
  valid import with an invalid password or tag still costs a full derivation.
  Serialized work does not bound caller queues, total process memory, or repeated guessing.
- The [member](cryptography.md#member-key-payload-profile-1) and
  [reviewer](cryptography.md#reviewer-key-payload-profile-1) wrappers generate local
  Ed25519/X25519 keys and validate purpose, algorithm, and canonical PKCS #8.
  They reject authenticated non-key payloads; member export also rejects inconsistent
  private/public halves. Failed imports return no key.
- Keys never enter HTTP services. These packages do not establish identity,
  authorization, revocation, expiry, backup freshness, or reviewer round binding.
  Browser custody, enrollment, round publication, and submission decryption are unavailable.
- Backups permit offline password guessing. They do not detect restored old copies
  or prevent expired-key reuse. Hostile callers and compromised devices can access returned secrets.
  Owned private buffers require caller cleanup; library/runtime copies prevent
  complete erasure. See [custody limits](key-management.md#device-keystores).
- Profile 2 uses ChaCha20-Poly1305 with one encryption per freshly salted derived
  key and a fresh 96-bit nonce. Do not reuse the key for multiple exports.
  Unsupported profiles fail before derivation, with no algorithm fallback.
  This is not a FIPS-validation claim.

### In-memory member sessions

- The [shared session](key-management.md#in-memory-member-sessions) retains private
  member bytes internally and returns only encrypted backups and public enrollment
  material. Restoring a different key fails before request signing or installation;
  the expected key must be independently trusted. Failed unlock never creates a
  replacement key.
- Unlocked backup export encrypts the retained key without reopening an old backup
  or returning private bytes. The temporary key copy remains owned until bounded
  work finishes; lock cancels output and clears the retained key without waiting
  for that copy's cleanup. The host supplies password confirmation and safe
  ciphertext persistence. An unlocked hostile host can request a backup under its
  own password. Export adds no reauthentication, rotation, revocation, deletion,
  rollback detection, or recovery.
- Lock clears the owned key and cancels pending setup/restoration/export. Cancelled work
  cannot later install a key, and each session admits only one pending operation.
  This does not limit hostile callers creating many sessions, erase runtime copies,
  or revoke already returned public material/backups.
- There is no account binding, automatic expiry, cross-tab lock, persistence,
  enrollment, or recovery. Callers still control passwords and session
  lifetime. Native state/ownership tests are not browser custody evidence.

### Offline key CLI

- The [CLI](key-management.md#local-key-cli) accepts bounded passwords through a
  pipe/file, with confirmation for generation and password changes. It publishes
  owner-only encrypted files without replacement,
  and validates backups before printing public keys only. There is no plaintext
  private-key export or reviewed interactive password prompt.
- File checks require a trusted directory, ancestors, owner, and access-control
  lists. They do not isolate hostile same-user writers. Interruption after
  publication may leave a complete backup; crashes may leave encrypted temporary files.
- [Password changes](key-management.md#backup-password-changes) re-encrypt the same
  key. They do not delete or invalidate old copies, rotate a compromised key, or
  establish freshness or expiry. Retained copies remain open to password guessing.
- Passwords and private bytes enter the local process. Compromised-device risks
  remain, and independent device-workflow review is still required.
- Optional [backup key matching](key-management.md#local-backup-key-matching) rejects
  a different member/reviewer public key after full backup validation, without stdout.
  With `rewrap`, a mismatch also prevents replacement-password derivation and file
  creation; matching uses the authenticated in-memory key, not a separate file read.
  It requires an independently trusted expected key. Old backups for the same key
  still match, so this does not detect rollback, expiry, or revocation. Public-key
  arguments may appear in process listings and shell history.
- [Member requests](cryptography.md#member-csr-profile-1) sign only a fixed,
  identity-free PKCS #10 structure. Bounded validation rejects extra claims and
  invalid signatures. Requests are public but linkable and replayable; they do not
  authenticate enrollment or belong on the anonymous submission path. HTTP
  services still perform no signing or request handling.
- Optional `csr -expect-public-key` rejects a substituted member backup after typed
  authentication and validation, before signing or creating a request file. It
  compares and signs with the same in-memory key. The expected key must be
  independently trusted; this does not detect rollback or revocation, establish
  identity, or authorize enrollment. Process listings and shell history can expose
  the linkable public-key argument.
- Optional [request file export](key-management.md#local-member-certificate-requests)
  shares the owner-only, no-replace publication path but stores public DER, not
  encrypted data. Failed validation creates no file; interruption after publication
  can leave a complete request, and crashes can leave public temporary files.
  File permissions do not establish confidentiality from the device owner or make
  a request trusted.
- Local `verify-csr` uses the same bounded profile and signature validation before
  printing a public key, without passwords or private keys. File checks do not
  make that key trusted, prove freshness, or authorize enrollment.
  Its optional expected-key check rejects a valid request for a different key
  without public output. It prevents substitution only when the expected key was
  obtained independently and trusted. Public key arguments remain linkable and
  may be visible in local process listings or shell history.
- Optional [public-key file export](key-management.md#local-public-key-file-export)
  from `inspect` and `verify-csr` uses owner-only, no-replace publication after
  validation and optional expected-key matching. A mismatch creates no file;
  publication failures never fall back to stdout. Interruption after publication
  can leave a complete file, and crashes can leave public temporary files. These
  records are linkable and neither encrypted nor signed attestations. Saving a key
  from an untrusted input does not establish independent trust or freshness.
- Optional [expected-key file input](key-management.md#local-expected-key-files)
  snapshots a bounded, kind-matched public record before password or subject-file
  access, then uses the existing post-validation comparison without fallback.
  Invalid records fail without output or file creation. This avoids a raw public-key
  argument but exposes the file path; the record remains linkable. Owner-only file
  checks do not authenticate the record or defeat hostile same-user writers. It
  must be independently trusted and adds no freshness or authorization guarantee.

### Public-only WASM verifier

- The [local verifier](key-management.md#local-wasm-request-verification) exposes
  only the existing member-request parser and public output. It bounds primitive
  string input before Go copies/decoding and does not inspect caller objects.
- Requests remain linkable and replayable; signature validation establishes no
  identity, certificate trust, freshness, or enrollment authority. Do not load
  membership requests on the anonymous submission origin.
- `verifyCSRForKey` rejects valid requests for another key without public output.
  Substitution protection requires an independently trusted expected key and a
  trusted host. Copying the expected key from the request provides no protection;
  neither key matching nor WASM protects against a compromised loading realm.
- Build hashes detect changed local artifacts, not a hostile distributor. The
  host realm and built-ins are trusted. Repeated calls, host allocations, and Go
  runtime memory are not bounded by the per-request size limit.
- Node compatibility tests are not browser execution, CSP, private-key custody,
  or independent security evidence. The HTTP shell still loads no executable code.

### Local WASM member bridge

- The worker's opt-in [text passphrase interface](key-management.md#browser-passphrase-text-interface)
  bounds UTF-8 output, rejects unpaired surrogates instead of replacing them, and
  preserves exact spelling without normalization. Setup/export still require shared
  Go byte confirmation. Owned encoding buffers are cleared before invocation returns;
  immutable strings, caller fields, autofill state, and runtime copies cannot be
  cleared by this component. It supplies no prompt, password-strength policy, storage,
  authentication, or protection from hostile host code.
- Optional [confirmed setup/export](key-management.md#in-memory-member-sessions)
  rejects mismatched bounded password bytes in shared Go before key generation,
  private-key snapshot, or derivation. Both bridge/worker input copies are bounded;
  accessible owned copies are cleared on normal completion. A mismatch returns no
  output and leaves the session unchanged. Confirmation does not establish password
  strength, persistence, independent user entry, authentication, or recovery. The
  trusted host still sees both inputs, and runtime copies prevent complete erasure.
- The [separate adapter](key-management.md#local-wasm-member-sessions) retains one
  shared session, snapshots bounded nonshared byte inputs, and returns only public
  enrollment material and encrypted backups. Invalid or busy calls start no operation;
  owned passwords are cleared before Promise settlement. Lock cancels pending work
  even before the shared session begins. Close waits for pending cleanup/settlement.
- Expected-key trust, account binding, backup persistence, expiry, integrated account
  logout, and browser delivery remain integration responsibilities, not bridge controls.
  Failed restoration never generates a key. Public keys and requests are linkable
  and must stay off the anonymous submission origin.
- Go WASM computation can block its host event loop despite a Promise interface.
  Direct-bridge cancellation cannot preempt Argon2id. The separate
  [local worker owner](key-management.md#local-member-worker-host) bounds admission
  before posting, checks response correlation/shapes, and terminates from the owner
  on lock, disposal, load/protocol errors, or timeout. This discards pending output
  without waiting for worker cleanup; it cannot guarantee erasure. Elapsed monotonic
  and wall time are checked before admission, readiness/reply publication, and on
  visibility events. Either deadline, invalid/failed readings, or observed clock
  rollback terminates locally without notifying peers or extending the lifetime.
  This rejects overdue replies even before delayed timeout callbacks run. Clock
  corrections may interrupt valid work; explicit restoration is required. A
  suspended/blocked owner cannot enforce these checks until it resumes, and hostile
  or simultaneously stalled clocks remain outside protection. No product HTTP or
  page integration exists.
  Hostile code in the loading realm can steal unlock material or inspect WASM memory;
  owned-buffer clearing does not erase runtime/library copies. Native/Node checks
  establish limited format/lifecycle evidence, not browser custody or security review.
  The worker's fixed local imports and bounded credential-free WASM fetch still
  require trusted delivery. One active owner per module realm does not constrain
  other realms/tabs or authenticate an account.
  Its public `closed` Promise lets hosts observe terminal local cleanup without
  polling, including idle peer locking. It exposes no reason or identifiers and
  does not acknowledge worker exit or remote locking. Handlers require a running
  owner event loop; they add no suspension, erasure, logout, or revocation guarantee.
  An optional host `AbortSignal` terminates only its owner, with the same local
  cleanup and pending-output rejection as disposal. Already-aborted signals start
  no worker; abort reasons are not read or exposed. Signal state is rechecked before
  admission and readiness/reply publication if abort event delivery was suppressed.
  This does not cancel peers, preserve the unlocked key, undo returned output, or
  provide a hard cancellation deadline while the owner is blocked.
- The worker owner's [lock notifications](key-management.md#lock-notifications-and-page-disposal)
  contain no secrets or account/key identifiers. Explicit lock can notify eligible
  same-origin, same-partition peers; all incoming traffic terminates locally without
  echo. Missing coordination facilities fail startup closed. Pagehide and loss of
  document visibility also terminate locally; hidden pages cannot start an owner.
  Visibility is checked before data admission and reply publication, not only on
  events. Foregrounding cannot resume the closed instance. These are development-only
  controls, not integrated account logout. Notifications are asynchronous, unacknowledged, and
  nondurable; suspended, new, or nonparticipating contexts may miss them. Page events
  are not guaranteed, and same-origin code can observe timing or force locking.
  Neither mechanism supplies a global singleton, durable revocation, hard expiry,
  or protection from hostile code in the owner realm. Visibility is browser-reported,
  not user-presence proof; unobserved transitions during suspension can be missed.
  Synthetic Chromium checks cover tab switching and explicit foreground restoration,
  not mobile suspension, a supported-browser matrix, or product custody.

## Browser account and vault risks

The [account vault](key-management.md#browser-account-vault) and
[account-to-anonymous flow](architecture.md#account-and-anonymous-flow) are planned,
not current controls. Assess them against these boundaries:

| Threat | Required control | Residual risk |
| --- | --- | --- |
| Stolen identity database/backups | Only authenticated ciphertext for member private keys; unlock material remains client-side | Password-wrapped copies permit offline guessing; wrapping/recovery strength limits protection |
| Account/session takeover | Owner-scoped vault access, recent authentication for changes, and separate local unlock | Attacker can deny access or replace encrypted copies; local validation/binding and recovery are still needed |
| Unsupported or replaced passkey | Check PRF outputs and prove local restoration; authorize each added unlock method | Login can succeed while decryption is unavailable; deleting a credential does not revoke copied secrets |
| Weak account recovery | Separate authentication recovery from client-held key recovery; no server decrypt fallback | Lost unlock/recovery material can mean permanent key loss |
| Backup substitution or rollback | Authenticated format, expected enrollment binding, version/concurrency and recovery review | Server-held metadata alone cannot defeat a malicious vault server; no rollback protection is implemented |
| Account-linked review history | No receipts, tokens, reply capabilities, or submission state in the account vault | Eligibility/issuance timing and user content can still correlate activity |
| Identity leakage during handoff | Separate origins, no identity cookies/headers/referrers or link identifiers in submissions; reviewed bounded handoff | Shared infrastructure and a malicious browser distributor can still correlate or exfiltrate |
| Shared device, stale tab, or persisted unlock | Bounded unlocked sessions, coordinated lock/logout/account switch, no persisted plaintext secrets | Browser/runtime copies prevent complete erasure; compromised devices remain outside protection |

Server-stored ciphertext is not a claim that the website operator cannot access
keys: a malicious update can capture them during unlock. Passkeys, PRF, WASM, and
non-extractable browser keys do not make hostile page code trustworthy. See
[browser delivery trust](#browser-delivery-trust) and the dated primary sources in
[key management](key-management.md#research-basis-and-outstanding-evidence).

## Assets and principals

- **Assets:** membership identities, eligibility, keys, answers, token unlinkability,
  vote integrity, reply confidentiality, receipts, audit evidence, availability,
  and distributed-client integrity.
- **Roles:** see [architecture](architecture.md#administrative-access). Visitors and
  members supply lower-trust inputs; no role has unrestricted component access.
- **Assumptions:** secure primitives, good device randomness, reviewed clients
  validating trusted keys, and enforced service boundaries.
- **Limits:** operators can observe network/server traffic. Reviewers can retain
  any answer or key they obtain.

## STRIDE analysis

| Threat | Boundary and intended control | Residual risk |
| --- | --- | --- |
| Spoofing | Certificate proof of possession; passkeys/TOTP and protected sessions for admins | Stolen device keys, stolen sessions, coerced or fraudulent enrollment |
| Tampering | Signed bulletin, authenticated encryption, token verification, log proofs | A malicious publisher can create several valid views without independent consistency checks |
| Repudiation | Tamper-evident administrative events and public checkpoints | A hash chain controlled by one operator can be rewritten before external anchoring |
| Information disclosure | Device encryption, separate storage, minimized metadata, no third-party requests | Identifying text, traffic correlation, small cohorts, reviewer disclosure |
| Denial of service | Request bounds, throttling, database constraints, admission controls | Network saturation, storage exhaustion, and availability tradeoffs remain |
| Elevation of privilege | Scoped roles, server-side authorization, reauthentication, isolated signing | Host or maintainer compromise can subvert code, keys, and access policy |

## Collusion and compromise

| Adversary | What can be learned or changed |
| --- | --- |
| Issuer alone | Identities, cohort membership, and issuance participation; may deny or over-issue tokens if compromised |
| Submission operator alone | Ciphertexts, accepted token inputs, arrival patterns, and service-observed metadata |
| Reviewer alone | Plaintext content and reply capabilities; may infer identity from writing or context |
| Issuer plus submission operator | Blindness protects direct transcript linking under its assumptions, but timing, selective failures, and key partitioning can reduce anonymity |
| CA or enrollment manager | Can issue fraudulent credentials or exclude members; issuance transparency and separation of duties are needed |
| Admin plus reviewer | Can combine cohort and plaintext context; response thresholds do not prevent such inference |
| Compromised client distributor | Can serve code that steals answers or private keys before encryption |
| Compromised endpoint | Can access local plaintext and secrets regardless of transport encryption |
| Global observer | Can correlate flows despite database isolation; not covered by an unconditional anonymity claim |

## Browser delivery trust

- The inert shell uses escaped templates, restrictive CSP, and same-origin hashed
  CSS with SRI. No request values enter templates. Tests do not prove confidentiality.
- CSP, local assets, SRI, pinned WASM hashes, and reproducible builds aid inspection
  and reduce accidental compromise. A hostile origin can replace code and its displayed hash.
- Stronger verification requires an independent signature/checkpoint trust anchor
  and independently obtained verification tooling. An optional CLI can support
  review; it must not become a prerequisite for ordinary browser use. The web-only
  product does not eliminate trust in the delivered client.
- WASM does not protect secrets from its loading page. No complete-erasure or
  universally constant-time guarantee in Go/browser runtimes.

## Small cohorts and content

- Thresholds govern release, not confidentiality from reviewers holding keys and
  ciphertext. Withholding ciphertext helps against honest-but-curious reviewers,
  not collusion with storage operators.
- Differencing, rare answer combinations, and repeated filters can reidentify.
  Publish a minimum cohort policy and restrict cross-filtering.
- One member can submit several responses. Never label response counts as distinct
  participants or turnout. Independent tokens do not prevent content/timing linkage.
- Use one common allowance, not individual limits that partition members.
- Stronger distinct-participant release claims require separate review, not identity
  fields or member slot indices in anonymous storage.

## Revocation, transfer, and deletion

- Fresh revocation checks block future issuance, not already-issued unlinkable tokens.
  Such tokens cannot be identified or selectively revoked.
- Tokens are shareable bearer capabilities. Honest-issuer quotas bound authorization,
  not authorship. Duplicate memberships or a compromised issuer can exceed per-person bounds.
- Submission storage cannot count a member's responses without breaking identity separation.
- Round-key destruction protects past data only if every relevant copy is gone.
  It is not ratcheting forward secrecy. Audit records show a procedure, not proof
  that devices or snapshots erased copies.

## Required security evidence

None of these protocol properties is implemented. Repository checks do not
establish protocol security.

| Intended property | Required evidence before claiming it |
| --- | --- |
| Eligibility | Certificate, challenge, cohort, schedule, and revocation rejection tests |
| Published per-member/round response quota | Real PostgreSQL slot/count concurrency, crash, recovery, and certificate-replacement tests for limits of one and greater than one |
| One accepted submission per token | Atomic canonical spending and payload-rebinding tests |
| Token unlinkability | Standards vectors, shared-key checks, transcript and storage inspection |
| Device-side confidentiality | Request capture, boundary tests, and log inspection proving no plaintext or keys cross into services |
| Browser accounts and encrypted key custody | [Vault acceptance](testing.md#browser-account-and-vault-acceptance), owner-isolation tests, recovery and handoff inspection; no identity-to-submission index |
| Ciphertext integrity | Tampering and cross-context rejection tests |
| Inclusion and append-only consistency | Independent proof verification, mutation tests, and split-view detection |
| Administrative accountability | Role tests and independently anchored audit verification |
| Retention protection | Controlled-copy inventory and restoration exercises with device limits disclosed |

Not provided: coercion resistance, receipt freeness, public-election assurance,
unconditional anonymity, guaranteed erasure, or end-to-end post-quantum protection.
Use established specialist systems where their model better fits the risk.

## Verification and updates

- Map mitigations to [tests](testing.md). Review new boundaries for identities,
  plaintext, keys, metadata, trust anchors, transport, and operator access.
- Track [open requirements](roadmap.md#open-implementation-questions); resolve them
  in their owning reference before implementation.
- Independent code/security review, transitive dependency audits, hosted protections,
  and reproducible-release evidence remain incomplete. One maintainer and repository
  files alone cannot establish independent review.

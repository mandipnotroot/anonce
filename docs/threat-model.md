<!-- SPDX-FileCopyrightText: 2026 Anonce Contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Threat model

Audience: security reviewers, implementers, and organizations considering adoption.

Status: design analysis, not a completed security assessment. The connected browser
application is for synthetic data only. Do not expose the local hosts publicly or
claim production readiness, independent approval or election suitability.

## Current controls and limits

### Connected local browser MVP

The browser services implement verified WebAuthn ceremonies, protected digest-only
sessions, exact-origin CSRF checks, bounded authentication/input, worker-owned keys,
owner-scoped encrypted member backups, single-use enrollment, authorized publication,
blind quotas, anonymous HPKE answers, signed storage acceptance and local review.
The [cryptographic profile](cryptography.md#browser-mvp-profile-1) and
[API](api.md) specify the admitted composition.

One browser journey spans separate identity and anonymous origins. Exact
origin/window checks and credential-free anonymous requests constrain the handoff;
they do not stop global traffic correlation, colluding operators or malicious
website delivery. Common round links contain no member identifier or bearer secret.

Signed acceptance follows committed exact ciphertext under a canonical spend. It
does not establish public-log inclusion, append-only consistency, independent
anchoring, resistance to privileged database rollback or availability after loss.
Publication trust is operator-configured; independently detected split views remain
unimplemented. Interrupted issuance consumes the sole allowance without refund.

### Account sessions

Inventory exposes at most 16 own live sessions with non-secret selectors,
timestamps and a current marker, not device/IP/user-agent or anonymous activity.
Revocation rechecks live ownership and recent authentication after account locks.
Passkey reauthentication is single-use, purpose/account/original-bearer bound and
rotates without extending absolute expiry. It cannot revive a revoked session.

Sign-out locks local workers before transport. Successful sign-out sends a
secret-free same-partition notice; observed `401` clears local state. Foreground
checks and a 30-second visible-page heartbeat are best-effort observation, not
instantaneous distributed erasure. Suspension, network failure, hostile code,
copied plaintext and already admitted work remain outside this boundary. Revoking
sessions does not revoke membership or delete encrypted backups.

### Reviewer record isolation

A member can submit a structurally valid envelope that the reviewer cannot
decrypt. Reviewer pages reject that record individually and continue with later
records. Worker closure, round expiry, hidden-page state, and owner replacement
still stop the read. This does not authenticate answer contents or prevent
identifying text.

### Local container infrastructure

Independent PostgreSQL instances have separate networks, volumes and credentials.
Runtime roles do not own schema or assume the migration owner. Each browser service
receives only its own runtime credential and read-only service state. Separately
scoped operator containers apply immutable migrations before HTTP startup.

Native listeners are loopback-only. Explicit container networking admits only
the matching fixed database hostname and IPv4 wildcard listener; Compose publishes
TLS on host loopback. Non-root users, read-only roots, dropped capabilities, resource
limits and disabled logging reduce local exposure. Edge bridges permit outbound
traffic; they are not egress firewalls or network-anonymity controls.

Host/daemon administrators can access both boundaries. Database credentials and
development signing files remain plaintext on the host. Round RSA keys lack
protected signer custody. Local database TCP is not a production TLS deployment.
Encrypted restoration, image-scan/SBOM evidence and production operation are missing.

Initialization accepts empty owner-only state and does not replace keys. Partial
state or browser data without its original state fails closed. TLS probes verify
the configured hostname and root without bypassing verification. Local certificate
expiry still requires operator handling. See [deployment](deployment.md).

### Storage and transactions

The account store retains only SHA-256 session verifiers and enforces absolute
database-clock expiry, session admission limits and account-first locking.
Session-scoped backup access derives ownership from the bearer, rechecks expiry
after lock waits and serializes with revocation/disable. Sensitive mutations
require authentication within five minutes. Trusted owner-ID library operations
are not public authorization interfaces.

Member backups have a fixed public binding, bounded envelope, revision checks
and retained deletion tombstones. Storage admission verifies only public envelope
structure, not password authentication or encrypted-key validity. These stores do
not provide malicious-server rollback detection, snapshot destruction or recovery.

The submission store atomically binds a round/spend to immutable ciphertext.
Uniqueness arbitrates concurrent spending; only exact-payload retries return the
same reference. Database-clock windows and cancellation serialize with admission.
The browser handler must validate the token and envelope before calling this store;
accepting caller-supplied spend digests directly would bypass authorization.

### Device keys and workers

Shared typed key import authenticates backup purpose and validates canonical
payloads before exposing a key. Member restoration requires the expected public
binding and never generates a replacement after failure. Fixed enrollment and
issuance signing do not expose an arbitrary signing oracle.

Dedicated workers bound operations/lifetime and terminate on lock, disposal or
observed hidden-page/clock failure. Correlated messages have strict fields, byte
bounds and method/result allowlists. Late replies cannot revive a closed owner.
Same-partition lock notifications contain no secrets but are not durable,
acknowledged or cross-device. Same-origin code can trigger local denial of service.

Workers and WASM are not boundaries against their own website, host or distributor.
JavaScript strings, Go/library copies, Argon2 arenas, swap and crash dumps prevent
complete-erasure guarantees. Suspended pages cannot enforce hard deadlines until
they resume. Manifest hashes detect build mismatch, not malicious distribution.

## Browser account and vault risks

| Risk | Implemented boundary | Remaining limitation |
| --- | --- | --- |
| Stolen identity database | Encrypted member keys; unlock passphrases remain local | Offline password guessing; write compromise and malicious delivery remain serious |
| Backup substitution | Typed validation, expected-key matching and same-browser public pin | New-device trust depends on server metadata; rollback is not independently detected |
| Stolen account session | Digest-only storage, expiry, CSRF and recent-authentication gates | An active bearer can exercise its permitted authority until invalidated |
| Lost passkey/passphrase | No server decryption or silent replacement | No account/key recovery; permanent loss is possible |
| Lost reviewer browser storage | No reviewer backup uploaded | Review access can be permanently lost |
| Review deadline | Server ciphertext access expires | Already obtained keys/ciphertext/plaintext cannot be recalled |
| Login mistaken for unlocking | Separate passkey and local passphrase steps | Future PRF support needs its own reviewed profile and compatibility evidence |
| Dashboard correlation | No account-linked submission/receipt history | Issuance participation and timing remain visible on the identity side |

See [custody and recovery requirements](key-management.md#browser-account-vault).

## Assets and principals

Protect membership/eligibility, quotas, signing keys, device keys, answers, tokens,
reply capabilities, encrypted backups and availability. Members, assigned reviewers,
administrators, operators, website distributors and external observers have different
authority. A public key or opaque identifier can still be linkable. Do not reuse
identity-side identifiers in anonymous requests, storage or diagnostics.

## STRIDE analysis

| Class | Required control or limit |
| --- | --- |
| Spoofing | Verified passkeys, membership checks, trusted bulletin keys and round-bound tokens |
| Tampering | Canonical signatures/AEAD, atomic spending and immutable bindings; independent proofs remain Next |
| Repudiation | Signed acceptance only proves its stated storage contract; separately anchored audit is required |
| Information disclosure | Local decryption, separate origins/stores, no sensitive logs; timing/content limits remain |
| Denial of service | Bounded parsing/work/concurrency; per-process counters do not stop distributed saturation |
| Elevation of privilege | Server-side object/role checks, session-derived owners and scoped database grants |

## Collusion and compromise

The design does not protect against compromised devices, hostile browser-delivered
code, all-operator collusion or global traffic observation. Blind signatures do not
hide issuance timing or identifying answers. A compromised reviewer key grants
read and decrypt authority for that round. This system is not coercion-resistant.

## Browser delivery trust

First-party assets, CSP, no external fonts/analytics, content-addressed entry assets,
SRI and runtime manifests constrain accidental drift and some injection paths.
They do not stop a malicious distributor that can replace both code and hashes.
Require reproducible, verifiable releases and independent trust distribution before
claiming stronger delivery assurance. Never weaken CSP, browser sandboxing, TLS,
user verification or CSRF to obtain a passing test.

## Small cohorts and content

Small anonymity sets, publication timing, repeated wording and identifying answers
can reveal authors. Response limits and minimum response counts do not prove
distinct participation. A key-holding reviewer can bypass client display thresholds;
stronger release guarantees need a separately reviewed mechanism. Bound filters and
aggregates before offering charts, exports or threshold claims.

## Revocation, transfer, and deletion

Revocation prevents future authorized operations under its policy, not decryption
of already copied material. Issued anonymous tokens cannot be mapped back to
membership certificates. Recovery and replacement must preserve consumed allowance.
Deleting active records does not erase snapshots, exported keys, reviewer copies,
swap or backups. Restoring storage must not reactivate expired reviewer access.

## Required security evidence

Require independent composition review, real database grant/race/isolation tests,
browser handoff/custody evidence, negative authorization cases, supported-provider
and mobile measurements, manual accessibility review, protected signer evidence,
encrypted restoration drills, sensitive-log inspection and verifiable releases.
Public transparency, audit, recovery, replies, stronger result release and broader
response limits need implementation plus attack tests before claims.

The [test mapping](testing.md) distinguishes executable checks from planned
acceptance cases. A passing component test is not a full security assessment.

## Verification and updates

Update this model when authority, cryptography, storage, browser delivery or
retention changes. Record concrete principals, trust boundaries and observable
outcomes. Report missing validation honestly and disclose vulnerabilities privately
under [SECURITY.md](../SECURITY.md).

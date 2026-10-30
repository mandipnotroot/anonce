<!-- SPDX-FileCopyrightText: 2026 Anonce Contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Key management

Audience: implementers, reviewers, and operators responsible for secret custody.

Status: the browser manages member and round-scoped reviewer keys through shared
Go cryptography in dedicated workers. Use synthetic data only. Recovery, protected
signer custody and production retention policy are not implemented.

## Browser account vault

### Implemented local-passphrase MVP

Members sign in with a passkey, then set up or unlock private access in the same
browser workspace. Setup collects two independent local passphrase entries and
automatically prepares a random member key, encrypted backup and enrollment request.
Users do not generate, upload, download or manage key files or certificate requests.
See the [account workflow](ui-design.md#account-and-review-workflow).

Only the 108-byte encrypted member backup, public binding and revision enter the
identity vault. Writes require a live session, CSRF protection and recent
authentication. Restoration authenticates the ciphertext and matches the complete
expected public key before installing a key. Wrong passphrases, corrupt backups,
binding mismatches and cancellation never create a replacement key.

A same-browser public pin detects changed server binding metadata. A new device
must trust that metadata. This does not provide malicious-service substitution or
rollback protection. Account access alone cannot decrypt the backup.

Reviewer keys are fresh per round and generated automatically in a separate worker.
Their encrypted backups stay only in identity-origin IndexedDB under account/round
context. Publication freezes the public binding, which restoration checks before
use. No reviewer private key or encrypted backup is uploaded. Clearing browser
storage, losing the passphrase or changing device can permanently lose review access.

### Authentication and unlocking

Account authentication, local unlocking and anonymous authorization are distinct
security checks inside one browser journey. Passkey sign-in and reauthentication
do not unlock private keys. Reuse an unlocked worker where its lifetime permits;
do not ask for a passphrase for every form action.

Authentication follows [WebAuthn Level 3, Recommendation of 2026-08-25](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/).
The server verifies the exact relying party and origin with user verification
required. The [session controls](api.md#browser-session-management) bind
reauthentication to the existing bearer and preserve absolute expiry.

The implemented unlock method is a local passphrase using
[device-backup profile 2](cryptography.md#device-backup-profile-2). It never enters
an HTTP request. There is no server-held unlock key or decryption fallback.

Passkey-assisted unlocking is Next research, not a second supported workflow.
Before adopting the [PRF extension](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/#prf-extension),
review the [wrapping boundary](cryptography.md#browser-vault-profile-boundary),
credential-specific secrets, recovery, browser/provider behavior and prompt counts.
Ordinary passkey support does not establish PRF support. Never serialize PRF output
with server authentication or downgrade after a failed decryption.

### Storage and lifecycle

- The identity service derives vault ownership from the session. Its
  [store](database.md#session-scoped-member-backup-access) serializes access with
  revocation and account disabling, and rejects stale revisions or changed bindings.
  Envelope admission alone cannot authenticate encrypted contents.
- Keep answers, tokens, issuance transcripts, receipts and reply capabilities out
  of the account vault. Restoring a member backup does not restore anonymous state.
- Never persist plaintext keys, passphrases or unlock material in browser storage,
  URLs, diagnostics or server databases. Browser storage is untrusted and may be evicted.
- Lock/logout, account switching, hidden-page disposal and worker deadlines clear
  accessible buffers and terminate owned workers. Same-partition notifications
  coordinate participating tabs; visible-page checks observe server invalidation.
- Session revocation prevents new server admission. It does not recall previously
  obtained keys, plaintext or work already admitted. Suspended pages may miss cleanup.
- Reviewer server backup needs a separately reviewed round-binding, expiry,
  snapshot and destruction policy before implementation.

### Recovery and compromise

Account recovery and encrypted-key recovery are not implemented. A login reset or
administrator action alone cannot decrypt existing keys. If the passphrase is lost,
explain the permanent loss rather than silently replacing an enrolled key.

Any future recovery must preserve membership quotas, consumed reservations and
review deadlines. Adding a passkey must not implicitly grant decryption access.
Specify recovery entropy, wrapping, authorization, replacement, notification and
all-methods-lost behavior before offering it. Do not add required key-file handling.

Password-wrapped backups permit offline guessing after theft. Server rate limits
cannot stop it. Rewrapping a key does not revoke copied backups, keys or plaintext.
Compromised keys need a separate rotation/revocation policy. A malicious website
or compromised device can steal secrets while unlocked, including PRF outputs.

### Research basis and outstanding evidence

Primary sources consulted 2026-10-27:

- WebAuthn Level 3 above and the working group's
  [PRF explainer](https://github.com/w3c/webauthn/blob/main/explainers/prf-extension.md).
- [OWASP browser storage guidance](https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#storage-apis).
- NIST SP 800-63B-4 [account recovery](https://pages.nist.gov/800-63-4/sp800-63b/events/#recovery)
  and [customer experience](https://pages.nist.gov/800-63-4/sp800-63b/customer/).

These references do not specify encrypted-vault recovery or establish an assurance
level here. Supported browser/provider, mobile cost, recovery and manual accessibility
evidence remain outstanding. See [acceptance requirements](testing.md#browser-account-and-vault-acceptance).

## Inventory

| Key or secret | Custodian | Separation and lifetime |
| --- | --- | --- |
| Membership CA | Identity service | Dedicated signing key; protected production custody still required |
| Member signing key | Member worker | Random Ed25519 key; only encrypted backup leaves the device |
| Enrollment code | Member until consumed | Random, expiring, single-use; server stores its digest |
| Blind-signing key | Identity service | Dedicated RSA key per round/profile; not a CA key |
| Reviewer key | Reviewer worker | Fresh X25519 key per round; encrypted copy stays in this browser |
| Publication key | Identity service | Separate from membership and token keys |
| Receipt key | Submission service | Signs durable storage acceptance, not public-log inclusion |
| Session secret | Identity service and protected cookie | Digest-only storage, bounded absolute expiry |
| Unlock passphrase | User and local browser operation | Never sent to services or retained by the worker |

Reply capabilities and transparency/audit signing keys require separate profiles
when those planned components are implemented.

## Protected CA storage

Production signing custody remains required, not implemented. Keep unlocked signers
behind narrowly authorized interfaces, separate encrypted keystores from unlock
material, and never expose a universal signing oracle. Specify rotation, restoration
authority and expired-key rejection. Optional hardware or dual control cannot replace
authorization, mechanism tests and independent review.

## In-memory member sessions

`internal/client/membersession` owns one locked or unlocked key without I/O or a
raw-private-key export API. Confirmed creation prepares a key, encrypted backup and
fixed identity-free request before retaining the key. Unlock requires the expected
public binding; request generation and profile-bound issuance signing never accept
arbitrary messages.

Setup, restoration and encrypted export share one admission slot. Lock cancels
pending work and prevents late key installation. Export snapshots the retained key
under lock and clears its temporary copy before releasing admission. It does not
rotate the key or invalidate existing backups. Callers own returned buffers and
must clear mutable secrets after use. Argon2id cannot be interrupted mid-derivation.

## Device keystores

`internal/client/keystore` implements bounded Argon2id and ChaCha20-Poly1305 backup
encryption. Typed `memberkey` and `reviewerkey` wrappers generate keys and validate
canonical PKCS #8 payloads with distinct authenticated purposes. See the
[cryptographic profiles](cryptography.md#keystore-composition).

Authentication failure or malformed input returns no partial key. Unknown profiles
fail before derivation. Owned temporary buffers are cleared where possible, but
library arenas, immutable strings, runtime copies, swap and crash dumps prevent
complete-erasure guarantees. The format alone provides no freshness, revocation,
round binding or recovery.

## Local WASM member sessions

The member WASM adapter is part of the browser runtime, built automatically by
`make build`. `make member-wasm-test` checks the same adapter in Node and Go. It
is loaded only inside the identity-side dedicated worker, never the anonymous page.

The bridge bounds and snapshots nonshared `Uint8Array` inputs before asynchronous
work, admits one operation, and returns only public enrollment material or encrypted
backups. Passwords are 1–1024 bytes, backups 108 bytes, public keys 32 bytes and
requests 129 bytes. Failure resolves to `null` without a replacement-key fallback.
Confirmed setup/export compare both inputs in shared Go before derivation. Lock
cancels work; close removes the namespace after pending cleanup.

Profile-bound `authorize` validates the 113-byte challenge, signed common bulletin,
configured publication key and blinded request before signing in shared Go.
It is not an arbitrary message-signing API.

The bridge follows pinned [Go JS bindings](https://pkg.go.dev/syscall/js@go1.27.3)
and [ECMAScript 2025 typed-array semantics](https://262.ecma-international.org/16.0/#sec-typedarray-objects),
consulted 2026-10-27. WASM is not a secret boundary from its trusted host.

## Local member worker host

`MemberWorkerSession` owns the matched member runtime and its correlated, bounded
transport. At most one live owner exists per module realm, not per device or account.
Construction requires module workers, BroadcastChannel, page events, a visible
document and usable monotonic/wall clocks. Missing facilities fail closed.

Startup is bounded to 30 seconds, operations to 120 seconds and total lifetime to
five minutes. Admission, readiness and reply publication recheck both clocks.
Invalid, backward or overdue readings terminate locally. These development budgets
are not evidence of mobile support or hard expiry during suspension.

The `ready` Promise reports startup, and `closed` reports terminal local cleanup
without secrets or a reason. An optional `AbortSignal` cancels the owner's lifetime.
Lock terminates locally and notifies participating peers; close/disposal stays local.
Pending work resolves to `null`, late replies cannot revive it, and restoration
requires an explicit new owner. No automatic restart or silent unlock occurs.

Commands use exact versioned fields, increasing safe-integer correlation IDs and
fixed method/input/result allowlists. Unknown, duplicate or malformed replies
terminate the owner. WASM fetches omit credentials/referrers, reject redirects and
bound streams to 8 MiB. Deploy loader, worker, bridge and manifests together.

### Browser passphrase text interface

The page uses `createWithPassphrase`, `unlockWithPassphrase` and confirmed export
over the same Go backup composition. UTF-8 encoding accepts only well-formed
primitive strings with 1–1024 encoded bytes. No trimming, normalization, lossy
conversion or alternate encoding is allowed. Independent confirmation entries are
compared in Go. Mutable encoding buffers clear synchronously after snapshots;
DOM fields clear promptly. Immutable strings and autofill copies cannot be erased.

See the [encoding profile](cryptography.md#browser-passphrase-text-encoding).

### Lock notifications and page disposal

The fixed `anonce.member-lock.v1` channel carries only `"lock"`, without account,
key or submission identifiers. Any received message or decoding error terminates
locally without rebroadcast. Notifications are same-origin/partition, asynchronous,
non-durable and unacknowledged. They are not global revocation or authorization.

`pagehide` and loss of document visibility terminate locally. Returning to the
foreground requires explicit restoration; interrupted setup must not silently
replace a key. Missing visibility reads fail closed. Suspended or blocked pages
cannot perform cleanup until they run again, and worker termination does not prove
memory erasure. The website distributor and same-origin code remain trusted.

These controls follow the WHATWG [worker](https://html.spec.whatwg.org/multipage/workers.html),
[BroadcastChannel](https://html.spec.whatwg.org/multipage/web-messaging.html#broadcasting-to-other-browsing-contexts)
and [page visibility](https://html.spec.whatwg.org/multipage/interaction.html#page-visibility)
models, consulted 2026-10-28. See [checks](testing.md#wasm-member-session-checks).

## Retention and destruction

Destroy controlled round-key copies after their approved retention deadline and
record the authorized outcome. Inventory encrypted backups, snapshots, swap and
crash dumps; deleting one active record is insufficient. Reviewers can retain keys
or plaintext. Server read expiry is not device erasure or forward secrecy.
See [retention limits](threat-model.md#revocation-transfer-and-deletion).

## Incident handling

Stop exposed signers, revoke affected membership where supported and review token
and trust-anchor impact. Issued anonymous tokens cannot be mapped back to revoked
certificates. Rotation and restoration need explicit authorization and compatibility
review. Never silently accept replacement trust material.

<!-- SPDX-FileCopyrightText: 2026 Anonce Contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Cryptographic composition

Audience: cryptographic reviewers and client implementers.

Status: device-backup encryption, local member/reviewer-key generation/import/export,
and identity-free member certificate requests are implemented as shared Go packages.
Identity-side session references use the storage profile below. The default browser
hosts use MVP profile 1 for enrollment, blind authorization, encryption and signed
storage acceptance. Broader public-proof protocols remain prospective.

## Chosen implementation boundaries

### Browser MVP profile 1

This unreleased browser composition uses the primary RFC 9474 and RFC 9180
references below, consulted 2026-10-29, CIRCL 1.6.5 `blindrsa`, and Go 1.27.3
`crypto/hpke`, `crypto/ed25519`, and `crypto/x509`. It is not independently approved
or Privacy Pass wire-compatible. Unknown versions and lengths fail closed. No
fallback algorithm is allowed. All integer fields below are unsigned big-endian;
byte strings are concatenated in the stated order, without delimiters.

- Bulletin: ASCII `ANONCER1`, random round ID (16), opening, closing and review
  expiry Unix seconds (8 each), explicit response limit (1, must equal one), fresh
  round reviewer X25519 public key (32), dedicated round RSA modulus (384), receipt
  Ed25519 public key (32), question byte length (2), well-formed UTF-8 question
  (1–1024). RSA is exactly 3072 bits, odd modulus, exponent 65537. Times are within
  2026–2100 with integral-second precision, opening precedes closing, and review expires after closing within 30
  days. The publication signature is pure Ed25519 over ASCII
  `anonce/bulletin/v1` followed by NUL and these bytes. Append its 64 bytes.
  The bulletin digest is SHA-256 of the complete signed bulletin. The publication
  verification key is operator-configured, not accepted from the bulletin.
- Token input: ASCII `ANONCET1`, round ID (16), bulletin digest (32), fresh random
  nonce (32). CIRCL prepares this with its own fresh 32-byte random prefix and
  uses `SHA384PSSRandomized`, including the 48-byte PSS salt. The token is the
  resulting prepared message (120) followed by its finalized signature (384).
  Verify exact context and signature before storage. Spend identity is SHA-256
  of ASCII `anonce/spend/v1`, NUL, and the prepared message, never signature bytes.
- Issuance challenge: version byte one, round ID (16), bulletin digest (32), fresh
  random nonce (32), SHA-256 of blinded request (32). The member signs only these
  113 bytes prefixed by ASCII `anonce/issuance/v1` and NUL. Challenges expire after
  two minutes, are session/member-bound, and are consumed before quota reservation.
  The identity ledger retains membership/round reservation only, not transcripts.
  Lost signing/delivery consumes the sole allowance without refund or re-signing.
- Answers: HPKE base mode, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256,
  ChaCha20-Poly1305, one fresh sender context per answer. `info` is ASCII
  `anonce/answer/v1`, NUL, bulletin digest; AAD is empty. Plaintext is exactly 4096
  bytes: a two-byte text length (1–4000), well-formed UTF-8 text, and zero padding.
  Envelope is byte one followed by `enc || ciphertext`; exactly 4145 bytes.
  Decryption validates length, UTF-8 and every padding byte before exposing text.
- Reviewer read authorization: the server generates 32 random bytes, retains only
  their SHA-256 digest bound to round and pagination cursor for two minutes, and
  HPKE-encrypts them to the bulletin reviewer key. `info` is ASCII
  `anonce/review/v1`, NUL, bulletin digest. Envelope is byte two followed by
  `enc || ciphertext`, exactly 81 bytes. Returning the decrypted 32 bytes consumes
  that challenge atomically before a bounded ciphertext read. No account cookie,
  member credential or identity identifier is accepted by this interface. This
  online proof of decryption adds no signing primitive and cannot decrypt answers
  for the server. Compromise of the reviewer key grants both read and decrypt access.
- Acceptance: ASCII `ANONCEA1`, round ID (16), bulletin digest (32), durable record
  ID (16), spend digest (32), SHA-256 of the exact envelope (32), followed by a pure
  Ed25519 signature (64). Sign only after the atomic record store commits. Verify
  all fields and the bulletin's receipt key locally. Exact-payload open-round
  retries reproduce acceptance; changed payloads and closed-round retries fail.
  This is a signed storage attestation, not inclusion, append-only consistency,
  external anchoring, or a guarantee against database rollback. The broader
  transparency-log contract remains Next work, not a property of this MVP.

Enrollment reuses CSR profile 1. A dedicated Ed25519 CA issues an empty-subject
X.509 leaf with random positive 16-byte serial, digital-signature usage, no CA
authority, and one-year validity. Only the exact stored certificate/public binding
for an active membership is eligible. Issuance checks the signature, validity and
current membership state online inside the identity boundary; it does not rely on
an absent CRL endpoint. An authorized administrator delivers a random 32-byte,
expiring, single-use enrollment code. Only its SHA-256 digest is stored. Consuming
it and binding the verified CSR to the account's fixed backup key is atomic.

WebAuthn authentication follows the selected Level 3 reference in
[key management](key-management.md#authentication-and-unlocking), verified by
go-webauthn 0.18.2 with exact HTTPS origin/RP ID, user presence and user verification
required, no cross-origin ceremonies, no attestation identity requirement, and no
PRF extension. Two-minute ceremonies are cookie-bound and single-use, including
failed verification. One credential per account and no account recovery are the
initial compatibility limits. Login does not unlock a device key.

| Purpose | Proposed implementation/profile |
| --- | --- |
| Membership and bulletin signatures | Go `crypto/ed25519`, `crypto/x509`; dedicated keys per purpose |
| Blind tokens | CIRCL `blindsign/blindrsa`; RFC 9474 randomized preparation, SHA-384/PSS, dedicated RSA round keys |
| Submission and reply envelopes | Go `crypto/hpke`; DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305, base mode |
| Device-backup encryption | `golang.org/x/crypto/chacha20poly1305.New`; RFC 8439, device-backup profile 2 |
| Password hashing and keystore derivation | `golang.org/x/crypto/argon2`, Argon2id |
| Log tree and proofs | `golang.org/x/mod/sumdb/tlog` and signed notes; C2SP checkpoint conventions |
| Randomness | `crypto/rand` through library interfaces |

## Local browser TLS

Local browser TLS uses the existing Go `crypto/x509` ECDSA P-256 initialization,
not a new primitive. The emitted root certificate is parsed before issuing leaves,
so the library copies its subject identifier into each leaf's authority identifier.
This follows [RFC 5280 section 4.2.1.1](https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.1),
consulted 2026-10-30. Native/container probes verify the exact configured name and
local trust root, with TLS 1.3 minimum and no verification bypass. Public root copies
in each read-only service mount do not expose its peer's private signing state.
Expired/nonconforming old certificates fail; startup never replaces existing keys.

## Account session storage profile

The separate browser host now composes this profile with
[passkey reauthentication and session controls](api.md#browser-session-management).
Reauthentication retains the selected WebAuthn verification requirements, binds the
stored ceremony to its purpose/account and the original bearer's SHA-256 digest,
and calls expiry-preserving rotation only after verification. Session selectors
remain non-secret and independent of tokens/digests. No new primitive, backup
format, anonymous identifier or device-key unlocking mechanism is introduced.
This retains the selected [WebAuthn Level 3](key-management.md#authentication-and-unlocking)
relying-party verification and [OWASP session renewal guidance](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#renew-the-session-id-after-any-privilege-level-change),
consulted 2026-10-29; five-minute admission is a project-specific development policy.

The internal account store generates independent 16-byte account IDs and 32-byte
opaque session secrets with Go `crypto/rand`. Session secrets contain no identity
or claims. Store only `crypto/sha256.Sum256(secret)` as the indexed verifier;
the raw secret is returned once in caller-owned mutable bytes, never sent to SQL.
Hash lookup does not require a secret-byte comparison in application code. This
is not password hashing, a JWT, a blind token, or a browser wire format.

Accept exactly 32 raw bytes before hashing. Session lifetimes are integral seconds
from one second through 12 hours, with no sliding renewal. PostgreSQL supplies
creation/expiry times and checks expiry on each resolution. These are development
storage limits, not a reviewed product authentication or reauthentication policy.
Raw secrets must be cleared after protected delivery; runtime/transport copies
cannot be guaranteed erased. SQL traces must not collect parameters or results.

This follows the [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
on random opaque secrets, one-way server storage, server-side expiry, and token
replacement after reauthentication (consulted 2026-10-28). Read-only theft of digests
alone does not yield bearer secrets, but application compromise, write access,
or a stolen secret defeats this boundary. Passkey verification, cookie
encoding/delivery, CSRF, idle expiry,
and authentication ceremonies are not implemented by this store.
Account sessions never unlock device backups or authorize anonymous submissions.

The account store also enforces a fixed development limit of 16 unexpired sessions
per account under its existing account lock. This is a
[storage admission policy](database.md#implemented-account-storage), not a change
to randomness, digest composition, lifetime, or any cryptographic format.

The internal [session inventory](database.md#session-scoped-session-inventory)
reuses this same digest and account-lock authorization, returning timestamps, a
current-session marker, and an independent non-secret row selector. Identity
migration 4 uses PostgreSQL 18's random UUID generator for selectors, not a hash
or truncation of bearer material. A selector is never accepted as a credential.
Rotation replaces it. Neither bearer secrets nor stored digests are returned;
device cryptographic profiles and session secret generation are unchanged.

Internal [session-scoped member-backup access](database.md#session-scoped-member-backup-access)
reuses this exact digest/expiry profile for owner authorization. It neither derives
an unlock key nor changes encrypted backups, session secrets, or browser formats.

After independently verifying fresh authentication for the same account, a trusted
caller may use `RotateSession` to atomically replace one live token with a fresh
random token. The new row's creation time records that authentication admission;
its absolute expiry is copied unchanged. No bearer-only renewal is permitted.
Session-scoped backup writes and
[sibling-session revocation](database.md#session-scoped-sibling-revocation) require
creation within the preceding five minutes, using the same shared admission window
checked with the database clock after the account lock. Sibling revocation neither
rotates the retained token nor changes its timestamps or device keys. This is a
development storage policy, not proof of a verified ceremony or a product assurance level.
The same gate applies to [selected sibling removal](database.md#session-scoped-selected-revocation).
Its non-secret selector only locates a row after bearer authorization; it is not a
credential and adds no cryptographic profile.
See the [transaction contract](database.md#session-scoped-member-backup-access).

[Session-scoped sign-out everywhere](database.md#session-scoped-sign-out-everywhere)
uses the same bearer digest and recent-admission check, deleting the current token
as well as siblings. It adds no cryptographic operation or profile and does not
lock or revoke device keys.

[Session-scoped account disabling](database.md#session-scoped-account-disabling)
also uses this unchanged digest and recent-admission policy. Account status and
session references change atomically; encrypted backups and device keys do not.
It adds no cryptographic profile, key revocation, or key recovery mechanism.

## Membership and authorization

The development [database bootstrap](database.md#local-container-bootstrap) uses
PostgreSQL 18's native [SCRAM-SHA-256 authentication](https://www.postgresql.org/docs/18/auth-password.html)
for TCP connections (consulted 2026-10-28), with separate random machine credentials.
This is not an account-password policy, vault unlock method, or device-key wrapping
profile. Existing backup, member-key, and CSR profiles are unchanged.

- Local requests use [member CSR profile 1](#member-csr-profile-1). This is not
  certificate issuance or an enrollment transport.
- Generate keys and CSRs on the device. The CA checks proof of possession and
  membership, issues bounded-lifetime certificates, and publishes signed CRLs.
- Fix extensions, chain rules, serial handling, and revocation freshness before
  implementation. Fail issuance closed without required freshness. Revocation
  cannot identify issued anonymous tokens.
- The application profile does **not** claim byte-for-byte Privacy Pass compatibility.
  Never silently substitute its randomized preparation or RSA modulus policy into
  RFC 9578's registered format.
- Fix canonical token input, domain context, key validation, and vectors before wire code.
- Give all round members the same public key, limit, and context to avoid partitioning
  anonymity. Bind tokens to the common bulletin/profile through reviewed encoding.
- Use independent single-use tokens with fresh randomness, not repeat spends.
  Never encode identity-side slots, counters, or member IDs in tokens.

### Member CSR profile 1

The automatic enrollment request profile uses RSA Security Inc. Public-Key Cryptography
Standards (PKCS) #10 version 1.7, as published in
[RFC 2986](https://www.rfc-editor.org/rfc/rfc2986), and the Ed25519 identifiers
in [RFC 8410](https://www.rfc-editor.org/rfc/rfc8410.html#section-6)
(sources accessed 2026-10-27). It requires independent review before real use.

- `internal/client/membercsr` creates requests through `crypto/x509` using an
  existing, internally consistent Ed25519 member key. Callers cannot supply a
  subject, attributes, extensions, arbitrary signed message, or another algorithm.
- Output is exactly 129 bytes of canonical DER: version zero, empty subject
  (`30 00`), Ed25519 SubjectPublicKeyInfo, and an empty mandatory attributes field
  (`a0 00`). Both algorithm identifiers are `1.3.101.112` with absent parameters.
  The signature is pure Ed25519 over the DER CertificationRequestInfo, with no
  prehash or additional context. No PEM, trailing data, or alternate encoding is accepted.
- Parsing checks size before ASN.1 work, uses `x509.ParseCertificateRequest`,
  compares the complete request with the canonical empty-subject/attribute encoding,
  and verifies with `CertificateRequest.CheckSignature`. Failures return no public
  key. Returned public bytes are independently owned.
- Cancellation is checked at generation entry and before returning output. Inputs
  remain caller-owned and must not be mutated during a call. Owned derived private
  buffers are cleared; library/runtime copies cannot be completely erased.
- Requests contain only a public key and its signature, but are linkable to that
  membership key. Never send them to the anonymous submission origin. Deterministic
  repeated requests do not establish freshness, identity, eligibility, or authority.

The request profile alone grants no authority. Browser enrollment separately
authenticates the account, checks its fixed backup binding and atomically consumes
the invitation under [browser profile 1](#browser-mvp-profile-1).

### In-memory member session composition

`internal/client/membersession` composes the existing member-key, password-backup,
and CSR profiles without adding a primitive, envelope, or browser interface.
Creation generates a random key, encrypts its backup, and prepares its request
before retaining the key. Restoration authenticates and validates the backup,
then compares the complete public key with a required independently trusted
expected key before preparing a request or installing the key in the session.

An unlocked session can export a fresh encrypted backup under a supplied local
password through the same `memberkey.Seal` composition. Each export uses full
profile-2 costs and fresh salt/nonce, preserves the member key, and returns only
ciphertext. It neither changes the session's key nor revokes existing backups.
Lock cancels pending export without waiting for Argon2id; owned temporary key
copies and discarded ciphertext are cleared before admission is released.

Opt-in `CreateConfirmed` and `BackupConfirmed` validate two independent password
bounds and use [Go 1.27.3 `crypto/subtle.ConstantTimeCompare`](https://pkg.go.dev/crypto/subtle@go1.27.3#ConstantTimeCompare)
before delegating to those same compositions (consulted 2026-10-28). Equal-length
comparison is independent of byte contents; differing lengths reject immediately.
No padding copies, text normalization, JavaScript comparison, or new cryptographic
profile is introduced. This is a local confirmation check, not a universal browser
timing guarantee or proof that two independent entries were collected.

Only public enrollment material and encrypted backups leave the session API.
Lock clears its owned private buffer and cancels pending setup/restoration/export; a
cancelled operation cannot install a key. One pending setup/restoration/export per
session is admitted, including while cancellation waits for bounded Argon2id work. This
does not bound the number of sessions a caller creates. See the
[session lifecycle](key-management.md#in-memory-member-sessions) for ownership and
integration limits. PRF wrapping and account recovery remain unspecified.

### Browser passphrase text encoding

The browser worker's [text passphrase interface](key-management.md#browser-passphrase-text-interface)
uses UTF-8 through the [WHATWG Encoding Standard](https://encoding.spec.whatwg.org/#interface-textencoder)
(Living Standard consulted 2026-10-28). Only primitive, well-formed JavaScript
strings are accepted, with 1–1024 encoded bytes. Unpaired UTF-16 surrogates fail
before encoding, rather than being silently replaced with U+FFFD. No trimming,
normalization, case folding, BOM insertion, or password-strength claim is added.
Whitespace, NUL, and explicitly supplied U+FEFF remain part of the password.
Setup/export confirmation still compares encoded bytes in shared Go, not JavaScript.
This is an explicit text-to-byte adapter over profile 2, not a new backup format;
the existing opaque-byte methods remain unchanged.

## Encryption and public proofs

The internal [submission record store](database.md#implemented-submission-record-storage)
adds no cryptographic primitive or wire profile. Its caller must verify tokens and
derive canonical spend digests before storage. Byte-identical ciphertext comparison
binds retries without a new public hash construction. Storage references and
timestamps are not signed receipts, commitments, or inclusion proofs. The 64 KiB
storage ceiling does not admit an HPKE encoding or replace envelope validation.

- HPKE base mode avoids identifying sender keys; token verification authorizes submission.
- Bind protocol version, round ID, bulletin/form digest, and purpose through the
  reviewed HPKE context/authenticated-data contract. No custom KEM combiner or signing scheme.
- HPKE alone does not stop replay, hide plaintext length, or guarantee forward secrecy
  while recipient keys remain.
- Publish randomized ciphertext commitments and public artifact hashes, never
  identities or bearer secrets.
- Independently verify signed checkpoints, inclusion, and consistency. Keep admin
  events separate and retain external anchors. One operator's hash chain cannot
  prove history was not rewritten. Strictly bound proof decoding size and work.

## Parameter policy

- Review RSA modulus size; proposed minimum: 3072 bits.
- Separate CA, issuer, bulletin, log, audit, and review keys.
- Reject unknown algorithms and downgrades. No unreviewed fallback.
- Version canonical encodings and strictly bound lengths.
- Use normative specification vectors and independent composition tests.
- Apply [compatibility review](versioning.md) to wire and parameter changes.

## Keystore composition

Browser restoration compares complete expected public keys only after typed
backup authentication and payload validation. This establishes matching, not
independent trust discovery, freshness or rollback protection.

### Reviewer-key payload profile 1

`internal/client/reviewerkey` generates device-local X25519 keys through
`crypto/ecdh.X25519().GenerateKey` with `crypto/rand`. Private keys are serialized
only inside [device-backup profile 2](#device-backup-profile-2), with reviewer-key
purpose `2`. This adds no HPKE envelope, round publication, or decryption workflow.

- The encrypted plaintext is exactly 48 bytes of canonical, unencrypted PKCS #8
  DER produced by `crypto/x509.MarshalPKCS8PrivateKey`: version zero, the RFC 8410
  X25519 OID `1.3.101.110` with absent parameters, and a nested OCTET STRING
  containing the 32-byte private key. Attributes, embedded public keys, PEM, raw
  scalars, other algorithms, and trailing data are not accepted on import.
- Imports bound ASN.1 input to 48 bytes, use `crypto/x509.ParsePKCS8PrivateKey`,
  require an X25519 `*ecdh.PrivateKey`, and compare re-encoded canonical DER in
  constant time. Authentication success alone does not establish payload validity.
  Wrong passwords, wrong purposes, and invalid payloads return the same invalid
  backup error without key output. There is no algorithm or format fallback.
- Generation and import return caller-owned 32-byte private-key buffers. Export
  accepts only the 32-byte encoding accepted by `ecdh.X25519().NewPrivateKey`.
  X25519 scalar processing belongs to the library; equivalent private encodings
  are not normalized or used as round identifiers.
- Callers may construct library keys in memory but must never persist or transmit
  private bytes unencrypted.
- Each export uses fresh backup salt and nonce. Owned DER and temporary byte
  buffers are cleared; the library's opaque `ecdh.PrivateKey` storage cannot be
  cleared through its API. Callers must clear returned private bytes and passwords.
  Cancellation is checked at entry and before returning key bytes, in addition to
  the backup package's checks. Runtime copies prevent complete-erasure guarantees.

The encrypted backup is 108 bytes. Browser reviewer workers use this profile. See
[file compatibility](versioning.md#cryptographic-file-compatibility) for review
and migration rules.

The wrapper itself enforces no round binding, expiry or revocation. The browser
composition generates a fresh key per round and matches its published binding
before restoration. Read expiry cannot recall keys or plaintext already obtained.

### Member-key payload profile 1

`internal/client/memberkey` generates device-local Ed25519 keys through
`crypto/ed25519.GenerateKey` with `crypto/rand`. It serializes private keys only inside
[device-backup profile 2](#device-backup-profile-2), with the member-key purpose.
This is not enrollment, a certificate profile, or a general signing interface.

- The encrypted plaintext is exactly 48 bytes of canonical, unencrypted PKCS #8
  DER produced by `crypto/x509.MarshalPKCS8PrivateKey`: version zero, the RFC 8410
  Ed25519 OID `1.3.101.112` with absent parameters, and a nested OCTET STRING
  containing the 32-byte seed. Attributes, embedded public keys, PEM, raw seeds,
  other algorithms, and trailing data are not accepted.
- Imports use `crypto/x509.ParsePKCS8PrivateKey`, require an Ed25519 private key,
  and compare re-encoded canonical DER in constant time. Decryption alone does not
  establish validity. Unsupported or malformed payloads return the same invalid
  backup error as authentication failure, with no key output.
- Export accepts only a 64-byte Go Ed25519 private key whose public half matches
  the library's seed-derived key, checked in constant time. Invalid input is not
  silently repaired. Each export uses fresh backup salt and nonce.
- Generation and import return caller-owned private-key buffers. Callers must
  clear these after use and must never persist or transmit them unencrypted.
  Owned temporary derived keys and DER buffers are cleared where accessible;
  library/runtime copies cannot be completely erased. Cancellation is checked at
  entry and before returning keys, in addition to the backup package's checks.

The encrypted backup is 108 bytes. This typed importer accepts only the member-key
profile; the browser session composes it with expected-key restoration. See
[file compatibility](versioning.md#cryptographic-file-compatibility) for review
and migration rules.

The wrapper itself does not bind a key to an account, certificate or expiry.
The browser enrollment transaction supplies that binding.
[Native/Node WASM compatibility](testing.md#wasm-member-session-checks) checks the
same backup through the browser adapter.

### Device-backup profile 2

`internal/client/keystore` composes library primitives, not a new primitive. This
unreleased format needs independent review before real keys are entrusted to it.
It is not a certificate, token, submission envelope, or protected CA keystore.

- KDF: `golang.org/x/crypto/argon2.IDKey`, Argon2id version `0x13`, 64 MiB,
  three passes, four lanes, 32-byte output. These are RFC 9106's second recommended
  parameters. No caller-selected or file-selected work factors are accepted.
- Salt: 16 fresh bytes from `crypto/rand` for every backup, including re-exports.
- AEAD: RFC 8439 ChaCha20-Poly1305 through
  `golang.org/x/crypto/chacha20poly1305.New`, using a 32-byte key, 12-byte nonce,
  and 16-byte tag. This is not plain ChaCha20 or XChaCha20-Poly1305.
- Generate a fresh nonce with `crypto/rand` for every export and prepend it to the
  library ciphertext/tag. Perform exactly one encryption per freshly salted
  derived key; do not reuse an AEAD/key across exports. This per-export key policy
  is essential: random 96-bit nonces are not a general uniqueness strategy for
  repeated encryption under one key. No algorithm fallback is allowed.
- Password: 1–1024 opaque bytes, with no Unicode normalization or trimming. This
  is an allocation bound, not a password-strength claim; callers must provide
  strong passwords through a separately reviewed interface.
- Plaintext: 1–65536 opaque bytes. The caller validates key type/serialization;
  successful decryption alone does not make a key valid or authorized.

All integers are unsigned big-endian. The complete 32-byte header is AEAD
associated data, followed immediately by the nonce-prefixed ciphertext:

| Byte offset | Length | Value |
| --- | --- | --- |
| 0 | 8 | ASCII `ANONCEKS` |
| 8 | 1 | Format version `1` |
| 9 | 1 | Profile `2`, fixing all KDF/AEAD parameters above |
| 10 | 1 | Purpose: member key `1`, reviewer key `2` |
| 11 | 1 | Reserved, must be zero |
| 12 | 16 | Random salt |
| 28 | 4 | Ciphertext length, including nonce and tag |
| 32 | 12 | Fresh nonce |
| 44 | plaintext length + 16 | Library ciphertext and authentication tag |

The total file size is 61–65596 bytes. Unknown versions/profiles/purposes,
nonzero reserved bytes, trailing data, truncation, and inconsistent lengths are
rejected before key derivation. The caller supplies the expected purpose; imports
cannot silently change it. There are no variable work factors for an import to
inflate or downgrade.

Valid-looking header tampering, a wrong password, and failed authentication return
the same invalid-backup error and no plaintext.

One active derivation per process/package instance limits concurrent KDF work.
Callers must still bound queued calls and imports; this is not a process RSS cap.
The package performs no file, network, or logging operations.

Cancellation is checked before queueing, after admission, after derivation, and
before returning output. Argon2id itself is not interruptible: cancellation during
it waits for that bounded computation to finish, then discards the result.
See [key management](key-management.md#device-keystores) for buffer ownership and limits.

The construction follows [RFC 8439, section 2.8](https://www.rfc-editor.org/rfc/rfc8439.html#section-2.8)
and the pinned [Go ChaCha20-Poly1305 API](https://pkg.go.dev/golang.org/x/crypto@v0.58.0/chacha20poly1305)
(consulted 2026-10-27). Independent review remains required.

Native benchmarks and [member-backup native/Node WASM checks](testing.md#wasm-member-session-checks)
are available, but browser performance remains untested. Do not weaken this profile
to make an interface responsive; introduce a separately reviewed profile and
compatibility plan if needed.

### Browser vault profile boundary

The [internal member-backup store](database.md#local-member-backup-storage-contract)
admits only the existing 108-byte member-purpose envelope. Shared
`keystore.ValidateEnvelope` checks public syntax without a password, derivation,
decryption, or authentication. A correctly shaped arbitrary ciphertext can pass;
device-side typed import and independently trusted expected-key matching remain
required. Stored public bindings and revision counters are not cryptographic
enrollment or anti-rollback evidence. No cryptographic profile changes.

The separate [local WASM member bridge](key-management.md#local-wasm-member-sessions)
reuses profile 2, member-key payload profile 1, and CSR profile 1 without parameter
or encoding changes. Passwords are opaque bytes, never PRF outputs or server login
credentials. The bridge exposes only encrypted backups and public enrollment
material, requires expected-key restoration, and adds no wrapping/recovery profile.
The [local dedicated-worker host](key-management.md#local-member-worker-host) changes
execution, local deadline checks, host-signal cancellation, lock notification, and
page/visibility disposal only. It runs this same Go bridge without JavaScript
cryptography, new profiles, or lower KDF costs. Termination discards runtime state
without guaranteeing cleanup or complete memory erasure.
The opt-in [synthetic browser checks](testing.md#member-worker-browser-checks)
exercise native/worker compatibility under isolated test CSP without changing
these profiles. They do not establish supported-device costs or product custody.
The [browser private-access form](ui-design.md#private-access-and-local-state) uses
confirmed setup and required expected-key restoration through these same methods,
without JavaScript cryptography or weaker KDF costs.

The [browser account vault](key-management.md#browser-account-vault) uses local
passphrase unlocking. WebAuthn Level 3 is the authentication reference; its PRF extension
is a candidate local unlock source, not a member signing key or a complete vault
encryption protocol. WebAuthn authentication keys, member Ed25519 keys, and
round-scoped reviewer X25519 keys retain separate purposes.

Device-backup profile 2 is the only supported password-backup profile.
Do not feed a passkey signature/public credential ID into it as an unlock secret,
reinterpret PRF bytes as a password profile without review, or change its format
or Argon2id costs for browser convenience.

Before a PRF/recovery implementation, select reviewed library composition and fix
versioned envelope/wrapping formats, context binding, KDF/AEAD parameters, fresh
nonce rules, multi-credential access, recovery-secret encoding, and substitution/
rollback behavior. Add cross-client vectors and downgrade rejection. A wrapping
change requires [compatibility review](versioning.md#cryptographic-file-compatibility);
this design adds no new profile, primitive, wire schema, or implementation.

## Post-quantum scope

The baseline is classical. ML-KEM, ML-DSA, and SLH-DSA have final NIST standards;
Go 1.27 provides HPKE and ML-DSA/X.509, but draft HPKE KEM combinations still need
explicit interoperability handling.

Future profiles require cross-client vectors, tested IDs, import/export tests,
hardware review, and downgrade prevention. RSA blind authorization rules out an
end-to-end post-quantum claim.

## Implementation discipline

- Follow [engineering boundaries](../AGENTS.md#engineering-boundaries). Share Go
  composition across native tests and browser WASM; do not duplicate primitives in JavaScript.
- Minimize secret copies and clear owned mutable buffers. Go garbage collection,
  JavaScript bridges, strings, storage, and runtime copies prevent complete-erasure
  guarantees. Browser execution is not universally constant-time.
- See [deployment](deployment.md#transport-and-headers) and
  [threat model](threat-model.md#browser-delivery-trust) for delivery controls and limits.

## References

Primary sources, accessed 2026-10-26:

- [RFC 5280: certificates and CRLs](https://www.rfc-editor.org/rfc/rfc5280).
- [RFC 8410: Ed25519 key encoding](https://www.rfc-editor.org/rfc/rfc8410.html#section-7)
  and [Go PKCS #8 parsing](https://pkg.go.dev/crypto/x509#ParsePKCS8PrivateKey).
- [RFC 8410: X25519 private-key encoding](https://www.rfc-editor.org/rfc/rfc8410.html#section-7)
  and [Go X25519 key generation and validation](https://pkg.go.dev/crypto/ecdh#X25519).
- [RFC 9474: RSA blind signatures](https://www.rfc-editor.org/rfc/rfc9474).
- [RFC 9578: Privacy Pass issuance protocols](https://www.rfc-editor.org/rfc/rfc9578).
- [RFC 9180: HPKE](https://www.rfc-editor.org/rfc/rfc9180).
- [CIRCL blind RSA](https://pkg.go.dev/github.com/cloudflare/circl/blindsign/blindrsa).
- [Argon2 package](https://pkg.go.dev/golang.org/x/crypto/argon2) and
  [OWASP password storage guidance](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).
- [RFC 9106: Argon2](https://www.rfc-editor.org/rfc/rfc9106.html#section-4).
- [Transparency tree routines](https://pkg.go.dev/golang.org/x/mod/sumdb/tlog) and
  [C2SP checkpoints](https://c2sp.org/tlog-checkpoint).

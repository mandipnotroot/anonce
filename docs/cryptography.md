<!-- SPDX-FileCopyrightText: 2026 Anonce Contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Cryptographic composition

Audience: cryptographic reviewers and client implementers.

Status: device-backup encryption, local member/reviewer-key generation/import/export,
and identity-free member certificate requests are implemented as shared Go packages.
Submission, enrollment, and public-proof protocols remain prospective.

## Chosen implementation boundaries

| Purpose | Proposed implementation/profile |
| --- | --- |
| Membership and bulletin signatures | Go `crypto/ed25519`, `crypto/x509`; dedicated keys per purpose |
| Blind tokens | CIRCL `blindsign/blindrsa`; RFC 9474 randomized preparation, SHA-384/PSS, dedicated RSA round keys |
| Submission and reply envelopes | Go `crypto/hpke`; DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305, base mode |
| Device-backup encryption | `golang.org/x/crypto/chacha20poly1305.New`; RFC 8439, device-backup profile 2 |
| Password hashing and keystore derivation | `golang.org/x/crypto/argon2`, Argon2id |
| Log tree and proofs | `golang.org/x/mod/sumdb/tlog` and signed notes; C2SP checkpoint conventions |
| Randomness | `crypto/rand` through library interfaces |

## Membership and authorization

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

The offline request profile uses RSA Security Inc. Public-Key Cryptography
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

The profile adds no certificate policy, CA trust, enrollment-code handling, replay
protection, or HTTP route. Future enrollment must separately authenticate the
member and atomically consume a code. See [compatibility](versioning.md).

The offline [`verify-csr` command](key-management.md#local-member-request-verification)
reuses this parser and library signature check without changing the profile.
It prints only the validated public key and makes no certificate-trust or
enrollment-authorization decision. Its optional expected-public-key check compares
the complete public key only after profile and signature validation. This adds
no cryptographic format, primitive, or trust-discovery mechanism.

Optional [public-key file export](key-management.md#local-public-key-file-export)
from `inspect` and `verify-csr` publishes their existing public-key line only after
validation and optional expected-key matching. It adds no primitive, cryptographic
format, signed attestation, or trust-discovery mechanism.

Optional [expected-key file input](key-management.md#local-expected-key-files)
reads that unchanged, kind-tagged lowercase public-key line through bounded
owner-only file checks. It supplies the existing complete public-key comparison,
not a new cryptographic profile, trust anchor, or primitive. The expected record
must be independently trusted; validation and signing/encryption order are unchanged.

The [WASM verifier's `verifyCSRForKey` method](key-management.md#local-wasm-request-verification)
uses the same parser and full public-key comparison after signature validation.
It changes no profile or primitive and requires an independently trusted expected
key; malformed input and mismatches return no public output.

The optional [`csr -out` file export](key-management.md#local-member-certificate-requests)
publishes the same public DER without encryption or private-key serialization.
It changes no cryptographic profile or authorization decision.

The optional `csr -expect-public-key` check compares the complete public key after
typed backup authentication and payload validation, before request signing or file
creation. It uses the same validated in-memory key for signing, without reopening
the backup. The expected key must be independently trusted; no profile or primitive
changes, freshness check, or enrollment authority is added.

The [local WASM verifier](key-management.md#local-wasm-request-verification) uses
the same parser and unchanged DER profile. Hexadecimal is only its bounded bridge
input representation, not a new request format. Its native/Node compatibility
evidence does not cover device backups or private-key custody in browsers.

### In-memory member session composition

`internal/client/membersession` composes the existing member-key, password-backup,
and CSR profiles without adding a primitive, envelope, or browser interface.
Creation generates a random key, encrypts its backup, and prepares its request
before retaining the key. Restoration authenticates and validates the backup,
then compares the complete public key with a required independently trusted
expected key before preparing a request or installing the key in the session.

Only public enrollment material and encrypted backups leave the session API.
Lock clears its owned private buffer and cancels pending setup/restoration; a
cancelled operation cannot install a key. One pending setup/restoration per session
is admitted, including while cancellation waits for bounded Argon2id work. This
does not bound the number of sessions a caller creates. See the
[session lifecycle](key-management.md#in-memory-member-sessions) for ownership and
integration limits. PRF wrapping and account recovery remain unspecified.

## Encryption and public proofs

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

The offline CLI's optional [backup key matching](key-management.md#local-backup-key-matching)
compares complete public keys only after typed backup authentication and validation.
Rewrapping can require the same match before replacement-password derivation or
file creation, using the validated key in memory without reopening the backup.
It adds no primitive or format and does not establish freshness or round binding.

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

The encrypted backup is 108 bytes. The [offline CLI](key-management.md#local-key-cli)
reuses it without changing the outer format or opaque keystore API. See
[file compatibility](versioning.md#cryptographic-file-compatibility) for review
and migration rules.

The wrapper enforces no round binding, expiry, revocation, restoration policy, or
separation between rounds. Browser interfaces and submission/reply encryption are
unimplemented; native/WASM compatibility is untested. Generate a fresh key per
round when those workflows are introduced.

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

The encrypted backup is 108 bytes. The outer format and generic opaque keystore
are unchanged; this typed importer accepts only the member-key profile. The
[offline CLI](key-management.md#local-key-cli) reuses it. See
[file compatibility](versioning.md#cryptographic-file-compatibility) for review
and migration rules.

The wrapper does not bind a key to a member, certificate, round, revocation state,
or expiry. Browser page custody is unimplemented;
[native/Node WASM member-backup compatibility](testing.md#wasm-member-session-checks)
is tested through the separate session adapter.

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

The separate [local WASM member bridge](key-management.md#local-wasm-member-sessions)
reuses profile 2, member-key payload profile 1, and CSR profile 1 without parameter
or encoding changes. Passwords are opaque bytes, never PRF outputs or server login
credentials. The bridge exposes only encrypted backups and public enrollment
material, requires expected-key restoration, and adds no wrapping/recovery profile.
The [local dedicated-worker host](key-management.md#local-member-worker-host) changes
execution and disposal only. It runs this same Go bridge without JavaScript
cryptography, new profiles, or lower KDF costs. Termination discards runtime state
without guaranteeing cleanup or complete memory erasure.

The [browser account vault](key-management.md#browser-account-vault) is planned.
WebAuthn Level 3 is the selected authentication design reference; its PRF extension
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
  composition across CLI/WASM; do not duplicate primitives in JavaScript.
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

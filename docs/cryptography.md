<!-- SPDX-FileCopyrightText: 2026 Anonce Contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Cryptographic composition

Audience: cryptographic reviewers and client implementers.

Status: the device-backup profile below is implemented as a shared Go package.
Submission, membership, and public-proof protocols remain prospective.

## Chosen implementation boundaries

| Purpose | Proposed implementation/profile |
| --- | --- |
| Membership and bulletin signatures | Go `crypto/ed25519`, `crypto/x509`; dedicated keys per purpose |
| Blind tokens | CIRCL `blindsign/blindrsa`; RFC 9474 randomized preparation, SHA-384/PSS, dedicated RSA round keys |
| Submission and reply envelopes | Go `crypto/hpke`; DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305, base mode |
| Password hashing and keystore derivation | `golang.org/x/crypto/argon2`, Argon2id |
| Log tree and proofs | `golang.org/x/mod/sumdb/tlog` and signed notes; C2SP checkpoint conventions |
| Randomness | `crypto/rand` through library interfaces |

## Membership and authorization

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

### Device-backup profile 1

`internal/client/keystore` composes library primitives, not a new primitive. This
unreleased format needs independent review before real keys are entrusted to it.
It is not a certificate, token, submission envelope, or protected CA keystore.

- KDF: `golang.org/x/crypto/argon2.IDKey`, Argon2id version `0x13`, 64 MiB,
  three passes, four lanes, 32-byte output. These are RFC 9106's second recommended
  parameters. No caller-selected or file-selected work factors are accepted.
- Salt: 16 fresh bytes from `crypto/rand` for every backup, including re-exports.
- AEAD: standard-library AES-256-GCM through `cipher.NewGCMWithRandomNonce`.
  The library prepends its fresh 12-byte nonce and appends a 16-byte tag. One
  encryption is performed per freshly salted derived key. No fallback is allowed.
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
| 9 | 1 | Profile `1`, fixing all KDF/AEAD parameters above |
| 10 | 1 | Purpose: member key `1`, reviewer key `2` |
| 11 | 1 | Reserved, must be zero |
| 12 | 16 | Random salt |
| 28 | 4 | Ciphertext length, including nonce and tag |
| 32 | 12 + plaintext length + 16 | AEAD output |

The total file size is 61–65596 bytes. Unknown versions/profiles/purposes,
nonzero reserved bytes, trailing data, truncation, and inconsistent lengths are
rejected before key derivation. The caller supplies the expected purpose; imports
cannot silently change it. Valid-looking header tampering, a wrong password, and
failed authentication return the same invalid-backup error and no plaintext.
There are no variable work factors for an import to inflate or downgrade.

One active derivation per process/package instance limits concurrent KDF work.
Callers must still bound queued calls and imports; this is not a process RSS cap.
Cancellation is checked before queueing, after admission, after derivation, and
before returning output. Argon2id itself is not interruptible: cancellation during
it waits for that bounded computation to finish, then discards the result.
The package performs no file, network, or logging operations. See
[key management](key-management.md#device-keystores) for buffer ownership and limits.

Native benchmarks are available, but browser performance and native/WASM
interoperability remain untested. Do not weaken this profile to make an interface
responsive; introduce a separately reviewed profile and compatibility plan if needed.

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
- [RFC 9474: RSA blind signatures](https://www.rfc-editor.org/rfc/rfc9474).
- [RFC 9578: Privacy Pass issuance protocols](https://www.rfc-editor.org/rfc/rfc9578).
- [RFC 9180: HPKE](https://www.rfc-editor.org/rfc/rfc9180).
- [CIRCL blind RSA](https://pkg.go.dev/github.com/cloudflare/circl/blindsign/blindrsa).
- [Argon2 package](https://pkg.go.dev/golang.org/x/crypto/argon2) and
  [OWASP password storage guidance](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).
- [RFC 9106: Argon2](https://www.rfc-editor.org/rfc/rfc9106.html#section-4) and
  [Go random-nonce GCM](https://pkg.go.dev/crypto/cipher#NewGCMWithRandomNonce).
- [Transparency tree routines](https://pkg.go.dev/golang.org/x/mod/sumdb/tlog) and
  [C2SP checkpoints](https://c2sp.org/tlog-checkpoint).

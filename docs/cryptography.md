<!-- SPDX-FileCopyrightText: 2026 Anonce Contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Cryptographic composition

Audience: cryptographic reviewers and client implementers.

Status: prospective profiles. No cryptographic protocol is implemented.

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

Generate member keys and CSRs on the device. The CA validates proof of possession
and membership, issues bounded-lifetime certificates, and publishes signed CRLs.
Fix certificate extensions, chain rules, serial handling, and revocation freshness
before implementation. Issuance fails closed when required revocation freshness
cannot be established. Revocation cannot identify already-issued anonymous tokens.

The application token profile is not a claim of byte-for-byte Privacy Pass
interoperability. In particular, the proposed randomized preparation and reviewed
RSA modulus policy must not be silently substituted into RFC 9578's registered
token format. Fix canonical token input, domain context, key validation, and test
vectors before wire code. All members of a round must receive the same public key,
response limit, and context; individualized keys or allowances can partition the
anonymity set. Bind tokens to the common bulletin/profile through the reviewed
encoding. A larger response allowance means independent single-use tokens, not
multiple spends of one token. Generate fresh randomness for each token and do not
encode identity-side reservation slots, counters, or member identifiers into it.

## Encryption and public proofs

HPKE base mode deliberately avoids identifying sender-authentication keys. Token
verification authorizes submission separately. Bind the protocol version, round ID,
bulletin/form digest, and message purpose through the reviewed HPKE context and
authenticated data contract. Do not invent a custom KEM combiner or signing scheme.
HPKE does not itself prevent replay, hide plaintext length, or guarantee forward
secrecy while recipient keys are retained.

Publish randomized ciphertext commitments and public artifact hashes, never member
identities or bearer secrets. Verify signed checkpoints, inclusion proofs, and
consistency independently. Keep administrative audit events separate and retain
external checkpoint anchors; a single operator's hash chain cannot prove that its
history was not rewritten. Proof decoders need strict size and work bounds.

## Parameter policy

Review RSA modulus size with a minimum proposed baseline of 3072 bits for the
application profile. Separate all CA, issuer, bulletin, log, audit, and review keys.
Reject unknown algorithms and parameter downgrades rather than negotiating an
unreviewed fallback. Version canonical encodings and enforce strict length bounds.
Use normative vectors from the selected specifications plus independent composition
tests. Wire and parameter changes receive [compatibility review](versioning.md).

## Keystore composition

Use a versioned password-derived authenticated envelope. Salt, nonce, AEAD choice,
authenticated header, parameter bounds, and file grammar still need independent
review. Use random salts, benchmark Argon2id on native and browser clients, and bound
imported work factors before allocation. Current OWASP minimum configurations are
a floor, not a performance-independent recommendation. Never use an unauthenticated
CBC container or a password hash directly as an encryption format. Custody and
recovery requirements belong in [key management](key-management.md).

## Post-quantum scope

ML-KEM, ML-DSA, and SLH-DSA have final NIST standards. Go 1.27 supplies HPKE and
ML-DSA/X.509 facilities, but draft-defined HPKE KEM combinations still need explicit
interoperability handling. The baseline remains classical. Future profiles require
cross-client vectors, tested identifiers, import/export tests, hardware capability
review, and downgrade prevention. Do not claim end-to-end post-quantum protection
while blind authorization is RSA-based.

## Implementation discipline

Follow the [engineering boundaries](../AGENTS.md#engineering-boundaries). Share Go
composition between CLI and WASM rather than duplicating primitives in JavaScript.
Minimize secret copies and clear owned mutable buffers, but do not promise complete
erasure in garbage-collected Go or browser runtimes. JavaScript bridges, strings,
storage, and runtime copies limit that guarantee. Browser timing is not universally
constant-time. Delivery controls and their limits belong in
[deployment](deployment.md#transport-and-headers) and the [threat model](threat-model.md#browser-delivery-trust).

## References

Primary sources, accessed 2026-10-26:

- [RFC 5280: certificates and CRLs](https://www.rfc-editor.org/rfc/rfc5280).
- [RFC 9474: RSA blind signatures](https://www.rfc-editor.org/rfc/rfc9474).
- [RFC 9578: Privacy Pass issuance protocols](https://www.rfc-editor.org/rfc/rfc9578).
- [RFC 9180: HPKE](https://www.rfc-editor.org/rfc/rfc9180).
- [CIRCL blind RSA](https://pkg.go.dev/github.com/cloudflare/circl/blindsign/blindrsa).
- [Argon2 package](https://pkg.go.dev/golang.org/x/crypto/argon2) and
  [OWASP password storage guidance](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).
- [Transparency tree routines](https://pkg.go.dev/golang.org/x/mod/sumdb/tlog) and
  [C2SP checkpoints](https://c2sp.org/tlog-checkpoint).

<!-- SPDX-FileCopyrightText: 2026 Anonce Contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Key management

Audience: implementers, reviewers, and operators responsible for secret custody.

Status: shared in-memory device-backup encryption and local member-key generation,
encrypted export, and validated import are implemented. Reviewer-key generation,
file/browser custody, recovery workflows, and signing services are not.

## Inventory

| Key or secret | Custodian | Lifetime and separation |
| --- | --- | --- |
| Membership CA | Isolated signing process | Explicit rotation, encrypted storage, separately controlled backups |
| Member signing key | Member device | Certificate lifetime; export only through encrypted backup |
| Enrollment code | Member until consumed | Single use, bounded expiry, digest retained for validation |
| Issuer blind-signing key | Issuer signing boundary | Dedicated per round and profile; never reused as a CA key |
| Round reviewer key | Reviewer device | Fresh per round, retained only for declared review window |
| Reply key/capability | Member device | Fresh per submission, expiry tied to reply policy |
| Bulletin signing key | Publication service | Separate from membership and token keys |
| Transparency/audit signing keys | Their respective services | Separate keys and external checkpoint retention |
| Session and recovery secrets | Identity-side authentication service | Bounded lifetime and rotation; never shared with submission service |

## Protected CA storage

- Keep the unlocked key in a signing process with a narrowly authorized interface.
  Store the encrypted keystore separately from unlock material.
- Never expose the raw CA key or a universal signing oracle to the web application.
- Simulated HSMs provide no physical tamper resistance. Optional SoftHSM/PKCS#11
  support requires exact mechanism/capability tests and does not replace hardware.
- Initialization requires reauthentication and explicit human fingerprint confirmation.
- Backups must define restoration authority, encrypted-copy locations, and how
  expired keys stay out of service.
- Dual control is [optional future work](roadmap.md#later).

## Device keystores

The implemented `internal/client/keystore` package seals and opens bounded opaque
secrets using [device-backup profile 1](cryptography.md#device-backup-profile-1).
It is not connected to any command, browser interface, or HTTP service.

The shared `internal/client/memberkey` package adds Ed25519 member-key generation
and typed encrypted backups under
[member-key payload profile 1](cryptography.md#member-key-payload-profile-1).
`Generate` returns a fresh local key; `Seal` validates and encrypts an existing key;
`Open` decrypts and validates its canonical PKCS #8 payload. It always selects the
member-key purpose, rejects inconsistent private/public halves on export, and
returns no key on failed import. No raw serialization API, signing endpoint,
identity/round binding, or certificate operations are provided. These functions
are library interfaces, not an operational device workflow.

Both packages follow these custody boundaries:

- `Seal` and `Open` take a context and password bytes. The generic keystore also
  takes the expected purpose; the member-key wrapper fixes it to member keys.
  Inputs remain caller-owned and must not be mutated until the call returns.
  Returned buffers are caller-owned; clear decrypted secrets after use.
- Owned derived-key bytes and failed/cancelled output buffers are cleared.
  Passwords and input secrets are neither copied unnecessarily nor cleared by the
  package. Callers must clear them when no longer needed.
- The library's Argon2 arena and expanded AES key cannot be cleared through their
  public APIs. Garbage collection, compiler/runtime copies, swap, and crash dumps
  prevent complete-erasure guarantees. Bound concurrency and secure the device.
- File permissions, atomic writes, password entry/confirmation, and browser
  persistence remain unimplemented caller responsibilities. The generic keystore
  also leaves serialization and purpose selection to callers; the member-key
  wrapper fixes both. Never store a raw key beside its encrypted backup.
- The format neither detects a restored old backup nor enforces revocation or
  reviewer-key expiry. Do not use it as evidence of safe retention/recovery.

Remaining custody requirements:

- Generate reviewer keys locally and connect member-key generation to reviewed
  device interfaces. Derive encryption keys from passwords
  with bounded Argon2id; authenticate the complete keystore header.
- Treat imports as untrusted. Enforce memory, iteration, size, and version limits.
  Wrong passwords or corrupt files must expose no partial plaintext.
- Browser persistence, exports, and CLI use the same reviewed Go implementation.
- Promise password recovery only with a separately reviewed mechanism. Lost keys
  may require revocation and fresh enrollment.
- Recovery preserves membership quota usage. It cannot reset allowance or replace
  reserved tokens. Unreserved slots retain ordinary limit and eligibility checks.

## Retention and destruction

- Destroy controlled round-key copies after the retention deadline. Record the public
  fingerprint and authorized outcome; retain an externally checkable audit checkpoint.
- Inventory encrypted exports, snapshots, swap, crash dumps, and backup retention.
  Deleting one active file is insufficient.
- Reviewers can retain keys or plaintext. Describe this as round-level retention
  protection, not guaranteed erasure or ratcheting forward secrecy.
  See [threat model](threat-model.md#revocation-transfer-and-deletion).

## Incident handling

- Revoke exposed certificates, stop affected signers, publish replacement trust
  material through the reviewed channel, and assess pre-incident tokens.
- Issued anonymous tokens cannot be mapped to revoked certificates.
- Rotation and trust-anchor recovery require an explicit compatibility plan.
  Never silently accept an untrusted replacement.

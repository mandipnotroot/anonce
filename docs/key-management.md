<!-- SPDX-FileCopyrightText: 2026 Anonce Contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Key management

Audience: implementers, reviewers, and operators responsible for secret custody.

Status: custody design; no keystore or signing service is implemented.

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

The signing process holds the unlocked CA key and exposes a narrowly authorized
signing interface. The encrypted keystore is stored separately from its unlock
material. Simulated HSM operation illustrates isolation and authorization but does
not provide physical tamper resistance. The web application must not receive a raw
CA key or a universal signing oracle. Optional SoftHSM/PKCS#11 support requires exact
mechanism and capability tests; it is not a substitute for physical hardware.

Initialization requires reauthentication and an explicit human confirmation of the
public fingerprint. Backup procedures must define who can restore the signer,
where encrypted copies live, and how an expired key is kept out of active service.
Dual control remains optional future work on the [roadmap](roadmap.md#later).

## Device keystores

The client generates member and reviewer keys locally, derives an encryption key
from a user password under a bounded Argon2id profile, and authenticates the complete
keystore header. Imported files are untrusted inputs and must have strict memory,
iteration, size, and version limits. Wrong-password and corrupt-file failures must
not expose partial plaintext. Browser persistence and export formats share the
same reviewed Go implementation as the CLI.

Do not promise password recovery without a separately reviewed recovery mechanism.
Losing the key may require certificate revocation and fresh enrollment. Preserve
the existing membership's quota usage; recovery must not reset its allowance or
replace already-reserved tokens. Other unreserved slots remain subject to the
published limit and ordinary eligibility checks.

## Retention and destruction

Destroy controlled round-key copies after the retention deadline, record the public
key fingerprint and authorized outcome, and keep an externally checkable audit
checkpoint. Inventory encrypted exports, snapshots, swap, crash dumps, and backup
retention. Deletion of one active file is insufficient.

The reviewer can keep a private copy or plaintext they already saw. Consequently,
the product must describe this as round-level retention protection, not guaranteed
erasure or ratcheting forward secrecy. See the [threat model](threat-model.md#revocation-transfer-and-deletion).

## Incident handling

Revoke exposed membership certificates, stop affected signers, publish replacement
trust material through the reviewed channel, and assess tokens issued before the
incident. Existing anonymous tokens cannot be mapped back to a revoked certificate.
Key rotation and trust-anchor recovery require an explicit compatibility plan,
not silent acceptance of an untrusted replacement.

<!-- SPDX-FileCopyrightText: 2026 Anonce Contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Key management

Audience: implementers, reviewers, and operators responsible for secret custody.

Status: shared in-memory device-backup encryption and local member/reviewer-key
generation, encrypted export, validated import, and an offline backup CLI are
implemented. Browser custody, round binding, recovery, and signing services are not.

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
The [local CLI](#local-key-cli) uses the typed wrappers below; no browser interface
or HTTP service handles device keys.

The shared `internal/client/memberkey` package adds Ed25519 member-key generation
and typed encrypted backups under
[member-key payload profile 1](cryptography.md#member-key-payload-profile-1).
`Generate` returns a fresh local key; `Seal` validates and encrypts an existing key;
`Open` decrypts and validates its canonical PKCS #8 payload. It always selects the
member-key purpose, rejects inconsistent private/public halves on export, and
returns no key on failed import. No raw serialization API, signing endpoint,
identity/round binding, or certificate operations are provided. These functions
are library interfaces reused by the offline CLI, not an enrollment workflow.

The shared `internal/client/reviewerkey` package adds X25519 reviewer-key generation
and typed encrypted backups under
[reviewer-key payload profile 1](cryptography.md#reviewer-key-payload-profile-1).
`Generate` returns fresh caller-owned private bytes; `Seal` validates the library's
32-byte private encoding and encrypts canonical PKCS #8; `Open` decrypts and
validates that payload. The wrapper fixes the reviewer-key purpose and returns no
key on failed import. Library `ecdh.PrivateKey` objects can be constructed from
these bytes in memory, but their opaque internal copies cannot be explicitly
cleared. No round binding, expiry, round-key publication, or HPKE decryption is
implemented. Future round workflows must generate a fresh key for each round.

All three packages follow these custody boundaries:

- `Seal` and `Open` take a context and password bytes. The generic keystore also
  takes the expected purpose; each typed wrapper fixes it to its own key purpose.
  Inputs remain caller-owned and must not be mutated until the call returns.
  Returned buffers are caller-owned; clear decrypted secrets after use.
- Owned derived-key bytes and failed/cancelled output buffers are cleared.
  Passwords and input secrets are neither copied unnecessarily nor cleared by the
  package. Callers must clear them when no longer needed.
- The library's Argon2 arena and expanded AES key cannot be cleared through their
  public APIs. Garbage collection, compiler/runtime copies, swap, and crash dumps
  prevent complete-erasure guarantees. Bound concurrency and secure the device.
- File permissions, atomic writes, password entry/confirmation, and browser
  persistence are caller responsibilities. The offline CLI implements a bounded
  subset below. The generic keystore leaves serialization and purpose selection
  to callers; the typed wrappers fix both. Never store a raw key beside its backup.
- The format neither detects a restored old backup nor enforces revocation or
  reviewer-key expiry. Do not use it as evidence of safe retention/recovery.

Remaining custody requirements:

- Extend member/reviewer-key generation to reviewed device interfaces and enforce
  reviewer round binding and retention. Derive encryption keys from passwords
  with bounded Argon2id; authenticate the complete keystore header.
- Treat imports as untrusted. Enforce memory, iteration, size, and version limits.
  Wrong passwords or corrupt files must expose no partial plaintext.
- Browser persistence and exports must reuse the same Go implementation as the CLI.
- Promise password recovery only with a separately reviewed mechanism. Lost keys
  may require revocation and fresh enrollment.
- Recovery preserves membership quota usage. It cannot reset allowance or replace
  reserved tokens. Unreserved slots retain ordinary limit and eligibility checks.

## Local key CLI

`make build` builds `bin/client`. This development-only, offline command reuses
the existing member/reviewer payload profiles without changing their bytes or
adding dependencies. Independent review is still required before real-key use.
It performs no network calls, enrollment, signing, reviewer round binding, expiry
checks, or decryption of submissions. It does not make a key trusted or authorized.

| Command | Required flags | Result |
| --- | --- | --- |
| `client generate` | `-kind member\|reviewer -out PATH` | Fresh key, encrypted backup file; no stdout |
| `client inspect` | `-kind member\|reviewer -in PATH` | Validated backup; exactly `member:<hex>\n` or `reviewer:<hex>\n` on stdout, with the 32-byte public key in lowercase hexadecimal |
| `client -help` | None | Static help on stdout; no password read |

Operation-specific `-help`/`-h` is also supported. Unknown flags, positional
arguments, missing values, unsupported kinds, and flags for the other operation
fail. Arguments are bounded to 8192 bytes including separators. Exit `0` means
success or help; all failures, including cancellation, exit `1`. Errors go to
stderr without reflecting argument values, paths, passwords, or key bytes. There
are no password flags or application environment settings.

### Password input

- Standard input must be a pipe or regular file, never a terminal or device.
  There is no interactive password prompt or terminal-echo management. Use a
  trusted password manager that emits the framing below without exposing the
  password in command arguments, shell history, environment variables, or logs.
- `generate` requires two matching LF-terminated password lines, followed by EOF;
  `inspect` requires one LF-terminated line, followed by EOF. Extra bytes fail.
- Each password is 1–1024 opaque bytes excluding LF. Spaces, CR, NUL, and non-UTF-8
  bytes are preserved. LF cannot be represented by this interface; the underlying
  backup profile is unchanged. CRLF input includes CR in the password.
- The read buffer is capped at 2051 bytes for generation and 1026 for inspection.
  Owned input/password/private-key buffers are cleared on return. The producer's
  buffers, any input file, runtime copies, and opaque library keys remain outside
  that guarantee. Protect or avoid plaintext password files.
- Interrupt/SIGTERM closes pending stdin reads and propagates cancellation to the
  shared key packages. Argon2id still finishes its bounded work before cancellation
  is observed. A producer that never closes stdin otherwise keeps the command waiting.
  On Linux, inherited pipes are duplicated and registered for nonblocking runtime
  polling so closing them interrupts reads. This changes shared file-status flags;
  do not read concurrently from another copy of the input descriptor. Pipe input
  on other platforms fails closed until an equivalent implementation is validated.

### File custody

Use an existing owner-only directory, for example one created with `mkdir -m 700`.
Supply a backup pathname within that directory to `-out` or `-in`. Native Linux
file behavior is tested; other operating systems/filesystems are not validated.

- The selected parent is pinned through `os.OpenRoot` and must have no group/other
  permission bits. Its owner, ancestors, mounts, and access-control lists must be
  trusted. Parent symlinks are not an independent trust check. These checks do not
  isolate hostile same-user processes, privileged users, or a compromised device.
- Generation writes only ciphertext to a randomly named same-directory temporary
  regular file with permissions at most `0600`, syncs and closes it, then publishes
  with a no-replace hard link. Existing files, directories, and symlinks, including
  dangling symlinks, are never overwritten. Filesystems without hard-link support
  fail closed; there is no rename/overwrite fallback.
- Temporary names are removed on return when possible; cleanup failure is reported.
  Successful publication syncs the directory. A crash can leave an encrypted
  temporary file. An error or cancellation
  after publication can leave a complete final backup; inspect the selected path
  before retrying. Never delete an existing backup merely because a retry failed.
  Power-loss durability depends on the filesystem and device honoring sync.
- Imports accept only owner-only, bounded regular files, rejecting symlinks,
  directories, and special files before opening. Identity/permissions are checked
  again after opening, and reads are bounded to the backup maximum plus one byte.
  This assumes no hostile writer in the trusted directory; it does not establish
  immutability or freshness. Typed wrappers authenticate purpose and validate DER.
- `inspect` emits no output on validation failure and never exports plaintext
  private keys. Successful public-key output is not a round bulletin, enrollment
  proof, authorization decision, or expiry/rollback check.

See [testing](testing.md#implemented-test-mapping) for executable evidence and
[threat model](threat-model.md) for remaining device and offline-guessing risks.

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

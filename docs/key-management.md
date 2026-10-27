<!-- SPDX-FileCopyrightText: 2026 Anonce Contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Key management

Audience: implementers, reviewers, and operators responsible for secret custody.

Status: shared in-memory device-backup encryption and local member/reviewer-key
generation, encrypted export, validated import, and an offline backup CLI are
implemented, along with local member certificate requests. Browser custody, round
binding, recovery, enrollment, and signing services are not.

## Browser account vault

### Product decision

Members use accounts and review links, not key-management commands. Generate a
random member key automatically in the browser using the shared Go packages;
never derive the member key itself from a password. Prepare certificate requests
and enrollment behind the [account workflow](ui-design.md#account-and-review-workflow).
Generate reviewer keys automatically per round, separately from account credentials.

Plan identity-side storage of encrypted member-key backups so another browser can
restore the same key after authentication and local unlocking. A public key is
linkable even though it is not secret; keep it off anonymous submission requests.
Backup storage and automatic restoration are requirements, not available features.

### Authentication and unlocking

Prefer passkey account authentication with user verification. The design reference
is [WebAuthn Level 3, Recommendation of 2026-08-25](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/).
Verify ceremonies on the server under its relying-party rules. A successful
assertion proves account authentication; it does not expose the authenticator's
private key or provide an encryption key by itself.

The preferred low-friction unlock candidate is the
[WebAuthn PRF extension](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/#prf-extension).
It can provide a credential-specific secret to the browser during a user-approved
ceremony. It is not silent access, and ordinary passkey support does not establish
PRF support. Check actual extension results for each credential and test the
browser, OS, authenticator/provider, sync, and cross-device paths before advertising
support. Do not serialize PRF outputs into the assertion payload sent to the server.

| Unlock method | Decision and limits |
| --- | --- |
| Passkey plus PRF | Preferred candidate for combined sign-in/unlock on tested setups; wrapping profile and multi-credential behavior need review |
| Local unlock passphrase | Browser-only compatibility path, explicitly configured by the user; use the existing password-backup profile without weakening its costs |
| Ordinary login password reused for backup encryption | Rejected when sent to the server for authentication; server access to that password defeats the custody separation |
| Server-held unlock key or server-side decryption | Rejected for member/reviewer private-key custody |

Keep any local unlock passphrase separate from a server-verified login password.
Prompt once per unlocked session where safe, not on each action. On a setup without
a usable configured unlock method, explain the limitation and offer reviewed
browser recovery or another supported device. Never silently downgrade after a
failed decryption or require a CLI to proceed.

PRF is a design direction, not an admitted cryptographic profile. Before coding,
specify the wrapping construction, domain separation, nonce rules, credential and
account binding, key validation, new-credential authorization, replacement, and
recovery in [cryptography](cryptography.md#browser-vault-profile-boundary).
Different credentials have different PRF secrets; registering a second passkey
does not automatically grant access to an existing encrypted backup. Synced-login
availability must not be presented as proof that vault restoration works.

### Storage and lifecycle

- Upload only encrypted member-key backups, public key/certificate material, and
  the reviewed version/binding metadata needed to restore them. Unlock material,
  plaintext private keys, and PRF results remain on the device.
- Authorize vault access by owner on the identity service. Bound sizes, versions,
  write rates, and concurrent updates; require recent authentication for replacement,
  recovery changes, and deletion. Use CSRF protection and `no-store` responses.
- Authenticate backup purpose and validate the restored key against its expected
  enrollment binding before signing. Server-supplied metadata alone is not an
  independent trust anchor. Resolve substitution and rollback detection before
  claiming protection against a malicious vault service.
- Do not put answers, blind tokens, issuance transcripts, receipts, mailbox IDs,
  reply keys/capabilities, or per-submission state in the account-linked vault.
  Account backup must not become an identity-to-submission index.
- Local encrypted caching is optional and needs explicit device-retention policy.
  Never persist plaintext keys, unlock passphrases, or PRF outputs in Web Storage,
  IndexedDB, caches, URLs, or diagnostics. Persistent browser storage is untrusted
  and may be cleared or evicted; it is not the only backup.
- Bound unlocked lifetime and concurrent cryptographic work. On lock/logout or
  account switch, clear accessible secret buffers and terminate the owning worker
  where used; coordinate other open tabs. Do not promise complete memory erasure.
- Reviewer-key server backup is excluded by default. Any future encrypted backup
  needs a separately reviewed round-binding, authorization, expiry, snapshot, and
  destruction policy. Member-key recovery must not reactivate expired review keys.

### Recovery and compromise

Account access recovery and encrypted-key recovery are different operations. A
password reset, email link, TOTP code, or administrator action alone cannot decrypt
an existing backup. Prefer an already-unlocked device or a separately reviewed
client-held recovery secret for adding a new unlock method. A server-verified
account recovery code is not automatically a key-recovery secret; never send a
vault recovery secret to the server as an authentication code.

Specify recovery entropy, encoding, local wrapping, authorization, replacement,
notification, and loss handling before offering it. Optional encrypted downloads
are an escape hatch, not required onboarding. If all unlock/recovery methods are
lost, explain that old encrypted material is unavailable. Revoke and re-enroll
where appropriate while preserving membership quota usage and reservation state.
Do not promise recovery of anonymous receipts/replies through the account vault.

Passphrase changes and removing a passkey do not revoke previously copied backups
or plaintext keys. Key compromise needs a separate rotation/revocation procedure.
Server-stored password backups permit offline guessing after theft; server rate
limits do not prevent it. All wrapping/recovery methods contribute to the vault's
effective security. A malicious website or compromised device can steal secrets
while unlocked, including PRF outputs. See the [threat model](threat-model.md#browser-account-and-vault-risks).

### Research basis and outstanding evidence

Primary sources consulted 2026-10-27:

- WebAuthn Level 3 above defines the authentication and PRF behavior. The working
  group's [PRF explainer](https://github.com/w3c/webauthn/blob/main/explainers/prf-extension.md)
  explains credential-specific secrets and why multiple credentials need a
  separately designed encryption structure. It is explanatory, not the profile.
- [OWASP browser storage guidance](https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#storage-apis)
  supports treating browser databases as untrusted storage, not a secret boundary.
- [NIST SP 800-63B-4 account recovery](https://pages.nist.gov/800-63-4/sp800-63b/events/#recovery)
  and [customer experience](https://pages.nist.gov/800-63-4/sp800-63b/customer/)
  inform authentication recovery and usable prompts. These references do not
  specify encrypted-vault recovery or establish an assurance-level claim here.

No supported-browser/provider matrix, vault wrapping/recovery profile, browser
private-key bridge, server vault API, or end-to-end evidence exists yet. Acceptance
requirements live in [testing](testing.md#browser-account-and-vault-acceptance).

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
| Vault unlock and key-recovery secrets | Member browser/user-controlled recovery material | Never sent to services; distinct from account recovery credentials |

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

Typed key wrappers provide `Generate`, `Seal`, and `Open`. They generate local
keys, validate and encrypt existing keys, and validate decrypted canonical PKCS #8
payloads. Each fixes its own backup purpose and returns no key on failed import.

| Package | Key and validation | Unavailable workflows |
| --- | --- | --- |
| `internal/client/memberkey` | Ed25519; rejects inconsistent private/public halves on export. See [member-key profile](cryptography.md#member-key-payload-profile-1) | Raw serialization API, signing endpoint, identity/round binding, certificates, enrollment |
| `internal/client/reviewerkey` | X25519; validates the library's 32-byte private encoding. See [reviewer-key profile](cryptography.md#reviewer-key-payload-profile-1) | Round binding, expiry, round-key publication, HPKE decryption |

Generated/imported private buffers are caller-owned. X25519 bytes can construct
in-memory `ecdh.PrivateKey` objects, but their opaque internal copies cannot be
explicitly cleared. Future reviewer workflows must generate a fresh key per round.

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
  persistence are caller responsibilities. The offline CLI implements the subset
  below. Never store a raw key beside its backup.
- The generic keystore leaves serialization and purpose selection to callers;
  typed wrappers fix both.
- The format neither detects a restored old backup nor enforces revocation or
  reviewer-key expiry. Do not use it as evidence of safe retention/recovery.

Remaining custody requirements:

- Extend key generation to reviewed device interfaces and enforce reviewer round
  binding and retention. Preserve the profile's bounded Argon2id derivation and
  complete-header authentication.
- Treat imports as untrusted. Preserve memory, iteration, size, and version limits;
  wrong passwords or corrupt files must expose no partial plaintext.
- Browser persistence and exports must reuse the same Go implementation as the CLI.
- Promise password recovery only with a separately reviewed mechanism. Lost keys
  may require revocation and fresh enrollment.
- Recovery preserves membership quota usage. It cannot reset allowance or replace
  reserved tokens. Unreserved slots retain ordinary limit and eligibility checks.

## Local key CLI

`make build` builds `bin/client`, an optional development-only offline command using
the shared key profiles. It is not product onboarding or a browser prerequisite.
Independent review is required before real-key use.

The CLI performs no network calls, enrollment, general-purpose signing, reviewer
round binding, expiry checks, or submission decryption. A local CSR signature does
not make a key trusted or authorized.

| Command | Required flags | Result |
| --- | --- | --- |
| `client generate` | `-kind member\|reviewer -out PATH` | Fresh key, encrypted backup file; no stdout |
| `client inspect` | `-kind member\|reviewer -in PATH`, optional `-out PATH` and expected-key flag below | Validated backup, optionally matched to an expected key; public key on stdout or in a new owner-only file |
| `client rewrap` | `-kind member\|reviewer -in PATH -out PATH`, optional expected-key flag below | Validated existing key, optionally matched to an expected key, freshly encrypted backup under the replacement password; no stdout |
| `client csr` | `-kind member -in PATH`, optional `-out PATH` and expected-key flag below | Validated member backup, optionally matched to an expected key; signed identity-free binary DER on stdout, or in a new owner-only file with no stdout |
| `client verify-csr` | `-kind member -in PATH`, optional `-out PATH` and expected-key flag below | Validated member request and signature, optionally matched to an expected key; public key on stdout or in a new owner-only file, no password input |
| `client -help` | None | Static help on stdout; no password read |

- `inspect` prints exactly `member:<hex>\n` or `reviewer:<hex>\n`, using the
  32-byte public key in lowercase hexadecimal. Optional `-out` selects
  [public-key file export](#local-public-key-file-export) instead of stdout.
- Expected-key checks accept either `-expect-public-key HEX` or
  [`-expect-public-key-file PATH`](#local-expected-key-files), never both.
- Each operation also supports `-help`/`-h`. Unknown flags, positional arguments,
  missing values, unsupported kinds, and flags for another operation fail.
  Arguments are bounded to 8192 bytes including separators.
- Exit `0` means success or help; all failures, including cancellation, exit `1`.
  Errors go to stderr without reflecting arguments, paths, passwords, or key bytes.
- There are no password flags or application environment settings. See
  [versioning](versioning.md#local-key-cli-compatibility) for compatibility rules.

### Password input

For backup operations, standard input must be a pipe or regular file, never a
terminal or device. There is no interactive prompt or terminal-echo management.
Use a trusted password manager that emits the framing below without exposing passwords in arguments,
shell history, environment variables, or logs.

Each line must end in LF, and the final line must be followed by EOF. Extra bytes fail.

| Operation | Password lines, in order | Maximum read buffer |
| --- | --- | --- |
| `generate` | Password, matching confirmation | 2051 bytes |
| `inspect` | Password | 1026 bytes |
| `csr` | Password | 1026 bytes |
| `rewrap` | Current password, replacement, matching replacement confirmation | 3076 bytes |

- A replacement may equal the current password; fresh salt and nonce are still generated.
- Each password is 1–1024 opaque bytes excluding LF. Spaces, CR, NUL, and non-UTF-8
  bytes are preserved. LF cannot be represented by this interface; the underlying
  backup profile is unchanged. CRLF input includes CR in the password.
- Owned input/password/private-key buffers are cleared on return. The producer's
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

- **Directory trust:** the selected parent is pinned through `os.OpenRoot` and
  must have no group/other permission bits. Its owner, ancestors, mounts, and
  access-control lists must be trusted. Parent symlinks are not an independent
  trust check. These checks do not isolate hostile same-user processes, privileged
  users, or a compromised device.
- **Publication:** generation and rewrapping write ciphertext to a randomly named,
  same-directory temporary regular file with permissions at most `0600`. They sync
  and close it, then publish with a no-replace hard link. Existing files, directories,
  and symlinks, including dangling symlinks, are never overwritten. Filesystems
  without hard-link support fail closed; there is no rename/overwrite fallback.
- **Cleanup and durability:** temporary names are removed on return when possible;
  cleanup failure is reported. Successful publication syncs the directory.
  Power-loss durability depends on the filesystem and device honoring sync.
- **Interrupted writes:** a crash can leave an encrypted temporary file. An error
  or cancellation after publication can leave a complete final backup. Inspect
  the selected path before retrying; never delete an existing backup merely because
  a retry failed.
- **Imports:** accept only owner-only, bounded regular files, rejecting symlinks,
  directories, and special files before opening. Identity/permissions are checked
  again after opening, and reads are bounded to the backup maximum plus one byte.
  This assumes no hostile writer in the trusted directory; it does not establish
  immutability or freshness. Typed wrappers authenticate purpose and validate DER.
- **Inspection:** `inspect` emits no output on validation failure and never exports
  plaintext private keys. Successful public-key output is not a round bulletin,
  enrollment proof, authorization decision, or expiry/rollback check.

### Backup password changes

`rewrap` opens the input through the selected typed key package, then seals the
same key under the replacement password using the existing backup/payload profile.
Both derivations use full profile costs and cancellation-aware admission. Wrong
passwords, wrong purposes, malformed or authenticated non-key payloads fail before
any output file is created.

Private bytes remain in memory and owned buffers are cleared on return; the
runtime-erasure limits above still apply.

The output must be a new path. Rewrapping never changes or deletes the input, even
when input and output name the same file. Existing destinations and symlinks fail
under the same no-replace publication rules as generation. Verify the new backup
with `inspect` before managing old copies under an independently reviewed retention
procedure.

To reject a substituted input before re-encryption, pass `-expect-public-key HEX`
with an independently retained public key. Matching occurs after typed backup
authentication and payload validation, using that same in-memory key before
replacement-password derivation or file creation. A mismatch leaves the source
unchanged, creates no output or temporary file, and writes nothing to stdout.
There is no fallback to unpinned rewrapping.

To check that the replacement still holds the expected key, use
[`inspect -expect-public-key`](#local-backup-key-matching) with the independently
retained public key from the trusted original backup.

Password changes do not rotate keys, revoke old backups, repair a weak old password,
enforce expiry, or make a compromised key safe. Retained copies remain decryptable
with their old password; no secure-deletion claim is made.

See [testing](testing.md#implemented-test-mapping) for executable evidence and
[threat model](threat-model.md) for remaining device and offline-guessing risks.

### Local backup key matching

`inspect -expect-public-key HEX` requires the validated member or reviewer backup
to contain that exact public key before stdout or an output file is written. `rewrap` supports the
same flag before [password replacement](#backup-password-changes). Supply exactly
64 ASCII hexadecimal characters in either case, without a kind prefix, whitespace,
or newline.
Empty, malformed, oversized, and repeated flags fail before password input or file
access. Omitting the flag preserves ordinary inspection or rewrapping. Generation
rejects it; CSR creation and request verification support it separately below.

Inspection still requires the usual one-line password input, trusted-file checks,
authenticated purpose, and canonical typed payload validation. A match prints the
unchanged `member:<hex>\n` or `reviewer:<hex>\n` line, or publishes it with `-out`;
a mismatch fails with no stdout or file creation.
Errors contain neither key nor the file path. Cancellation before output prints
nothing; output failures can leave a partial line, which must be discarded.

Obtain the expected key independently, such as retained inspection output from a
trusted original backup before restoration or password replacement. Copying it from
the file under examination provides no substitution protection. Public-key arguments
remain linkable and may appear in process listings and shell history.

A match establishes neither freshness, revocation, identity, authorization, nor
reviewer round binding or expiry. Older backups for the same key still match. For
X25519, this compares public keys, not exact private encodings: equivalent private
encodings can produce the same public key. Cryptographic profiles are unchanged.

### Local public-key file export

`inspect -out PATH` and `verify-csr -out PATH` publish exactly the same public-key
line as their default stdout output in a new owner-only regular file. They write
nothing to stdout, including on failure, and never fall back to stdout. An explicitly
empty output path fails before password input or file access. Omitting `-out`
preserves stdout behavior, including detection of short or failed writes.

Validation and optional `-expect-public-key` matching finish before any output or
temporary file is created. Inspection still requires its one-line password input;
request verification never reads stdin. Neither command exports a private key.

Use an existing owner-only trusted directory under the [file-custody rules](#file-custody).
The shared publisher syncs and closes a same-directory temporary file with permissions
at most `0600`, publishes it with a no-replace hard link, and syncs the directory.
Existing files, directories, symlinks, and the input itself are never replaced.
Unsupported hard-link filesystems fail closed without a rename fallback.

Cancellation before publication removes the temporary file when possible. Errors or
cancellation after publication can leave a complete final file; a crash can leave a
public `.anonce-public-key-` temporary file. Inspect the destination before retrying.
Cleanup failures are reported; sync durability depends on the filesystem and device.

These files are public and linkable, not encrypted, signed attestations, or independent
trust anchors. Retaining a record from a trusted original backup can support later
expected-key checks; exporting an untrusted input's key does not make it trusted.
The hex flag accepts only its existing 64-character encoding; use
[`-expect-public-key-file`](#local-expected-key-files) to read this file directly.
Matching still establishes no freshness, identity,
revocation, enrollment authority, reviewer round binding, or expiry.

### Local expected-key files

`inspect`, `rewrap`, `csr`, and `verify-csr` accept `-expect-public-key-file PATH`
instead of `-expect-public-key HEX`. Retain an independently trusted export from
`inspect -out` or `verify-csr -out`; copying a key from the input being checked
provides no substitution protection. Generation rejects both expected-key flags.

The file must contain exactly the existing lowercase public-key line for the
selected kind: `member:<64 lowercase hex characters>\n` (72 bytes) or
`reviewer:<64 lowercase hex characters>\n` (74 bytes). Uppercase hex or kind names,
bare hex, CRLF, missing LF, whitespace, extra lines, trailing bytes, and wrong-kind
records fail. No trimming, format detection, or fallback is performed.

The same [trusted owner-only file and parent checks](#file-custody) apply. Reads
are capped at the selected kind's line length plus one byte to detect growth.
The file is read once before password input or backup/request access; its public
key is retained in memory for the existing post-validation comparison. Failures
write no stdout and create no output or temporary files. `verify-csr` still never
reads stdin. Empty, NUL-containing, repeated, oversized, or conflicting flags fail
at argument parsing, before any file or password access.

Matching still precedes output, CSR signing, or replacement encryption and does
not weaken typed backup or request signature validation. Existing output and
no-replace rules apply, including when the output names the expected-key file.
Neither input file is modified. Cancellation propagates without unpinned fallback.

The file must remain independently trusted, including its directory and ancestors.
Permissions do not authenticate its contents or protect against hostile same-user
writers. Its path can appear in process listings and shell history, and the public
record remains linkable. Matching adds no freshness, revocation, identity,
enrollment authority, reviewer round binding, or expiry guarantee.

### Local member certificate requests

`csr` opens a member-purpose backup through `memberkey` and uses the shared
`membercsr` package to create [member CSR profile 1](cryptography.md#member-csr-profile-1).
Without `-out`, stdout contains exactly 129 bytes of binary DER without a label,
PEM armor, or additional newline. Only `-kind member` is accepted; subject,
extension, and password flags are unavailable. Existing backup files are unchanged.

The command uses the same bounded one-line stdin and trusted-file import rules as
`inspect`. Validation or cancellation before writing produces no stdout; an output
failure can leave a partial public request, which must be discarded. Password and
owned private buffers are cleared on return, subject to the runtime limits above.

With `-expect-public-key HEX`, the authenticated and validated backup must contain
that exact member public key before request signing or file creation. The command
compares the complete public key and signs with that same in-memory key; it does
not reopen the backup. A mismatch writes nothing to stdout and creates no output
or temporary file, with no fallback to unpinned signing. Omitting the flag preserves
ordinary CSR creation. The check also works with `-out`.

Use the same 64-character ASCII hexadecimal encoding and independently trusted key
source as [backup key matching](#local-backup-key-matching). Empty, malformed,
oversized, or repeated flags fail before password input or file access. Matching
does not establish freshness, revocation, identity, or enrollment authority; public
key arguments remain linkable and visible to process inspection and shell history.

With `-out PATH`, the command publishes the same 129 public bytes in a new regular
file with permissions at most `0600` and writes nothing to stdout. An explicitly
empty output path fails rather than selecting stdout. Use an existing owner-only
trusted parent directory under the [file-custody rules](#file-custody). The shared
publication helper syncs and closes a same-directory temporary file, then creates
the destination with a no-replace hard link and syncs the directory. Existing
files, directories, and symlinks, including the input backup, are never replaced.
Unsupported hard-link filesystems fail closed without a rename fallback.

Validation failure creates no output. Cancellation before publication removes the
temporary file when possible; an error or cancellation after publication can leave
a complete request. A crash can leave a public `.anonce-request-` temporary file.
Check the destination before retrying. File requests are not encrypted: they
contain only the linkable public key and its signature, never private-key bytes.
They can be passed directly to `verify-csr` without changing permissions.

A request is not a certificate, fresh challenge, enrollment proof, or authorization.
It includes no identity, cohort, enrollment code, or requested privileges. It is
linkable to the membership public key and must not reach the anonymous submission
origin. No CA transport or code-consumption workflow exists.

### Local member request verification

`verify-csr` reads a request file and reuses `membercsr.Parse` to enforce the
unchanged member CSR profile 1 and verify its signature through `crypto/x509`.
It accepts `-kind member -in PATH`, with optional `-out PATH` and
`-expect-public-key HEX`. It never reads stdin or performs password derivation, private-key operations, network
calls, or input-file writes. Success prints exactly `member:<hex>\n`, matching the
public-key encoding from `inspect`, or publishes that line through
[public-key file export](#local-public-key-file-export).

Use an owner-only regular file in an owner-only trusted directory, under the same
[import rules](#file-custody) as backups. The file is capped at 129 bytes before
parsing; reads are bounded to 130 bytes to detect growth. Symlinks, devices,
directories, PEM, extra claims, trailing data, and invalid signatures fail without
stdout. Cancellation is checked before reading, after reading, and before output.
Output failures can leave a partial public-key line, which must be discarded.

With `-expect-public-key HEX`, the validated request must contain that exact
32-byte public key before any stdout or output file is written. Supply exactly
64 ASCII hex characters in either case, without a `member:` prefix, whitespace, or newline.
Empty, malformed, oversized, or repeated expected-key flags fail as invalid
arguments before reading the request. Backup inspection supports the same flag
under [backup key matching](#local-backup-key-matching), as does rewrapping; CSR
creation checks before signing, and generation rejects it. Omitting it preserves
ordinary request verification and public-key output.

Obtain the expected key through an independently trusted channel, for example
the hex portion of `inspect` output for a trusted local member backup. Copying
the key from the untrusted request being checked provides no substitution
protection. The expected key is public but linkable; command arguments can be
visible to local process inspection and shell history. Errors include neither
the expected key nor the request key.

A valid request does not establish freshness, identity, eligibility, certificate
trust, revocation, or enrollment authorization. Its public key remains linkable
and must not reach the anonymous submission origin. Independent review is required
before real use.

## Local WASM request verification

`make wasm` builds a development-only `js/wasm` entry point in `bin/wasm/` using
Go 1.27.3. It reuses `membercsr.Parse`; no cryptographic profile changes. The
directory contains `client.wasm`, the matching unmodified `wasm_exec.js`, Go
`LICENSE`/`PATENTS`, `LICENSE.anonce`, and `SHA256SUMS`. The build checks reviewed
loader/notice hashes and an 8 MiB uncompressed WASM ceiling in `scripts/wasm.toml`.
Generated files are disposable, not signed releases or independently trusted hashes.

After a trusted host loads the matching Go runtime and starts the module with
`Go.run`, `globalThis.anonce` exposes only:

| Method | Contract |
| --- | --- |
| `verifyCSR(hex)` | Exactly one primitive string containing 258 ASCII hexadecimal characters, either case, encoding the unchanged 129-byte DER profile; returns exactly `member:<lowercase hex>\n` on success, JavaScript `null` on invalid input |
| `verifyCSRForKey(hex, expectedHex)` | Exactly two primitive strings: the same request hex and exactly 64 ASCII hexadecimal characters encoding an independently trusted 32-byte member public key, either case; returns the same public-key line only after profile/signature validation and an exact key match, otherwise `null` |
| `close()` | No arguments; removes the namespace, releases callbacks, and lets `Go.run` finish. Extra arguments return `null` without shutting down |

The bridge checks JavaScript string lengths before copying into Go, bounding both
inputs to `verifyCSRForKey` before copying either. It bounds hex decoding and calls
the shared profile/signature validator. It rejects
objects without inspecting or coercing them. PEM, trailing bytes, extra claims,
and invalid signatures fail without public output. Calls are synchronous; hosts
must bound repeated calls and must not reuse saved callbacks after shutdown.
An existing `anonce` namespace is never overwritten; the new instance exits instead.

Use `verifyCSRForKey` when request substitution must be rejected. Obtain the expected
key through an independently trusted channel, not from the request being checked.
Empty or malformed expected keys, missing/extra arguments, and mismatches return
`null` without falling back to ordinary verification. Key matching establishes no
freshness, identity, eligibility, revocation, or enrollment authority. The existing
one-argument `verifyCSR` contract remains unchanged and still rejects extra arguments.

There is no file, password, private-key, network, storage, or enrollment interface.
Public requests and keys remain linkable and must not reach the anonymous submission
origin. The loading realm and its built-ins must be trusted; WASM does not isolate
the verifier from its host. Do not change the inert shell's CSP to load this artifact.
No browser page, delivery loader, CSP integration, or supported-browser evidence is
provided. See [testing](testing.md#wasm-verifier-checks) for Node-only evidence and
[compatibility](versioning.md#wasm-verifier-compatibility) for review requirements.

This follows the official [Go WebAssembly build/runtime guidance](https://go.dev/wiki/WebAssembly)
and [Go 1.27.3 JavaScript bindings](https://pkg.go.dev/syscall/js@go1.27.3)
(accessed 2026-10-27). No Node product build or npm dependencies are introduced.

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

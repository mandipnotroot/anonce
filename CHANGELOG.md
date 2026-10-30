<!-- SPDX-FileCopyrightText: 2026 Anonce Contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Changelog

Notable changes follow [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/)
and [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).
No release has been published.

## [Unreleased]

### Added

- Browser passkey accounts, automatic member-key setup, encrypted member backups,
  single-use membership invitations and an eligible-review dashboard.
- Administrator publication of one free-text question with one reviewer and an
  explicitly selected one-response limit. Reviewer keys are round-scoped, backed
  up only in that browser, and used for local decryption.
- Blind authorization, anonymous HPKE-encrypted answers, atomic single-use spending,
  payload-bound retries and locally verified signed storage acceptance. Acceptance
  is not public transparency-log inclusion.
- Bounded own-account session inventory, selected-session sign-out, confirmed
  sign-out everywhere and passkey reauthentication that preserves absolute expiry.
  Local locking and invalidation observation cannot recall copied keys or plaintext.
- Isolated TLS services and PostgreSQL databases, scoped runtime credentials,
  operator-only immutable migrations and no-replace server initialization.
- Shared Go cryptography, bounded worker custody, native/Node compatibility checks,
  parser fuzzing and opt-in real-browser, PostgreSQL and container checks.
- Contributor policies, licensing checks, private-disclosure guidance and validated
  mdBook documentation.

### Changed

- Standardized the application, build, API reference and documentation on one
  browser-only workflow for members, reviewers and administrators. `make up` is
  the operator startup command; users need no installed tools or key files.
  Development interfaces are unreleased and may change without compatibility shims.

- PR title, description, and label edits no longer trigger CI. Code updates and
  existing lifecycle, default-branch, and manual triggers retain all checks.

### Fixed

- WASM builds with an empty module cache download admitted notice sources at their
  selected versions before verifying license hashes, including platform-unused modules.

- Browser reviewer reads reject malformed or undecryptable answers individually
  and continue with later records. Lock, visibility loss, round expiry, and owner
  replacement still stop reading without publishing late plaintext; owned buffers
  are cleared.
- Policy, Pages, and nightly CI explicitly install and verify ExifTool before
  inspecting asset metadata, keeping missing inspection a failure.

Production operation, independent security approval, recovery, PRF unlocking,
protected signers and reviewer server backup remain unavailable.

[Unreleased]: https://github.com/mandipnotroot/anonce/commits/main

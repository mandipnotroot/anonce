<!-- SPDX-FileCopyrightText: 2026 Anonce Contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Changelog

Notable changes follow [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/)
and [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Opt-in confirmed member setup and encrypted-backup export through shared Go
  `CreateConfirmed`/`BackupConfirmed` and development WASM/worker
  `createConfirmed`/`backupConfirmed`. Bounded exact password matching precedes key
  generation, private-key snapshots, and derivation; mismatches return no output
  and preserve session state. Native race/fuzz and Node bridge/worker checks cover
  confirmation and cancellation. Synthetic browser cases are added but unverified.
  No UI, storage, account authentication, recovery, or cryptographic profile is added.
- Unlocked member-session encrypted-backup export through shared Go `Backup` and
  development WASM/worker `backup(password)`, preserving the key with fresh profile-2
  encryption and ciphertext-only output. Native race/cancellation, Node compatibility,
  and worker bounds/fuzz checks cover export; synthetic browser cases are added but
  unverified. Old backups remain valid. No persistence, account-password change,
  key rotation, revocation, recovery, product UI, or new cryptographic profile is added.
- Optional development member-worker `AbortSignal` ownership for immediate local
  cancellation of startup, unlocked custody, or pending restoration. Cancellation
  terminates the instance without notifying peers or exposing the abort reason;
  an already-aborted signal starts no worker. Existing no-argument construction,
  transport, HTTP, and cryptographic profiles are unchanged.
- Development member-worker `closed` Promise for secret-free observation of terminal
  local cleanup, including idle peer lock and failed startup, without polling.
  Node lifecycle and actual-worker checks plus synthetic browser checks cover the
  observer. Existing methods, transport, HTTP, and cryptographic profiles are unchanged;
  settlement does not establish worker exit, erasure, account logout, or revocation.
- Opt-in `make member-browser-test` for synthetic member workers in sandboxed
  headless Chromium: native/worker backup compatibility, restoration failures,
  page CSP probes, UI event-loop progress, same-origin peer lock, and worker
  termination on navigation. A Go test-only loopback host verifies bounded assets
  and rejects unexpected hosts, origins, paths, methods, and bodies. Product HTTP,
  shell CSP, and cryptographic profiles are unchanged. No account/vault journey,
  mobile/provider support, accessibility, or complete-erasure claim is added.
- Development-only member-worker lock coordination using a fixed, secret-free
  BroadcastChannel notification and local pagehide termination. Explicit lock
  notifies peers; disposal remains local. A host helper can lock peers without a
  live local owner. Missing coordination facilities reject startup without fallback.
  Node lifecycle/failure checks cover the implementation, not browser delivery,
  partition behavior, account logout, reliable global revocation, or memory erasure.
- Development-only dedicated-worker host for member WASM sessions, with bounded
  input snapshots, transferred buffers, correlated responses, one active owner per
  module realm, and startup/operation/lifetime limits. Lock/disposal terminates the
  worker and cancels pending output without waiting for queued worker execution.
  Node worker/native backup compatibility, transport failure, and lifecycle checks
  are included. Existing direct bridge, CLI, HTTP, and cryptographic profiles are
  unchanged. No browser page, delivery/CSP integration, account storage, passkeys,
  recovery, account logout integration, or complete-erasure guarantee is provided.
- Separate development-only WASM member-session bridge for automatic key/backup/CSR
  setup, required expected-key restoration, fixed requests, and lock/shutdown.
  Bounded nonshared byte inputs are snapshotted before work; owned passwords are
  cleared before Promise settlement, with one admitted operation per instance.
  Native/Node backup compatibility and rejection/lifecycle checks are included.
  Existing verifier, CLI, HTTP, and cryptographic profiles are unchanged. Browser
  page/worker integration, accounts, persistence, passkeys, and recovery remain unavailable.
- Shared in-memory member sessions for automatic key, encrypted-backup, and CSR
  preparation; restoration requires a validated backup and an independently trusted
  expected key. Private bytes stay internal, lock clears owned key buffers and
  cancels pending work, and concurrent setup/restoration is bounded per session.
  Existing cryptographic profiles and CLI/HTTP/WASM contracts are unchanged.
  Browser integration, account binding, persistence, expiry, and recovery remain
  unavailable; native race, failure, lifecycle, and bounded admission-fuzz checks
  cover the local component only.
- Optional `-expect-public-key-file PATH` on `client inspect`, `rewrap`, `csr`, and
  `verify-csr` to read an independently trusted public-key export instead of a hex
  argument. Bounded owner-only imports reject malformed or wrong-kind records before
  password/input access; conflicting or repeated expected-key flags fail closed.
  Matching still follows typed backup or request validation, before output, signing,
  or replacement encryption. Existing formats, password framing, default behavior,
  WASM, and HTTP are unchanged. Records remain public and linkable, not proof of
  freshness, revocation, round binding, or enrollment authority.
- Optional `client inspect -out PATH` and `client verify-csr -out PATH` for owner-only,
  synced, no-replace public-key files instead of stdout. Validation and optional
  expected-key matching precede file creation; publication failures never fall back
  to stdout. Default output, password framing, cryptographic formats, WASM, and HTTP
  behavior are unchanged. Exported keys remain public and linkable, not trusted
  attestations or evidence of freshness or enrollment authority.
- Optional `client csr -expect-public-key HEX` to reject a substituted member
  backup after typed validation, before signing or creating a request file. Works
  with stdout and `-out`; mismatches produce no output. The expected key must be
  independently trusted. Existing password framing, cryptographic formats, WASM,
  and HTTP behavior are unchanged; this adds no freshness or enrollment authority.
- Optional `client rewrap -expect-public-key HEX` to reject a substituted member or
  reviewer backup after typed validation, before replacement encryption or file
  creation. The expected key must be independently trusted. Existing rewrapping,
  password framing, cryptographic formats, WASM, and HTTP behavior are unchanged;
  matching does not establish freshness, revocation, or reviewer round binding.
- Optional `client inspect -expect-public-key HEX` for validated member/reviewer
  backup key matching before public output. Malformed or repeated flags fail before
  password/file access; mismatches print nothing. The expected key must be
  independently trusted. Existing formats, password framing, default inspection,
  request verification, WASM, and HTTP behavior are unchanged. Matching does not
  establish backup freshness, revocation, or reviewer round binding.
- Public-only WASM `verifyCSRForKey(hex, expectedHex)` for bounded request and
  signature validation followed by exact expected-key matching. Invalid input or
  mismatches return `null` without public output or fallback. Existing `verifyCSR`,
  CLI, HTTP, and cryptographic profiles are unchanged; the expected key must be
  independently trusted. No page integration or enrollment is added.
- Optional `client verify-csr -expect-public-key HEX` to reject requests for a
  different member key before public output. Malformed or repeated expected-key
  flags fail before file access. Existing verification, cryptographic profiles,
  and WASM behavior are unchanged; the expected key must be independently trusted.
- Optional `client csr -out PATH` for owner-only, synced, no-replace public request
  files that can be used directly by `verify-csr`. Existing stdout behavior,
  passwords, cryptographic formats, and HTTP services are unchanged. This does not
  implement enrollment or certificate issuance.
- Public-only Go WASM member request verifier using the existing CSR profile and
  parser, with bounded input, explicit shutdown, reviewed loader hashes/notices,
  an artifact size gate, and native/WASM compatibility checks. No page integration,
  private-key access, enrollment, or certificate trust is implemented.
- Offline `client verify-csr` for bounded member request and signature validation,
  with public-key-only output, owner-only file imports, and no stdin or private-key
  access. Existing cryptographic formats and commands are unchanged. Verification
  does not authorize enrollment or establish certificate trust.
- Offline `client csr` for identity-free member certificate requests using existing
  encrypted backups, bounded password input, and public-only binary DER output.
  Shared validation and race/fuzz tests reject invalid signatures and extra claims.
  No enrollment, certificate issuance, or network operation is implemented.
- Offline `client rewrap` for validated member/reviewer backup password changes,
  confirmed bounded stdin input, fresh encryption, preserved key bytes, and
  no-replace output. Old backups are unchanged and remain valid; this is not key
  rotation, revocation, or secure deletion. Existing formats are unchanged.
- Offline `client generate` and `client inspect` commands for encrypted member and
  reviewer backups, bounded confirmed stdin passwords, owner-only no-replace files,
  and public-key-only inspection. Existing backup formats are unchanged; browser,
  enrollment, round binding, and independent security review remain outstanding.
- Shared local X25519 reviewer-key generation, validated encrypted PKCS #8 backups,
  purpose-isolation and cancellation/concurrency tests, and bounded payload fuzzing.
  Browser interfaces, round binding, and submission decryption remain unavailable.
- Shared local Ed25519 member-key generation, validated encrypted PKCS #8 backups,
  strict import validation, cancellation/concurrency tests, and bounded payload
  fuzzing. Browser custody and enrollment remain unavailable.
- Shared in-memory device-backup encryption with bounded Argon2id, ChaCha20-Poly1305,
  authenticated key purposes and headers, cancellation-aware derivation admission,
  tampering/concurrency tests, parser fuzzing, and native benchmarks. See
  [key management](docs/key-management.md#device-keystores) for custody limits.
- A read-only local submission-service overview and about page, opt-in mock style
  guide, embedded content-addressed CSS with SRI, and rendered-shell checks.
- Local-only Go CA, issuer, and submission commands with liveness, explicit
  demonstration status, source discovery, bounded connections, and graceful shutdown.
- Go build, race/coverage, lint, bounded configuration fuzzing, vulnerability, and
  secret checks. Protocol operations remain unavailable and readiness fails closed.
- Project licensing, contributor rules, local hooks, and repository policy checks.
- Technical references for architecture, protocol, security, storage, and interfaces.
- A component roadmap with implementation priorities and open questions.
- Governance, private-disclosure guidance, contribution templates, and documentation
  validation workflows.
- An mdBook site with topic-based navigation, local search, device fonts,
  light/dark themes, checksum-pinned setup, and source/rendered link validation.

### Changed

- Breaking development bridge/worker method-set expansion for opt-in password
  confirmation. Rebuild and deploy all member assets together; mixed method sets
  fail closed. Existing methods, command envelopes, HTTP, CLI, and backup formats
  are unchanged; confirmed calls never fall back to unconfirmed operations.
- Breaking development bridge/worker method-set expansion for encrypted-backup
  export. Rebuild and deploy all member WASM/worker assets together; incompatible
  bridge method sets fail closed. Existing command envelopes, HTTP, CLI, and backup
  formats are unchanged.
- Breaking development member-worker lifecycle change: require valid monotonic and
  wall clocks and enforce existing startup, operation, and lifetime deadlines before
  admission or publishing readiness/results, even when timeout callbacks are delayed.
  Failed, invalid, or backward readings terminate locally without notifying peers;
  restoration needs an explicit new owner. Node boundary/failure tests and actual
  Node/Chromium worker checks use synthetic clock advances, not real suspension.
  No account/vault integration, hard expiry, format, or product HTTP change is added.
- Breaking development member-worker lifecycle change: require a visible owner
  document, terminate locally on visibility loss, and reject hidden-page startup.
  Data admission and reply publication recheck visibility. Foregrounding requires
  explicit restoration through a new owner; peers are not notified by backgrounding.
  Node failure/lifecycle tests and synthetic Chromium tab-switch/restoration checks
  cover this behavior. Direct bridge, transport, HTTP, and cryptographic profiles
  are unchanged; no reliable suspension, user-presence, or memory-erasure claim is added.
- Document the maintainer rule for PR-number suffixes on squash-merge commit titles.
- Breaking development worker-owner lifecycle change: BroadcastChannel and page
  event APIs are now required, and explicit lock also notifies participating peers.
  Direct bridge methods, worker commands, CLI, HTTP, and cryptographic profiles
  are unchanged. See [compatibility](docs/versioning.md#wasm-member-session-compatibility).
- Document only the supported ChaCha20-Poly1305 device-backup profile, remove repeated
  custody guidance, and consolidate parser-rejection tests across both key purposes.
  Backup formats and runtime behavior are unchanged.
- Set the planned product direction to browser-only accounts, shared review links
  and an eligible-round dashboard, with automatic device-side key management and
  identity-side encrypted member-key backups. Document researched passkey/PRF
  unlocking, browser-only compatibility, separate account/key recovery, anonymity
  boundaries, and required acceptance evidence. Prioritize the complete browser
  journey over optional CLI extensions. No account/vault API, new cryptographic
  profile, or runtime behavior is implemented by this documentation change.
- Breaking cryptographic-format addition: define member CSR profile 1 as fixed,
  canonical Ed25519 PKCS #10 DER. Existing backups and HTTP behavior are unchanged;
  independent review is required before real use.
- Link conventions and standards to their official, project-adopted versions
  instead of repeating their rules. Preserve project-specific requirements and
  identify standards whose versions remain unselected.
- Clarify documentation with focused sections, shorter summaries, and canonical
  links while preserving requirements and safety guidance. Correct outdated
  component-status descriptions and require professional, concise, complete prose.
- Breaking cryptographic-payload addition: define reviewer-key payload profile 1
  inside the unchanged device-backup format. Only canonical X25519 PKCS #8 is
  accepted by the typed importer. Independent review is still required.
- Breaking cryptographic-payload addition: define member-key payload profile 1
  inside the unchanged device-backup format. The typed importer rejects opaque,
  wrong-algorithm, and noncanonical payloads. Independent review is still required.
- Modernize internal Go cleanup, slice searches, and test contexts without changing
  HTTP responses, command interfaces, or device-backup formats.
- Shorten documentation, improve scanning, and link named standards without changing
  requirements or behavior.
- Breaking HTTP behavior: the submission process now serves HTML at `/` instead
  of the previous JSON `404`. CA and issuer routes and the status JSON are unchanged.
- Align public status with the demonstration infrastructure, include Go module
  dependency updates, document publication prerequisites, and reject padded commit
  descriptions.
- Define an administrator-set per-member limit
  in each signed round bulletin. Tokens remain single-use; quota enforcement and
  multi-response privacy checks are design requirements, not implemented features.
- Standardize original-work copyright notices as `Anonce Contributors`.
- Consolidate documentation around canonical references and remove repeated guidance.
- Focus documentation and planning on project capabilities and implementation evidence.
- Keep baseline requirements and acceptance evidence explicit in the documentation index.

### Fixed

- Pages CI now installs the pinned development Node.js runtime before running
  WASM checks instead of relying on the runner's preinstalled version.
- Backup inspection now reports short public-key writes as failures, rather than
  treating a partial stdout line as successful inspection.

[Unreleased]: https://github.com/mandipnotroot/anonce/commits/main

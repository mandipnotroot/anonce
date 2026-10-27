<!-- SPDX-FileCopyrightText: 2026 Anonce Contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Changelog

Notable changes follow [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/)
and [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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
- Shared in-memory device-backup encryption with bounded Argon2id, AES-256-GCM,
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
- Breaking cryptographic-format addition: define device-backup profile 1 with no
  legacy decoder or parameter fallback. Independent review and native/WASM
  interoperability evidence are still required before real-key use.
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

- Backup inspection now reports short public-key writes as failures, rather than
  treating a partial stdout line as successful inspection.

[Unreleased]: https://github.com/mandipnotroot/anonce/commits/main

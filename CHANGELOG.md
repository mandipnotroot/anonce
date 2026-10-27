<!-- SPDX-FileCopyrightText: 2026 Anonce Contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Changelog

Notable changes follow [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Offline `client generate` and `client inspect` commands for encrypted member and
  reviewer backups, bounded confirmed stdin passwords, owner-only no-replace files,
  and public-key-only inspection. Existing backup formats are unchanged; browser,
  enrollment, round binding, and independent security review remain outstanding.
- Shared local X25519 reviewer-key generation, validated encrypted PKCS #8 backups,
  purpose-isolation and cancellation/concurrency tests, and bounded payload fuzzing.
  Device interfaces, round binding, and submission decryption remain unavailable.
- Shared local Ed25519 member-key generation, validated encrypted PKCS #8 backups,
  strict import validation, cancellation/concurrency tests, and bounded payload
  fuzzing. CLI/browser custody and enrollment remain unavailable.
- Shared in-memory device-backup encryption with bounded Argon2id, AES-256-GCM,
  authenticated key purposes and headers, cancellation-aware derivation admission,
  tampering/concurrency tests, parser fuzzing, and native benchmarks. No device
  interface or persistence integration is available yet.
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

[Unreleased]: https://github.com/mandipnotroot/anonce/commits/main

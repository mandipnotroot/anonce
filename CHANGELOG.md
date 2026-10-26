<!-- SPDX-FileCopyrightText: 2026 Anonce Contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Changelog

Notable changes follow [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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

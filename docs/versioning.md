<!-- SPDX-FileCopyrightText: 2026 Anonce Contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Versioning and compatibility

Audience: maintainers, integrators, and client authors.

Follow [SemVer 2.0.0](https://semver.org/spec/v2.0.0.html), consulted 2026-10-30.
First release: `v0.1.0`; no tag or released compatibility baseline exists.
Pre-release interfaces may change directly without deprecation shims or alternate
product paths. Review breaking impact explicitly; never preserve an unsafe path.

## Public API boundary

The product has one browser workflow. Its transport is defined in
[HTTP API](api.md) and [OpenAPI](openapi.yaml). Server administration uses the
commands and configuration in [deployment](deployment.md).

Public contracts include HTTP paths/statuses/schemas, cryptographic encodings and
parameters, certificate/trust rules, database migration ranges, operator flags,
configuration, signed bulletins and storage-acceptance receipts. Changes to these
contracts are breaking without an explicit reviewed compatibility mechanism.

Internal Go packages are unstable implementation details. Future public modules
must use `/vN` module/import paths for breaking v2+ releases.

### Cryptographic file compatibility

| Contract | Compatibility boundary |
| --- | --- |
| [Browser profile 1](cryptography.md#browser-mvp-profile-1) | Bulletin, token, challenge, HPKE envelope, review proof and signed acceptance |
| [Device-backup profile 2](cryptography.md#device-backup-profile-2) | Fixed Argon2id/ChaCha20-Poly1305 envelope; unknown profiles fail before derivation |
| [Member-key payload profile 1](cryptography.md#member-key-payload-profile-1) | Canonical Ed25519 PKCS #8, member purpose |
| [Reviewer-key payload profile 1](cryptography.md#reviewer-key-payload-profile-1) | Canonical X25519 PKCS #8, reviewer purpose |
| [Member CSR profile 1](cryptography.md#member-csr-profile-1) | Fixed identity-free Ed25519 PKCS #10 DER for automatic enrollment |

These profiles require independent security review before real-key use. Importers
reject wrong purposes, algorithms and noncanonical payloads without fallback.
PRF wrapping and recovery are not admitted profiles.

### WASM member session compatibility

Build and deploy the member/reviewer WASM, Go loader, workers, client modules,
manifests and original notices as one matched set using `make build`. Mixed builds
are unsupported and fail closed. Changes to method sets, command allowlists, text
encoding or lifecycle requirements need breaking-impact review. Do not fall back
to unconfirmed setup, another algorithm or automatic key replacement.

### Local container compatibility

`make up` builds the application, prepares no-replace state, applies isolated
migrations and starts the identity/submission TLS services. State and database
volumes are never automatically discarded or regenerated. Published migrations are
immutable. The runner supports contiguous histories through identity version 5 and
submission version 3 and rejects unsupported state. Review changes to ownership,
authentication, mounts and bootstrap grants explicitly.

## Change classification

Use the official SemVer definitions for stable releases. During `0.y.z`:

| Impact | Project policy |
| --- | --- |
| MAJOR | Increase MINOR; document breaking impact and required operator action |
| MINOR | Increase MINOR |
| PATCH | Increase PATCH |

Removed operator flags/configuration, incompatible formats and unsafe migration
ranges are breaking. Security fixes are not automatically PATCH. Before the first
release, update the single current contract rather than documenting multiple
supported versions. Do not rewrite released artifacts or shared Git history.

## Commit and PR mapping

Follow [Conventional Commits 1.0.0](https://www.conventionalcommits.org/en/v1.0.0/)
for meaning and breaking-change notation, with repository types/scopes/limits in
`scripts/commits.toml`.

- Compatible `perf` changes normally have PATCH impact.
- Docs/tests/CI/maintenance have no automatic bump unless public behavior changes.
- Every PR needs exactly one `semver:major`, `semver:minor` or `semver:patch` label.
  `semver:major` means breaking impact during `0.y.z` too.
- Non-release work may use `semver:patch` plus `changelog:not-needed` with maintainer rationale.
- Review the diff; labels do not replace compatibility analysis.

## Changelog contract

Follow [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/), consulted
2026-10-30. Maintain the human-curated [changelog](../CHANGELOG.md). PRs update
Unreleased unless a maintainer applies `changelog:not-needed`. Summarize supported
capabilities and relevant limitations, not a commit log. Released entries remain
accurate records; automation must not replace reviewed prose with commit messages.

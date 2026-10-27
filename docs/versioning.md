<!-- SPDX-FileCopyrightText: 2026 Anonce Contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Versioning and compatibility

Audience: maintainers, integrators, and client authors.

Use [SemVer 2.0.0](https://semver.org/spec/v2.0.0.html) and `vMAJOR.MINOR.PATCH` tags.
First release: `v0.1.0`; no tag yet.
Unstable `0.y.z` changes still require compatibility review.

## Public API boundary

Public contracts include:

- CLI commands, flags, exits; HTTP paths, statuses, schemas.
- Wire/token/envelope formats; keystores/backups; certificate profiles and trust rules.
- Database migration ranges; configuration keys/environment variables.
- Versioned forms/bulletins; documented client-visible asset hashes and receipt profiles.

Internal Go packages are unstable implementation details. Future public modules
must use `/vN` module/import paths for breaking v2+ releases, even in a monorepo.

**Current interfaces:** commands report `development`; see [API](api.md) and
[deployment](deployment.md#local-development). Infrastructure and shell additions
are unreleased, not stable wire profiles or a product. Future crypto formats need
explicit breaking review.

### Cryptographic file compatibility

The following formats are unreleased breaking additions requiring `semver:major`
review and independent security review before real-key use. None has a prior
supported format or legacy migration.

| Contract | Compatibility boundary |
| --- | --- |
| [Device-backup profile 1](cryptography.md#device-backup-profile-1) | Defines the outer encrypted file. Unknown versions/profiles fail closed; future format or parameter changes require breaking review and an explicit migration plan |
| [Member-key payload profile 1](cryptography.md#member-key-payload-profile-1) | Canonical Ed25519 PKCS #8 inside member-purpose backups |
| [Reviewer-key payload profile 1](cryptography.md#reviewer-key-payload-profile-1) | Canonical X25519 PKCS #8 inside reviewer-purpose backups |

Typed key importers reject opaque, wrong-algorithm, and noncanonical payloads.
Their addition does not change the outer format, generic opaque keystore API,
or HTTP/CLI contracts.

### Shell compatibility

Submission `/` changed from JSON `404` to HTML `200`,
breaking HTTP behavior even before release. Consumers expecting root errors must
use explicit infrastructure endpoints. `/about`, hashed CSS, and opt-in
`-dev-styleguide` are new. CA/issuer roots remain JSON `404`; infrastructure JSON is unchanged.

### Local key CLI compatibility

`client generate` and `client inspect` are new
opt-in commands requiring `semver:minor` review. Their flags, stdin framing, exits,
file-custody rules, and public-key output are documented in
[key management](key-management.md#local-key-cli). Existing HTTP commands and
encrypted backup/payload formats are unchanged. This does not remove the existing
breaking-impact or independent-review requirements for those unreleased formats.

`client rewrap` is an additive opt-in command requiring `semver:minor` review.
Its three-line password framing applies only to that command. Existing commands,
password framing, backup/payload formats, and HTTP behavior remain unchanged.

## Change classification

| Impact | Stable release behavior | Unstable release policy |
| --- | --- | --- |
| MAJOR | Incompatible public contract, removed flag/config, unsafe migration range, crypto/wire/parameter change without compatibility | Increase MINOR, document breaking impact and migration; use `!` or the standard breaking footer |
| MINOR | Backward-compatible feature or new opt-in capability | Increase MINOR |
| PATCH | Backward-compatible fix, clarification, hardening with no contract break | Increase PATCH |

Security fixes are not automatically PATCH: rejecting unsafe parameters or changing
trust anchors may break compatibility and require operator action. Crypto/wire
changes are breaking without a reviewed compatibility mechanism. Never retain insecure paths for compatibility.

## Commit and PR mapping

- `feat`: normally MINOR; `fix`/compatible `perf`: normally PATCH.
- Any type with `!` or `BREAKING CHANGE:`: breaking review.
- Docs/tests/CI/maintenance: no automatic bump unless public behavior changes.
- Review the diff; labels do not replace compatibility analysis.
- Every PR needs exactly one `semver:major`, `semver:minor`, or `semver:patch`.
  `semver:major` means breaking impact during `0.y.z` too; apply the unstable policy above.
- Non-release work may use `semver:patch` plus `changelog:not-needed` with maintainer rationale.

## Changelog contract

- Human-curated [CHANGELOG.md](../CHANGELOG.md),
  [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/).
- Newest section: `## [Unreleased]`; dated entries: `## [X.Y.Z] - YYYY-MM-DD`, newest first.
- Groups: Added, Changed, Deprecated, Removed, Fixed, Security. Comparison links at bottom.
- Withdrawals retain entries with `[YANKED]` in the version heading.
- PRs change content inside Unreleased unless a maintainer applies `changelog:not-needed`.
- Automation extracts reviewed sections, never replaces the changelog with commit
  messages or reformats curated prose.

<!-- SPDX-FileCopyrightText: 2026 Anonce Contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Versioning and compatibility

Audience: maintainers, integrators, and client authors.

Use Semantic Versioning 2.0.0 and tags `vMAJOR.MINOR.PATCH`. The first release will
be `v0.1.0`; no tag exists yet. Development versions `0.y.z` remain unstable, but
changes still receive explicit compatibility review.

## Public API boundary

The compatibility contract includes CLI commands/flags and exit behavior; HTTP
paths/statuses and schemas; wire/token/envelope formats; keystore and backup files;
certificate profiles and trust rules; supported database migration ranges;
configuration keys/environment variables; and versioned form schemas/bulletins.
Documented client-visible asset hashes and receipt profiles are also public contracts.

Internal Go packages are not an invitation to import unstable implementation details.
If public Go modules are later introduced, breaking releases at v2 and above must
use the required `/vN` module path, including matching import paths. A monorepo tag
does not excuse Go module compatibility rules.

## Change classification

| Impact | Stable release behavior | Unstable release policy |
| --- | --- | --- |
| MAJOR | Incompatible public contract, removed flag/config, unsafe migration range, crypto/wire/parameter change without compatibility | Increase MINOR, document breaking impact and migration; use `!` or the standard breaking footer |
| MINOR | Backward-compatible feature or new opt-in capability | Increase MINOR |
| PATCH | Backward-compatible fix, clarification, hardening with no contract break | Increase PATCH |

A security fix is not automatically a PATCH. Rejecting previously accepted unsafe
parameters or changing trust anchors may require a breaking release and operator
action. Crypto parameters and wire formats are breaking unless an explicit reviewed
compatibility mechanism exists. Never retain an insecure path solely for compatibility.

## Commit and PR mapping

`feat` normally requests MINOR; `fix` and compatible `perf` normally request PATCH.
Any type with `!` or `BREAKING CHANGE:` requests breaking review. Documentation,
tests, CI, and maintenance types have no automatic release bump unless public
behavior changes. Labels are an explicit review decision, not an inferred substitute
for examining the diff.

Every PR has exactly one `semver:major`, `semver:minor`, or `semver:patch` label.
The `semver:major` label denotes breaking impact even during `0.y.z`, where the
actual version policy above applies. Non-release changes may carry `semver:patch`
with `changelog:not-needed` and a maintainer rationale.

## Changelog contract

[CHANGELOG.md](../CHANGELOG.md) is human-curated using Keep a Changelog 1.1.0.
Its newest section is `## [Unreleased]`; dated sections use
`## [X.Y.Z] - YYYY-MM-DD`, newest first. Allowed groups are Added, Changed,
Deprecated, Removed, Fixed, Security. Keep comparison references at the bottom.
A withdrawn release keeps its entry with `[YANKED]` in the version heading.

PRs must modify content inside Unreleased, not merely touch the file elsewhere,
unless `changelog:not-needed` is applied by a maintainer. Automation extracts a
reviewed release section; it must not turn commit messages into a replacement
changelog or reformat curated prose.

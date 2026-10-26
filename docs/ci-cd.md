<!-- SPDX-FileCopyrightText: 2026 Anonce Contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# CI/CD

Audience: contributors, repository administrators, and release maintainers.

## Available workflows

The repository supplies policy/documentation checks, a nightly full-history policy
run, and an mdBook Pages workflow. They use read-only permissions
by default, full checkout history, non-persistent checkout credentials, timeouts,
concurrency controls, pinned action commits, and a local runner-hardening script.

The hardening script establishes restrictive defaults and validates the checkout
context. It is not a claim of network isolation on a hosted runner. No proprietary
runner-monitoring service is required.

Documentation jobs run `make docs-setup` to verify the pinned mdBook release and
upstream asset notices before the offline build. `book.toml` and `SUMMARY.md`
define configuration and navigation; source and rendered link checks fail closed.
Installation and local preview are in [contributing](../CONTRIBUTING.md).

`make workflow-lint` runs pinned actionlint using Go; this validates workflow syntax
without introducing a Go module or runtime application into the documentation work.

PR policy validation covers the current files and full reachable history, PR text,
commit range, allowed title grammar, exactly one SemVer label, and an Unreleased
change or the maintainer-controlled exception. Dependency identity handling is
specified in [contributing](../CONTRIBUTING.md#dependency-updates).

The PR workflow must never combine privileged write credentials with execution of
untrusted PR files. Pages publication is limited to the trusted default branch.
Workflow and policy changes need owner review.

## Runtime pipeline contract

The following workflows are designed, not implemented.
Their implementation is tracked in the [roadmap](roadmap.md).

| Workflow | Intended checks |
| --- | --- |
| Runtime checks | Run the build, database, security, browser, WASM, container, and simulation targets in [testing](testing.md#required-runtime-command-contract) |
| Nightly extension | Longer fuzzing, vulnerability refresh, Scorecard, complete repository/history scan |
| PR reporting | Coverage artifact and restricted comment publication without executing PR content |
| Release | Enforce the [release checklist](releasing.md#maintainer-release-checklist) in trusted publication jobs |
| Triage | Component/size labels and conservative stale handling; never auto-close security reports |

Proposed short fuzzing is 15 seconds per available parser on PRs; nightly runs may
use five minutes per target under explicit CPU/memory limits. Validate those budgets
against actual runtime rather than adding idle placeholder jobs.

## Tool and licensing policy

Tool admission follows [dependencies](dependencies.md). Required checks must use
openly licensed tools, have real local Make targets, and not depend on proprietary
hosted services. Node-based browser/diagram tools remain development-only. CodeQL
cannot be a required branch-protection check.

Cache only disposable module/download/build data with keys bound to lockfile hashes
and toolchain versions. Untrusted PR caches must not supply release inputs. Do not
cache secrets, keystores, tokens, enrollment data, or signing state.

## Branch protection guidance

`make labels` creates missing labels from `.github/labels.toml` through the GitHub CLI.
It requires maintainer permissions and preserves existing label definitions. Fork
maintainers can pass their repository to `scripts/sync_labels.py --repo owner/name`.

Repository administrators must configure a default-branch ruleset with:

- PR-based changes, conversation resolution, and required owner review.
- Required `policy` and `docs` jobs from `checks.yml` once they have a successful run.
- Required runtime checks only after they genuinely exist and run on every PR.
- No force pushes or deletion, no ordinary bypass, and review dismissal on new changes.
- Linear history and maintainer squash merges under reviewed human identities.
- Protected release tags and tightly scoped publication environment access.

A sole maintainer cannot independently approve their own PR. Document that limitation
instead of claiming independent review exists. Hosted ruleset availability depends on
repository visibility and account features; the repository files alone do not enforce it.

## Artifact and release integrity

Upload only coverage, public screenshots, SBOMs, public hashes, and sanitized test
reports. Strip and inspect image metadata. Use separate OIDC-enabled signing jobs
with narrow permissions. Never expose publication credentials to PR builds or
execute downloaded artifacts in a privileged reporting job. Exact release checks
and user verification belong in [releasing](releasing.md).

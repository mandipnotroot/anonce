<!-- SPDX-FileCopyrightText: 2026 Anonce Contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# CI/CD

Audience: contributors, repository administrators, and release maintainers.

## Available workflows

The repository supplies policy/documentation and Go infrastructure checks, a
nightly full-history policy run, and an mdBook Pages workflow. They use read-only permissions
by default, full checkout history, non-persistent checkout credentials, timeouts,
concurrency controls, pinned action commits, and a local runner-hardening script.

The hardening script establishes restrictive defaults and validates the checkout
context. It is not a claim of network isolation on a hosted runner. No proprietary
runner-monitoring service is required.

Documentation jobs run `make docs-setup` to verify the pinned mdBook release and
upstream asset notices before the offline build. `book.toml` and `SUMMARY.md`
define configuration and navigation; source and rendered link checks fail closed.
Installation and local preview are in [contributing](../CONTRIBUTING.md).

Weekly dependency update configuration covers GitHub Actions, Python check tools,
and Go modules. It does not update version strings embedded in Make targets or the
mdBook artifact manifest. Review those pins and their licenses/advisories manually;
do not infer complete dependency coverage from the update configuration.

`make workflow-lint` runs pinned actionlint with the pinned Go toolchain.
The `runtime` job builds all three demonstration commands and runs race/coverage,
lint, 15-second bounded configuration fuzzing, and vulnerability/secret checks.
It does not exercise a protocol, database, browser, container, or WASM client.

PR policy validation covers the current files and full reachable history, PR text,
commit range, allowed title grammar, exactly one SemVer label, and an Unreleased
change or the maintainer-controlled exception. Dependency identity handling is
specified in [contributing](../CONTRIBUTING.md#dependency-updates).

The PR workflow must never combine privileged write credentials with execution of
untrusted PR files. Pages publication is limited to the trusted default branch.
Workflow and policy changes need owner review.

## Runtime pipeline contract

The following extensions are designed, not implemented.
Their implementation is tracked in the [roadmap](roadmap.md).

| Workflow | Intended checks |
| --- | --- |
| Runtime checks | Extend the infrastructure job with database, browser, WASM, container, and simulation targets in [testing](testing.md#required-runtime-command-contract) |
| Nightly extension | Longer fuzzing and Scorecard beyond the existing vulnerability and complete repository/history checks |
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
- Required `policy`, `docs`, and `runtime` jobs from `checks.yml` after each has a
  successful hosted run. Extend required checks only when they genuinely exist.
- No force pushes or deletion, no ordinary bypass, and review dismissal on new changes.
- Linear history and maintainer squash merges under reviewed human identities.
- Protected release tags and tightly scoped publication environment access.

A sole maintainer cannot independently approve their own PR. Document that limitation
instead of claiming independent review exists. Hosted ruleset availability depends on
repository visibility and account features; the repository files alone do not enforce it.

## Before publication

The local repository configuration does not establish the remote repository's
settings. Before a first push, the maintainer must:

- Confirm the destination and compare histories. Publish a fresh local history to
  a new empty repository, not over an existing shared branch. Do not force-push to
  replace shared history. Review hard-coded repository, source, and Pages URLs if
  the destination changes.
- Confirm owner permissions and the `CODEOWNERS` account, enable private vulnerability
  reporting, and establish a usable confidential conduct-reporting channel.
- Configure labels, branch protection, and the GitHub Pages source/environment.
  Restrict Pages publication to the protected default branch.
- Run local checks, then verify the actual hosted check results and required job
  names before enabling required-check rules. Request owner review and apply the
  reviewed SemVer label to each PR.

These are operator actions, not checks that a local build can mark as passed.

## Artifact and release integrity

Upload only coverage, public screenshots, SBOMs, public hashes, and sanitized test
reports. Strip and inspect image metadata. Use separate OIDC-enabled signing jobs
with narrow permissions. Never expose publication credentials to PR builds or
execute downloaded artifacts in a privileged reporting job. Exact release checks
and user verification belong in [releasing](releasing.md).

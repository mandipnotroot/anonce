<!-- SPDX-FileCopyrightText: 2026 Anonce Contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# CI/CD

Audience: contributors, repository administrators, and release maintainers.

## Available workflows

| Workflow/check | Coverage |
| --- | --- |
| Policy | Current files, full reachable history, PR text/commit range/title grammar, exactly one SemVer label, Unreleased change or maintainer exception |
| Runtime | HTTP commands, offline key CLI, public-only WASM verifier, separate local member-session bridge/worker; race/coverage, lint, 15-second parser/admission fuzzing, vulnerability/secret scans, shell delivery, and native/Node request and member-backup compatibility. See [testing](testing.md#current-executable-checks) |
| Documentation / Pages | Pinned mdBook and upstream notices via `make docs-setup`, offline build, source/rendered links; `book.toml` and `SUMMARY.md` configure the site |
| Nightly | Full-history policy, complete local runtime checks with pinned Node, documentation build and external links |
| Weekly dependency updates | GitHub Actions, Python check tools, Go modules |
| `make workflow-lint` | Pinned actionlint and Go toolchain |

The checks workflow runs when a PR opens, receives new commits, reopens, or becomes
ready for review, on pushes to `main`, and on manual dispatch. Title, description,
and label edits do not start or cancel CI runs. PR metadata is validated when PR
checks run, not on each metadata edit. Maintainers must review the final title,
description, and SemVer label before merging; an earlier policy result does not
validate subsequent metadata changes.

- Workflows use read-only permissions by default, full history, non-persistent
  checkout credentials, timeouts, concurrency controls, pinned action commits,
  and local runner hardening.
- Hardening sets restrictive defaults and validates checkout context, not hosted-runner
  network isolation. No proprietary monitoring service is required.
- Runtime does not test protocols, databases, browsers, containers, or WASM private-key custody.
- The opt-in [member-worker Chromium target](testing.md#member-worker-browser-checks)
  is locally runnable but not installed or executed by hosted workflows.
- Manually review Make-target pins and the mdBook manifest, including licenses/advisories;
  weekly updates do not cover them. See [dependency identity rules](../CONTRIBUTING.md#dependency-updates).
- Never combine privileged write credentials with untrusted PR execution. Publish
  Pages only from the trusted default branch. Workflow/policy edits need owner review.
- See [contributing](../CONTRIBUTING.md) for site setup/preview. Link checks fail closed.

## Runtime pipeline contract

Planned, not implemented. Track work in the [roadmap](roadmap.md).

| Workflow | Intended checks |
| --- | --- |
| Runtime checks | Extend the infrastructure job with database, browser, container, and simulation targets in [testing](testing.md#required-runtime-command-contract); extend WASM evidence to actual browser custody and worker lifecycle |
| Nightly extension | Longer fuzzing and Scorecard beyond the existing vulnerability and complete repository/history checks |
| PR reporting | Coverage artifact and restricted comment publication without executing PR content |
| Release | Enforce the [release checklist](releasing.md#maintainer-release-checklist) in trusted publication jobs |
| Triage | Component/size labels and conservative stale handling; never auto-close security reports |

Proposed fuzz budgets: 15 seconds/parser on PRs; nightly may use five minutes/target
with explicit CPU/memory limits. Validate actual runtime; no idle placeholder jobs.

The browser job must cover the [account/vault acceptance cases](testing.md#browser-account-and-vault-acceptance),
not require users to install the CLI. Real browser/provider evidence and recovery
results must remain distinct from virtual-authenticator and Node-only checks.

## Tool and licensing policy

- Follow [dependency admission](dependencies.md). Required checks need openly licensed,
  locally runnable Make targets, without proprietary hosted prerequisites.
- Node browser/diagram tools are development-only. CodeQL cannot be a required
  branch-protection check.
- Cache only disposable module/download/build data keyed by lockfile hashes and
  toolchain versions. Never use untrusted PR caches as release inputs or cache
  secrets, keystores, tokens, enrollment data, or signing state.

## Branch protection guidance

`make labels` uses GitHub CLI and maintainer permissions to create missing labels
from `.github/labels.toml`, preserving existing definitions. Forks can use
`scripts/sync_labels.py --repo owner/name`.

Repository administrators must configure a default-branch ruleset with:

- PR-based changes, conversation resolution, and required owner review.
- Required `policy`, `docs`, and `runtime` jobs from `checks.yml` after each has a
  successful hosted run. Extend required checks only when they genuinely exist.
- No force pushes or deletion, no ordinary bypass, and review dismissal on new changes.
- Linear history and maintainer squash merges under reviewed human identities.
- Protected release tags and tightly scoped publication environment access.

Disclose that a sole maintainer cannot independently approve their PR. Hosted
rulesets depend on visibility/account features; repository files do not enforce them.

## Before publication

Local configuration does not establish remote settings. Before the first push:

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

These require operator verification, not a local passing build.

## Artifact and release integrity

- Upload only coverage, public screenshots, SBOMs, public hashes, and sanitized reports.
  Strip and inspect image metadata.
- Separate OIDC signing jobs with narrow permissions. No publication credentials
  in PR builds or downloaded-artifact execution in privileged reporting jobs.
- See [releasing](releasing.md) for release checks and user verification.

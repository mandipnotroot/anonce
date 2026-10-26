<!-- SPDX-FileCopyrightText: 2026 Anonce Contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Contributor instructions

Audience: contributors and automated tooling.

## Repository status and layout

anonce designs anonymous submissions from verified members with administrator-set
per-member response limits for each round.
This checkout contains documentation and repository checks, not a working product.
Keep implemented behavior distinct from intended behavior.

- `docs/`: architecture, security, operations, and contributor reference.
- `docs/dependencies.md`: dependency choices, licensing, and review requirements.
- `docs/roadmap.md`: current priorities and unresolved implementation questions.
- `scripts/`: policy, commit, and documentation checks.
- `.githooks/`: local enforcement, installed through `make setup`.
- `.github/`: collaboration templates and supported CI workflows.
- Planned runtime layout: `cmd/`, `internal/`, `migrations/`, `web/`.

## Authorship and wording

Authorship belongs to people. Credit human contributors only. This rule applies to
the entire project: source, comments, identifiers, fixtures, filenames, documentation,
research, configuration, workflow text, package data, SPDX notices, image and PDF
metadata, binaries, build strings, SBOMs, release assets, collaboration text, and Git
authors, committers, messages, trailers, branches, tags, and annotations.

Do not attribute work to automated tooling, describe its involvement, or include
its identifying names, models, vendors, signatures, or bot addresses. The person who
commits must understand, review, and be able to explain the entire change. Human
co-authors may receive ordinary credit. Recognized dependency-update identities are
permitted only in PR identity fields under the [dependency-update rules](CONTRIBUTING.md#dependency-updates).
Original third-party vendor text stays unchanged and receives a licensing review.
Conventional reproducibility headers for approved ordinary build programs are allowed.
The scanner vocabulary lives only in `scripts/policy.toml`.

Describe project work as features and components, using **Now / Next / Later**.
Do not introduce numbered delivery periods or equivalent sequencing terminology.
Do not use em dashes. Rewrite the sentence naturally instead of replacing a mark.

## Commands

```sh
make setup            # install hooks in this clone
make check            # all supported local checks
make policy-test      # scanner and commit grammar regression tests
make attribution      # index, historical files, identities, messages, refs, tags
make commitlint       # all reachable commit subjects
make reuse            # REUSE 3.3 validation
make docs-links       # local files, anchors, and reference links
make docs-lint        # Markdown structure and first-party formatting
make docs-setup       # install checksum-pinned mdBook and asset notices
make docs-build       # build and validate the mdBook site
make docs-external    # check externally hosted references
make workflow-lint    # pinned actionlint; requires Go
```

The Go/container work is not present yet. Its required command contract is recorded
in [testing](docs/testing.md): setup, build, race tests, lint, vulnerability checks,
WASM build, stack startup, and browser tests must have real Make targets when added.
Do not add successful no-op checks or claim unavailable commands passed.

## Engineering boundaries

- Keep command entry points thin; domain packages must not import transport packages.
- Keep member/reviewer cryptography in shared device-side Go packages.
- Never implement a primitive; choose reviewed libraries and document profiles in `docs/cryptography.md` before implementation.
- Use `crypto/rand` for security randomness and library verification routines.
- Use constant-time comparisons where secret comparison is required.
- Wrap errors with operation context, not secrets; propagate cancellation.
- Never log private keys, tokens, credentials, answers, or private reply contents.
- Minimize sensitive copies, clear owned mutable buffers, and document runtime limits.
- Fail closed. Do not add a fallback algorithm after a validation failure.
- Identity and submission storage must have separate services, roles, and credentials.
- Use immutable, versioned SQL migrations; runtime roles must not own schema objects.
- Test grants and isolation against real PostgreSQL, not mocks alone.
- Never collect submission-path IP addresses in logs, telemetry, or proxy records.

## Front end

- Go serves embedded templates and assets; no product Node build or CDN.
- Vendor assets with their original licenses and reviewed hashes.
- No external fonts, analytics, third-party requests, or inline executable scripts.
- Escape templates by default; do not cast untrusted values to trusted HTML.
- Preserve keyboard access, visible focus, semantic structure, labels, and contrast.
- Gate the style guide behind explicit development configuration.
- Keep mock data obvious; disabled security features must not look operational.

## Git and review

Use short feature names such as `docs/key-storage` and never rewrite shared history.
Use Conventional Commits: `<type>[scope][!]: <description>`, lowercase imperative
description, no trailing period. A breaking change needs `!` or the standard footer.

Types: feat, fix, docs, style, refactor, perf, test, build, ci, chore, revert.
Scopes: repo, ca, issuer, server, reviewer, client, wasm, keystore, log, web, admin,
db, docs, ci, deps, release. `scripts/commits.toml` is the machine-readable authority.

Examples: `docs(ca): describe revocation checks`; `fix(web): preserve focus on errors`.
Keep commits atomic. PR titles must also pass commit lint. Every PR needs a SemVer
impact label and an Unreleased entry unless the documented exception label applies.
Use the [PR template](https://github.com/mandipnotroot/anonce/blob/main/.github/pull_request_template.md)
and request owner review.

## Licensing, tests, and documentation

Use AGPL-3.0-only for original work. Never relicense upstream files. Record binary,
JSON, checksum, and font notices in `REUSE.toml` when headers cannot be carried.
Use `Anonce Contributors` for original project notices. Preserve upstream holders.
SPDX header examples:

```text
// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

# SPDX-FileCopyrightText: 2026 Anonce Contributors
# SPDX-License-Identifier: AGPL-3.0-only

<!-- SPDX-FileCopyrightText: 2026 Anonce Contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->
```

Add table-driven unit tests, error cases, race coverage, and bounded parser fuzzing
with each implementation. Keep protocol attack cases mapped to named tests and
report unimplemented cases honestly. Never use production identities or secrets.

Update the canonical document, linking to it rather than repeating explanations:
API changes -> `docs/api.md` and OpenAPI; security changes -> threat model and cryptography;
storage changes -> database and migration docs; UI changes -> design and screenshots;
operator changes -> deployment; public compatibility -> versioning and changelog.
Every `docs/` file states its audience. Cite primary sources where they support a
requirement, with access dates for external observations. Scope wire/parameter changes as breaking
unless a documented compatibility mechanism exists.

## Never do

- Add an unjustified dependency or a proprietary required check.
- Add real-looking credentials, production data, or a private key fixture.
- Weaken security checks to make a test pass or suppress an unexplained failure.
- Edit generated outputs by hand or use screenshots as evidence of unbuilt behavior.
- Publish, sign, or tag a release without the release checklist and maintainer approval.

## Definition of done

The change is reviewed, scoped, licensed, tested, documented in its canonical home,
and reflected in Unreleased when user-visible. All applicable checks pass without
bypass. Unavailable checks and residual security risks are explicitly reported.

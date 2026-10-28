<!-- SPDX-FileCopyrightText: 2026 Anonce Contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Contributing

Audience: prospective and returning contributors.

Follow [AGENTS.md](AGENTS.md) for authorship, wording, engineering, licensing, and
commit rules. Every committer must review and understand the entire change.

## Working on a change

- Discuss substantial changes in an issue or PR. Choose a focused component from
  the [roadmap](docs/roadmap.md).
- Fork and clone over SSH, run `make setup`, and use a short feature branch.
- Use dummy data, focused diffs, and atomic commits.
- Keep requirements in their [reference document](docs/README.md).
- Run `make check` before review.

Original contributions use AGPL-3.0-only. Submitting confirms your right to license
the contribution on those terms. No copyright transfer or separate contributor
agreement is required. Preserve imported material's upstream notices.

## Go guidelines

Use the [Modern Go Guidelines](https://github.com/JetBrains/go-modern-guidelines)
for writing and reviewing Go code (accessed 2026-10-26). Prefer modern language
features and standard-library APIs supported by the Go version in `go.mod` and
the toolchain pinned in `Makefile`. Project security requirements and engineering
boundaries in [AGENTS.md](AGENTS.md#engineering-boundaries) take precedence.

## Local checks

On Linux with Python 3.13, install the pinned documentation tools and run the
repository and site checks:

```sh
python3 -m venv .cache/docs-env
.cache/docs-env/bin/python -m pip install --require-hashes -r requirements-docs.txt
. .cache/docs-env/bin/activate
make docs-setup
make check docs-build
```

Add new files to Git for index, link, and site validation. Build from tracked
documents; do not maintain separate site copies.

`make check` covers build, race/coverage, lint, bounded parser fuzzing, security,
and rendered-shell checks. Go 1.27.3 and tools are pinned in `Makefile`; downloads
use the Go module proxy/checksum service. See [testing](docs/testing.md) for evidence
limits and [deployment](docs/deployment.md#local-development) for process flags.
`make check` also requires Node.js 22.23.3 for public-request WASM compatibility
checks and separate local member-session WASM and worker checks. No npm install or
Node product build is used; `make wasm` and `make member-wasm` build with Go alone. Container
setup is opt-in through the [local Compose stack](docs/deployment.md#container-stack),
with separate databases and `make container-test`. Separate migration histories have
an opt-in `make db-migration-test`; HTTP persistence remains unavailable. The separate opt-in `make member-browser-test`
uses a pinned external Chromium executable supplied through `MEMBER_BROWSER`;
see [browser check setup and limits](docs/testing.md#member-worker-browser-checks).
It is not included in `make check` or hosted CI.

## Documentation site

- **Setup:** `make docs-setup` installs official mdBook 0.5.4 archives, checks
  SHA-256 digests in `scripts/mdbook.toml`, and verifies published theme notices.
  Supports Linux/macOS on x86_64/aarch64, without Rust or a product Node build.
  Downloads stay in `.cache/mdbook/`.
- **Build:** `make docs-build` uses `book.toml`, `SUMMARY.md`, tracked Markdown,
  assets, licenses, and theme overrides. Builds are offline after setup.
  `MDBOOK` may select another command of the same pinned version.
- **Isolation:** assembly uses a disposable `.cache/docs-build/` directory.
  Environment configuration overrides are ignored to keep build paths there.
  Success replaces `site/`; failure preserves the previous site.
- **Validation:** missing chapters, warnings, broken rendered links/anchors,
  inline executable scripts, and remote page resources fail the build.
- **Assets:** local navigation, search, light/dark themes, and device fonts.
  Theme scripts are externalized without code changes; upstream licenses remain
  in `assets/upstream-licenses/`. No external fonts, runnable playground, or analytics.
- **Manual review:** static checks do not replace browser or assistive-technology tests.

Preview at `http://127.0.0.1:8000/` after running:

```sh
python3 -m http.server --bind 127.0.0.1 --directory site 8000
```

## Documentation dependencies

When updating documentation dependencies, edit `requirements-docs.in` and rebuild
the lock rather than hand-editing it:

```sh
pipx run --spec pip-tools==7.6.2 pip-compile \
  --no-header --no-annotate --generate-hashes --strip-extras \
  --index-url https://pypi.org/simple \
  --output-file requirements-docs.txt requirements-docs.in
```

## Pull requests

- Use the [PR template](https://github.com/mandipnotroot/anonce/blob/main/.github/pull_request_template.md)
  and link the issue and reference document.
- Follow [versioning](docs/versioning.md) for compatibility labels and Unreleased entries.
- Use the title grammar in `scripts/commits.toml`.
- Exclude secrets and personal data.
- Pass checks and obtain maintainer review.

### Squash-merge commit titles

Maintainers append the PR number as ` (#N)` to the final squash-merge commit
title, for example, `feat(client): add member sessions (#2)`. Keep individual
development commit subjects and PR titles free of this suffix; add it only when
merging.

The final title must still follow [Conventional Commits 1.0.0](https://www.conventionalcommits.org/en/v1.0.0/)
and the types, scopes, and subject limit in `scripts/commits.toml`. The suffix is
part of the description and counts toward the subject limit. Preserve any
breaking-change notation when preparing the final title.

## Dependency updates

Review purpose, exact versions, hashes, licenses, and security advisories under
[dependencies](docs/dependencies.md). Do not auto-merge updates.

- Only the exact identity in `scripts/policy.toml` may receive an author/committer
  exception, limited to its own PR commits after workflow account verification.
- No exceptions for files, messages, trailers, titles, descriptions, protected base
  history, nightly scans, or release scans.
- Review and squash-merge under human author/committer identities. If hosted merging
  cannot produce compliant metadata, prepare the reviewed squash locally through
  the protected process. Never rewrite shared history to fix an avoidable violation.

## Review expectations

Review correctness, trust boundaries, accessibility, failures, tests, licensing,
and documentation. Passing checks do not prove security. Ask about unclear
cryptographic intent. Maintainers may request smaller changes for reliable review.

New clients must reuse device-side Go cryptography and preserve origin separation.
The [product direction](AGENTS.md#product-direction) is browser-only with automatic
key management, not CLI-based onboarding. Review browser work against the
[account and review workflow](docs/ui-design.md#account-and-review-workflow).
New transports, storage backends, and integrations must retain ciphertext-only
submission, bounded inputs, atomic spending, and the documented metadata policy.
Update the threat model, API, and compatibility guidance when those boundaries change.

Follow the [Code of Conduct](CODE_OF_CONDUCT.md). Use
[private disclosure](SECURITY.md) for vulnerabilities and [support](SUPPORT.md) for
ordinary questions.

<!-- SPDX-FileCopyrightText: 2026 Anonce Contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Contributing

Audience: prospective and returning contributors.

Follow [AGENTS.md](AGENTS.md) for authorship, wording, engineering, licensing, and
commit rules. Every committer must review and understand the entire change.

## Working on a change

Discuss substantial changes in an issue or pull request. Keep the requirements in
the relevant [reference document](docs/README.md).
Use the [roadmap](docs/roadmap.md) to choose a focused component.

Fork and clone over SSH, run `make setup`, and work on a short feature branch. Use
dummy data, focused diffs, and atomic commits. Run `make check` before review.

For the complete documentation checks on Linux with Python 3.13:

```sh
python3 -m venv .cache/docs-env
.cache/docs-env/bin/python -m pip install --require-hashes -r requirements-docs.txt
. .cache/docs-env/bin/activate
make docs-setup
make check docs-build
```

Add new files to Git before index, link, and site validation includes them. The
site build uses tracked documents directly; do not maintain separate site copies.

Go infrastructure uses the pinned Go 1.27.3 toolchain. `make check` includes build,
race/coverage, lint, bounded parser fuzzing, and security checks. The tools are
pinned in `Makefile` and downloaded through the Go module proxy/checksum service.
Local process flags are in [deployment](docs/deployment.md#local-development),
with evidence limits in [testing](docs/testing.md). No container or database setup
is available yet.

`make docs-setup` installs mdBook 0.5.4 from the official release using the SHA-256
digests in `scripts/mdbook.toml`. It also verifies the notices for published theme
assets. The installer supports Linux and macOS on x86_64 and aarch64; no Rust
toolchain or product Node build is needed. Downloads stay under `.cache/mdbook/`.

`make docs-build` uses `book.toml` and the chapter navigation in `SUMMARY.md`.
Canonical tracked Markdown, assets, licenses, and the small theme overrides are
assembled in a disposable directory under `.cache/docs-build/`. Missing chapters,
builder warnings, broken rendered links/anchors, inline executable scripts, and
remote page resources fail validation. Configuration environment overrides are
ignored to keep all build paths within that disposable tree. A successful build
replaces `site/`; a failed build leaves the previous site untouched. Builds are
offline after setup. `MDBOOK` can select a different command, but its version must
still match the pin.

Preview with `python3 -m http.server --bind 127.0.0.1 --directory site 8000`, then
open `http://127.0.0.1:8000/`. Navigation, search, and light/dark themes use local
assets and device fonts. The build externalizes theme scripts without changing
their code and retains upstream license texts under `assets/upstream-licenses/`.
No external font service, executable playground, or analytics is configured.
Static validation is not a substitute for browser and assistive-technology review.

When updating documentation dependencies, edit `requirements-docs.in` and rebuild
the lock rather than hand-editing it:

```sh
pipx run --spec pip-tools==7.6.2 pip-compile \
  --no-header --no-annotate --generate-hashes --strip-extras \
  --index-url https://pypi.org/simple \
  --output-file requirements-docs.txt requirements-docs.in
```

Original contributions use AGPL-3.0-only. By submitting a contribution, you confirm
you have the right to license it on those terms. No copyright transfer or separate
contributor agreement is required. Preserve upstream notices for imported material.

## Pull requests

Use the [PR template](https://github.com/mandipnotroot/anonce/blob/main/.github/pull_request_template.md), linking the relevant issue
and reference document. Follow [versioning](docs/versioning.md) for compatibility labels
and Unreleased entries. PR titles follow the commit grammar in `scripts/commits.toml`.
Do not include secrets or personal data.

Changes require passing checks and maintainer review.

## Dependency updates

Review purpose, exact versions, hashes, licenses, and security advisories under
[dependencies](docs/dependencies.md). Do not auto-merge updates.

Only the exact dependency-update identity configured in `scripts/policy.toml` may
receive an author/committer exception in its own PR commits, after the workflow
verifies the PR account. Files, messages, trailers, titles, and descriptions have
no exception. Protected base history always receives the ordinary policy scan.

Review and squash-merge updates under human author and committer identities. If
hosted merging cannot produce compliant metadata, prepare the reviewed squash
locally through the protected process. Never rewrite shared history to repair an
avoidable identity violation. Nightly and release scans have no exception.

## Review expectations

Review correctness, trust boundaries, accessibility, failure behavior, tests,
licensing, and documentation. A green pipeline is not a security proof. Ask for
clarification instead of guessing at cryptographic intent. Maintainers may request
smaller changes when review would otherwise become unreliable.

New clients must reuse device-side Go cryptography and preserve origin separation.
New transports, storage backends, and integrations must retain ciphertext-only
submission, bounded inputs, atomic spending, and the documented metadata policy.
Update the threat model, API, and compatibility guidance when those boundaries change.

Follow the [Code of Conduct](CODE_OF_CONDUCT.md). Use
[private disclosure](SECURITY.md) for vulnerabilities and [support](SUPPORT.md) for
ordinary questions.

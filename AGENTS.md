<!-- SPDX-FileCopyrightText: 2026 Anonce Contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Contributor instructions

Audience: contributors and automated tooling.

## Repository status and layout

anonce is designed for anonymous submissions from verified members with
administrator-set per-member/round limits. Docs, checks, local demo HTTP
infrastructure, a read-only shell, shared device-backup encryption, local
member/reviewer-key generation/import/export, and an offline encrypted-file CLI exist.
Distinguish implemented from planned behavior.

- `docs/`: architecture, security, operations, and contributor reference.
- `docs/dependencies.md`: dependency choices, licensing, and review requirements.
- `docs/roadmap.md`: current priorities and unresolved implementation questions.
- `scripts/`: policy, commit, and documentation checks.
- `.githooks/`: local enforcement, installed through `make setup`.
- `.github/`: collaboration templates and supported CI workflows.
- `cmd/`, `internal/`: local CA, issuer, and submission HTTP infrastructure.
- `internal/client/keystore`: bounded, in-memory device-backup encryption, used by
  typed key wrappers; no browser or service integration.
- `internal/client/memberkey`: local Ed25519 member keys and validated encrypted
  backups; offline CLI integration, no browser or enrollment integration.
- `internal/client/reviewerkey`: local X25519 reviewer keys and validated encrypted
  backups; offline CLI integration, no browser, round-binding, or decryption integration.
- `internal/clientcli`, `cmd/client`: offline backup generation and public-only
  inspection and password rewrapping with optional expected-public-key matching;
  bounded stdin passwords and no-replace
  encrypted files, plus identity-free member CSR stdout or no-replace file output
  with optional expected-public-key matching before signing
  and password-free request verification with optional expected-public-key matching;
  no old-backup revocation, key rotation, or enrollment.
- `internal/client/membercsr`: local Ed25519 certificate requests and bounded
  profile validation; no identity claims, certificate issuance, or transport.
- `cmd/wasm`, `internal/clientwasm`: public-only member request verification using
  the shared parser, with opt-in expected-public-key matching; local WASM artifacts
  and Node compatibility checks, no page integration, device-key access, or enrollment.
- `web/`: embedded read-only demonstration templates and first-party CSS.
- Planned runtime layout also includes `migrations/`.

## Authorship and wording

Authorship belongs to people. Credit human contributors only. This rule applies to
the entire project: source, comments, identifiers, fixtures, filenames, documentation,
research, configuration, workflow text, package data, SPDX notices, image and PDF
metadata, binaries, build strings, SBOMs, release assets, collaboration text, and Git
authors, committers, messages, trailers, branches, tags, and annotations.

Do not attribute work to automated tooling, describe its involvement, or include
its identifying names, models, vendors, signatures, or bot addresses. The person who
commits must understand, review, and be able to explain the entire change. Human
co-authors may receive ordinary credit.

Recognized dependency-update identities are
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
make build            # build the local demonstration commands
make test             # race tests and coverage report
make lint             # Go analysis, formatting, and module checks
make fuzz             # bounded configuration, shell-route, backup, key, and CLI parser fuzzing
make vuln             # Go vulnerability, static security, and secret checks
make web-lint         # rendered inert markup, local CSS, SRI, and HTTP delivery checks
make wasm             # public-only Go WASM verifier, matching loader, hashes, size gate
make wasm-test        # native/WASM public-request compatibility and bridge checks
```

See [testing](docs/testing.md) for required database, container, browser, and
protocol targets, none available yet. WASM evidence covers request verification
only. Add real Make targets with implementation.
No successful no-op checks or claims that unavailable commands passed.

## Engineering boundaries

- Follow the [Modern Go Guidelines](https://github.com/JetBrains/go-modern-guidelines)
  for Go code, with the [project-specific rules](CONTRIBUTING.md#go-guidelines).
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

- Use short feature branches, such as `docs/key-storage`. Never rewrite shared history.
- Consult the official [Conventional Commits 1.0.0 specification](https://www.conventionalcommits.org/en/v1.0.0/)
  and follow it strictly for every commit and PR title.
- Repository-specific types, scopes, and subject limits are defined in `scripts/commits.toml`.
- Keep commits atomic; commit lint and hooks must pass without bypass.
- Follow the official [SemVer 2.0.0](https://semver.org/spec/v2.0.0.html) and
  [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/) guidance, with
  project-specific requirements in [versioning](docs/versioning.md).
- Every PR needs a [SemVer impact label](docs/versioning.md#commit-and-pr-mapping)
  and Unreleased entry unless the documented
  exception label applies.
- Use the [PR template](https://github.com/mandipnotroot/anonce/blob/main/.github/pull_request_template.md)
  and request owner review.

## Licensing, tests, and documentation

Follow the official [REUSE 3.3 specification](https://reuse.software/spec-3.3/).
Use AGPL-3.0-only for original work. Never relicense upstream files. Record binary,
JSON, checksum, and font notices in `REUSE.toml` when headers cannot be carried.
Use `Anonce Contributors` for original project notices. Preserve upstream holders.

Add table-driven unit tests, error cases, race coverage, and bounded parser fuzzing
with each implementation. Keep protocol attack cases mapped to named tests and
report unimplemented cases honestly. Never use production identities or secrets.

Write professional documentation in plain, easy-to-understand language. Keep
paragraphs short and focused. Avoid overexplaining, filler, unnecessary repetition,
and jargon that does not help the intended audience. Be concise without omitting
required information, essential context, prerequisites, limitations, or safety
guidance.

For external conventions and standards, consult the official source for the
version adopted by the project instead of repeating its rules. Keep project-specific
requirements explicit. Do not silently use a newer version; if none is selected,
record that limitation and resolve it before implementation.

Update canonical references and link instead of repeating explanations:

| Change | Update |
| --- | --- |
| API | `docs/api.md` and OpenAPI |
| Security | Threat model and cryptography |
| Storage | Database and migration docs |
| UI | Design and screenshots |
| Operations | Deployment |
| Public compatibility | Versioning and changelog |

Every `docs/` file states its audience. Cite primary sources supporting requirements;
date external observations. Wire/parameter changes are breaking unless a documented
compatibility mechanism exists.

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

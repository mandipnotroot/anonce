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
  typed key wrappers; profile 2 uses Argon2id and ChaCha20-Poly1305;
  no browser or service integration.
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
  inspection and request verification support owner-only no-replace public-key files;
  expected-key checks also accept independently trusted public-key export files;
  no old-backup revocation, key rotation, or enrollment.
- `internal/client/membercsr`: local Ed25519 certificate requests and bounded
  profile validation; no identity claims, certificate issuance, or transport.
- `internal/client/membersession`: in-memory member setup, required expected-key
  restoration, fixed CSR requests, unlocked encrypted-backup export, and explicit
  lock/cancellation, with opt-in confirmed setup/export passwords;
  public-only results and encrypted backups, no account binding
  or persistence.
- `cmd/wasm`, `internal/clientwasm`: public-only member request verification using
  the shared parser, with opt-in expected-public-key matching; local WASM artifacts
  and Node compatibility checks, no page integration, device-key access, or enrollment.
- `cmd/memberwasm`, `internal/memberwasm`: separate development-only WASM member
  setup/restoration, fixed requests, encrypted-backup export, and lock/shutdown
  using shared sessions, including two-input confirmed setup/export;
  bounded byte inputs, public/encrypted outputs, native/Node backup checks;
  no page integration, account binding, storage, passkeys, or enrollment.
- `internal/memberworker`: development-only dedicated-worker owner for that bridge,
  bounded/correlated transferred messages, single active owner per module realm,
  fixed startup/operation/lifetime limits with dual-clock deadline checks, terminal
  lock/disposal with public closure observation and optional host-signal cancellation,
  secret-free same-partition lock notifications, and local pagehide/hidden-page
  termination, plus opt-in bounded UTF-8 text passphrases over confirmed setup/export
  and expected-key restoration with synchronous encoding-buffer cleanup;
  native/Node checks and an isolated synthetic browser-test harness with a confirmed
  local setup/unlock form, expected-key restoration, and encrypted/public
  page-memory output; no product HTTP
  delivery, supported-browser matrix, or account logout integration.
- `web/`: embedded read-only demonstration templates and first-party CSS.
- `Dockerfile`, `compose.yaml`, `deploy/postgres/`, `scripts/containers.py`: local
  non-root HTTP containers and separate PostgreSQL instances/volumes/credentials;
  empty-volume role/schema bootstrap, loopback host publication, liveness probes,
  secret preparation, and opt-in real-container checks; no application database
  integration, encrypted database restoration, image scan, or product readiness.
- `migrations/`, `internal/dbmigrate`, `cmd/migrate`: separate embedded Goose SQL
  histories and an operator-only pgx runner for local databases, with owner-created
  boundary markers, explicit migration targets, and opt-in real-PostgreSQL checks;
  identity version 2 adds internal account/session persistence and version 3 adds
  an encrypted member-backup slot; version 4 adds independent non-secret session
  selectors. No credentials, protocol tables or HTTP persistence.
- `internal/identity/accounts`: identity runtime-role account/session store, digest-only
  random tokens, absolute expiry, individual/all-session revocation, transactional
  disable, token rotation after caller-verified reauthentication without extending
  expiry, a fixed per-account live-session admission limit, bounded session-scoped
  active-session metadata with non-secret selectors, recently authenticated
  all-sibling or selected-sibling revocation, bearer-derived sign-out everywhere,
  session-authorized atomic account disabling, and bounded expired cleanup;
  no authentication ceremony, membership, vault, or HTTP integration.
- `internal/identity/memberbackup`: development-only account-scoped encrypted
  member-backup slots with fixed public binding, compare-and-swap revisions,
  deletion tombstones, and session-derived access serialized with revocation/disable;
  fixed recent-authentication admission for session-scoped mutations;
  no authentication ceremony, enrollment, browser/API integration, PRF, or recovery.

## Product direction

The required product is browser-only for members, reviewers, and administrators:
sign in, open a shared review link or an available round, complete the form, and
submit. No app, extension, CLI, manual key generation, CSR handling, or key-file
management may be required for ordinary use. The existing CLI is optional tooling,
not the product onboarding path. Prioritize a complete browser workflow over
additional optional CLI features.

- Follow [account and review UX](docs/ui-design.md#account-and-review-workflow)
  and the [browser account vault](docs/key-management.md#browser-account-vault).
- Generate member and round-scoped reviewer keys automatically on the device.
  Only encrypted member-key backups may enter identity-side vault storage;
  never upload plaintext keys, unlock secrets, or passkey PRF outputs.
- Keep account authentication, local vault unlocking, and anonymous submission
  authorization separate. Passkey login alone does not decrypt a vault.
- Prefer passkey-assisted unlocking after compatibility/profile review; provide
  an explicit browser-only unlock path for unsupported setups, never a server
  decryption fallback. Do not promise universal one-gesture access or recovery.
- Keep submission history, receipts, reply capabilities, and tokens out of the
  account vault. Dashboards must not create identity-to-submission records.
- Recovery must preserve membership quotas, revocations, and round-key expiry.
  Login reset is not recovery of encrypted keys. Reviewer-key server backup needs
  a separately reviewed retention policy before it can be enabled.
- These are planned requirements. Do not present them as implemented controls.

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
make member-wasm      # separate local member-session WASM and matching notices
make member-wasm-test # native/Node backup compatibility, member bridge/worker checks
make member-browser-test # opt-in synthetic Chromium checks; requires MEMBER_BROWSER
make container-secrets # generate/validate local database secret files, no replacement
make container-config # validate normalized Compose settings, no daemon required
make up              # build/start/wait and verify the local demo stack
make smoke           # inspect a running stack and its HTTP/database boundaries
make down            # stop the demo stack without deleting database volumes
make container-test  # isolated real-container/PostgreSQL checks; disposable test data
make migrate-identity # explicitly apply local identity database migrations
make migrate-submission # explicitly apply local submission database migrations
make db-migration-test # isolated real-PostgreSQL migration/version/grant checks
make db-account-test   # real runtime-role account/session race, expiry, grant checks
make db-member-backup-test # real runtime-role member-backup scope, revision, grant checks
```

See [testing](docs/testing.md) for required full database, browser, container-scan,
inventory, and protocol targets that remain unavailable. The opt-in container target
checks infrastructure/bootstrap only. The separate opt-in browser target checks
synthetic member workers, not product custody or the account/vault journey.
Add real Make targets with implementation.
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
- Follow the maintainer [squash-merge title rule](CONTRIBUTING.md#squash-merge-commit-titles).
- Keep commits atomic; commit lint and hooks must pass without bypass.
- Follow the official [SemVer 2.0.0](https://semver.org/spec/v2.0.0.html) and
  [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/) guidance, with
  project-specific requirements in [versioning](docs/versioning.md).
- Every PR needs a [SemVer impact label](docs/versioning.md#commit-and-pr-mapping)
  and Unreleased entry unless the documented
  exception label applies.
- Follow the [PR template](https://github.com/mandipnotroot/anonce/blob/main/.github/pull_request_template.md) strictly when creating
  a PR. Preserve every section, section order, and checklist item. Replace guidance
  with concise, change-specific details; do not omit the checklist or substitute a
  custom structure. Check items only after verification or explicit contributor
  confirmation. Request owner review only when the owner is not the PR author.
- Use neutral, completed-change wording in PR descriptions, such as "Added" or
  "Updated", rather than first-person "I/we" or task instructions such as "Add"
  or "Update". Explain what changed, why, and what was tested in natural language,
  not a progress report or exhaustive inventory. Keep evidence and limitations
  concise, and link to canonical docs for detail. Preserve the required template,
  including its checklist text. Do not invent test results, review, or approval.

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

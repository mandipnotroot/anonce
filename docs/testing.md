<!-- SPDX-FileCopyrightText: 2026 Anonce Contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Testing and evidence

Audience: contributors and security reviewers.

## Current executable checks

### Connected browser MVP checks

`make browser-test` builds the application and matched runtimes, runs Node session
checks, then exercises `TestBrowserMVP` with Chromium WebAuthn and two fresh real
PostgreSQL instances. Supply the reviewed `MEMBER_BROWSER` executable, Node.js
22.23.3 on `PATH` and `BROWSER_TEST_PG` pointing to PostgreSQL 18.6's `bin` directory.
The target is opt-in, not part of `make check`, and fails rather than skips missing
prerequisites.

Run it inside an OS sandbox with isolated loopback networking, an empty allowlisted
environment, read-only source/toolchains, scratch-only writes and explicit CPU,
memory, process, disk/file and wall-clock limits. Never use existing databases.
Trust authentication applies only to disposable synthetic clusters; application
startup uses independent SCRAM credentials. Test TLS pins fresh certificate public
keys without globally disabling verification. Keep browser sandboxing, CSP,
WebAuthn verification, protected cookies and CSRF enabled.

The driver uses real registration/assertion verification with a standard virtual
authenticator, not a login bypass. It covers administrator publication, member
vault/enrollment, exact-origin handoff, blind finalization, anonymous encryption,
signed acceptance, concurrent exact retries, conflicting spending and local review.
Wire inspection rejects passphrases, plaintext answers, account cookies/referrers
and unexpected origins. PostgreSQL cases cover persistence, grants/isolation,
enrollment races and quota persistence across sessions.

Session cases use independently authenticated contexts and a shared-partition tab.
They check accessible controls, Enter activation, expiry-preserving reauthentication,
purpose/bearer binding, selected revocation, confirmed all-session sign-out,
foreground invalidation, local clearing and unchanged encrypted backups.
`session-management-http` checks actual TLS/CSRF, runtime-role authorization,
foreign/stale selectors and recent-authentication rejection. The nested
`reauthentication-binding-and-consumption` case rejects swapped bearers, missing
bearers, purpose confusion, malformed/replayed assertions and revocation mid-ceremony.

These checks do not establish physical-authenticator/provider sync, mobile support,
instantaneous remote erasure, manual accessibility approval or independent review.

`make browser-unit-test`, also included in `make check` and runtime CI, checks that
one malformed or undecryptable answer does not suppress later records or pages.
It checks plaintext-buffer cleanup and stops without publishing late results when
the reviewer owner closes, is replaced, becomes hidden, or reaches round expiry.
These Node checks do not replace the real-browser journey.

The journey also passes a corrupted envelope followed by an actual stored answer
through the shared reader and real reviewer worker. It requires a rejection
placeholder followed by the correctly decrypted answer, and checks that reaching
the review deadline terminates the actual worker.

| Target | Executable scope |
| --- | --- |
| `make build` | Browser services, matched member/reviewer runtimes, notices and operator tools |
| `make test` | All native packages with race detection and statement coverage |
| `make lint` | Native/WASM vet, pinned gofumpt/golangci-lint, tidy diff and module verification |
| `make fuzz` | Bounded native parser/admission fuzzing, two workers and 15 seconds per target; override with `FUZZTIME` |
| `make vuln` | govulncheck, gosec, module inventory/verification and redacted current-file Gitleaks |
| `make web-lint` | Embedded product page/runtime-manifest, integrity, origin-policy and markup checks |
| `make browser-profile-test` | Native protocol composition and selected library vectors |
| `make browser-session-test` | Node session-control lifecycle, bounded inventory, confirmation, uncertain outcomes and local clearing |
| `make browser-unit-test` | Reviewer record isolation, plaintext cleanup, owner lifecycle and expiry checks in Node |
| `make member-wasm` | Member runtime and worker assets with matching reviewed loader/notices, hashes and 8 MiB gate |
| `make member-wasm-test` | Worker/form lifecycle, native/Node bridge and backup compatibility |
| `make member-browser-test` | Opt-in isolated synthetic Chromium worker/backup/lifecycle checks; requires `MEMBER_BROWSER` |
| `make container-config` | Real normalized Compose configuration and hardening checks; requires Compose, not a daemon |
| `make container-test` | Disposable real application/database containers, verified TLS, grants and isolation |
| `make db-migration-test` | Real PostgreSQL migration histories, failure, concurrency, ownership and grants |
| `make db-account-test` | Runtime-role sessions, expiry, revocation, limits, locks/races and isolation |
| `make db-member-backup-test` | Runtime-role owner/binding/revision/tombstone and session-authorization races |
| `make db-submission-record-test` | Runtime-role atomic spends, payload retries, windows, cancellation and grants |

`make up`, `make smoke` and `make down` are operator lifecycle commands, not test
substitutes. See [setup](../CONTRIBUTING.md) and [commands](../AGENTS.md#commands).

### Parser fuzzing and fixtures

`make fuzz` includes browser database/JSON/session admission, profile rejection,
submission input, account/session operations, member-backup admission, migrations,
listener configuration, backup envelopes, typed key payloads, fixed member requests,
member-session confirmation/unlocking and WASM/manifest size admission.

| Parser | Work bound |
| --- | --- |
| Listener/source configuration | 8192 bytes before parsing, tighter field limits |
| Browser JSON | 32 KiB body, duplicate-key rejection and maximum nesting |
| Submission storage | 17-byte round, 33-byte digests, 65537-byte ciphertext fuzz caps; no crypto/database work |
| Session token | 33-byte fuzz cap; exact 32-byte token admission and digest oracle |
| Member-backup storage | 33-byte key/token, 109-byte envelope caps and fixed-width revision; no KDF/database work |
| Typed key payload | 49-byte fuzz cap, exact 48-byte ASN.1 profile; no KDF work |
| Member request | 130-byte fuzz cap, exact 129-byte DER plus library signature validation |
| Member session | Bounded password/backup/key metadata and locked-state rejection without derivation |
| Worker transport/text | Generated bounded commands/Unicode strings with independent admission oracles |

Keep licensed, synthetic regressions under the package's `testdata/fuzz/<target>`.
Never retain passwords, private keys or production records in fixtures, screenshots,
traces or crash corpora. Real backup tests use full profile costs, not weaker test
parameters, and generate keys at runtime. Typed wrappers share contract tests in
`internal/client/internal/keytest` while retaining algorithm-specific cases.

### Implemented test mapping

| Boundary | Named checks |
| --- | --- |
| Profile journey and isolation | `TestProfileJourney`, `TestEnvelopeIsolation`, `TestBulletinBounds`, `TestSignedTimestampBounds`, `FuzzProfileRejection` |
| HTTP admission | `TestIdentityGate`, `TestCookieEncoding`, `TestAuthenticationLimiter`, `TestSessionHTTPAdmission`, `FuzzSessionSelectorHTTP` |
| State custody | `TestStateFileAdmission`, `TestInitializationDoesNotReplace` |
| TLS lifecycle | `TestBoundedTLSMetadata`, `TestRunTLSFailures`, connection-limit/cancellation/shutdown tests in `internal/service` |
| Product assets | `scripts/browser_markup.py` and tests in `web/browser` for labels/landmarks, local resources, strict manifests, entry integrity and origin-specific CSP |
| Backup/key custody | Native tests in `internal/client`, bridge/worker checks below |
| Product surface | `scripts/test_product_workflow.py` checks the command/build/runtime/API inventory |

### Container infrastructure checks

`make container-test` uses a fresh project, random ephemeral loopback ports,
generated secrets and disposable volumes. It checks connected pages, strict TLS
trust/hostname, scoped read-only state and runtime credentials, restart persistence,
non-root/read-only/capability/resource/logging policy and independent database grants.
It removes only its own test resources; images/cache remain. Missing Docker or
Compose is a failure, not a successful no-op. Source/configuration unit tests do
not replace real daemon evidence. See [deployment](deployment.md#container-stack).

### Database migration checks

`make db-migration-test` applies independent embedded histories on real PostgreSQL,
including repeated/concurrent runs, failed application, wrong targets, unsupported
or malformed histories, boundary markers and owner/runtime grants. Published SQL
is immutable. Runtime roles must not own schema or migration state.

### Account storage checks

`make db-account-test` adds race-enabled runtime-role account/session checks:
digest-only persistence, absolute expiry/cleanup, 16-session admission, cross-account
revocation isolation, concurrent disable, rotation without expiry extension,
inventory/selectors, recent-authentication gates and cancellation after lock waits.
Constraint and privilege tests reject unauthorized changes and the wrong database.
Native admission tests alone cannot establish transaction/grant behavior.

### Member-backup storage checks

`make db-member-backup-test` adds persistence, owner isolation, fixed public binding,
revision conflicts, retained tombstones, concurrent writes/disable and rollback.
Session-derived operations race revocation, sign-out, rotation and disable and
recheck expiry/authentication age after account-lock waits. Invalidated bearers
cannot retain vault authority; revocation does not erase encrypted records.

### Submission record storage checks

`make db-submission-record-test` adds cross-pool duplicate spending, exact retries,
payload conflicts, immutable round/record bindings, database-clock admission,
post-lock windows, cancellation ordering, uncommitted conflicts, rollback and
runtime grants/isolation. This store-level target does not verify tokens or the
HTTP protocol; `make browser-test` covers their composition.

### WASM member session checks

`make member-wasm-test` builds the product member runtime, runs worker/form Node
lifecycle tests and native/Node compatibility tests under `wasmintegration`.
They cover two-way backup validation, fixed request output, expected-key matching,
wrong passwords/corruption, input snapshots/cleanup, confirmation, busy/locked
states, cancellation, explicit termination and malformed worker transport.

Worker tests cover clocks, visibility, abort signals, peer lock, `closed`
observation, invalid facilities, late results and bounded Unicode encoding. Node
is a development test runtime, not a product dependency or browser support claim.

### Member-worker browser checks

`make member-browser-test` requires the pinned, reviewed Chromium binary via
`MEMBER_BROWSER` and the Node version in `scripts/wasm.toml`. It fails missing
prerequisites. The isolated test-only host serves synthetic fixtures, not another
product entry point. Tests cover native/worker backup compatibility, CSP probes,
event-loop progress, peer lock, synthetic clock expiry, background-tab locking,
explicit restoration, navigation termination and accessible setup/restoration controls.
The test screenshot documents that fixture only, not the product account journey.

## Required runtime command contract

Keep build, race/coverage, static analysis, dependency/secret checks, bounded fuzzing
and matched browser-worker checks executable. Add real targets with implementation;
never add a passing placeholder. Full database, browser, container scan, inventory,
recovery and protocol evidence must be reported separately when unavailable.

## Test layers and gates

Unit/admission tests establish bounded local behavior. Node checks establish bridge
and controller behavior. Real PostgreSQL establishes transactions/grants. Real
browsers establish the composed journey on recorded versions. Manual assistive,
mobile and provider checks establish usability evidence. Independent review remains
necessary even when automated checks pass. No layer substitutes for the others.

## Browser account and vault acceptance

The connected journey above covers a limited implementation. Remaining required
evidence includes physical/synced authenticators, a supported browser/provider
matrix, mobile startup/unlock latency and peak memory, manual accessibility,
autofill/paste, prompt counts and unsent-answer warnings.

Exercise wrong passphrases, corrupt/substituted backups, cancelled ceremonies,
new-device binding, private/shared browsing, evicted storage, multiple tabs,
lock/logout/account switching, worker expiry and unavailable networking. Failures
must not create replacement keys, upload secrets or silently resume abandoned work.
Capture request/header/URL/referrer/storage/database boundaries with synthetic data:
no identity credentials on anonymous requests, no plaintext keys/unlock material on
services, and no account-linked token/receipt history.

PRF, credential addition/removal, account/key recovery, reviewer server backup and
retention restoration are unimplemented. Require dedicated negative and race cases
before offering them, including preserved quotas and no expired reviewer-key reuse.
Agree and document UX/resource budgets before claiming support.

## Multi-user simulation

Required broader evidence: at least 24 distinct dummy members across cohorts and
rounds, valid/revoked/expired/ineligible/nonparticipating members, parallel devices,
multiple reviewers, role boundaries, interrupted issuance and restored state.
Higher response limits, replies and thresholds require their own implementation
before simulation. Report revision, population and executed/pass/fail/unimplemented
cases; never relabel one credential as several members or report empty suites as passing.

## Attack-simulation matrix

Existing evidence is mapped above. These broader named acceptance tests are planned,
not existing passing suites:

| Boundary | Planned tests |
| --- | --- |
| Vault ownership and recovery | `TestVaultEnforcesOwnerIsolation`, `TestVaultKeepsUnlockMaterialLocal`, `TestVaultSeparatesAccountAndKeyRecovery`, `TestVaultRejectsBindingAndVersionMismatch` |
| Anonymous handoff/history | `TestBrowserPreservesAnonymousHandoff`, `TestDashboardExcludesSubmissionHistory`, `TestVaultCoordinatesSessionLock` |
| Membership and invitations | `TestIssuerRejectsUntrustedCertificate`, `TestIssuerRejectsRevokedOrExpired`, `TestIssuerRejectsStaleRevocations`, `TestIssuerRejectsWrongCohort`, `TestChallengeRejectsReplay`, `TestEnrollmentConsumesCodeAtomically`, `TestEnrollmentRejectsReplacedCode` |
| Signer authority | `TestSignerEnforcesAuthorization`, `TestBlindProfileRejectsInvalidInputs` |
| Response policy | `TestRoundRejectsInvalidResponseLimit`, `TestRoundAcceptsConfiguredResponseAllowance` |
| Quotas and recovery | `TestIssuerConcurrentQuotaEnforcement`, `TestIssuerRecoveryPreservesUnlinkability`, `TestIssuerQuotaSurvivesCredentialReplacement`, `TestIssuerQuotaSurvivesBackupRestore` |
| Spending and ciphertext | `TestSubmissionRejectsWrongRound`, `TestSubmissionConcurrentSpend`, `TestSubmissionCanonicalSpendDigest`, `TestSubmissionRejectsPayloadRebinding`, `TestClientRejectsEnvelopeTampering` |
| Publication and transparency | `TestRoundPreservesPublishedResponseLimit`, `TestClientRejectsBulletinSubstitution`, `TestSubmissionRecoversLogPublication`, `TestReceiptRejectsMutation`, `TestLogDetectsSplitView` |
| Administration and audit | `TestAdminEnforcesRoleMatrix`, `TestAdminRejectsCrossSiteWrite`, `TestAdminRejectsRepeatedAuthentication`, `TestAdminRequiresRecentAuthentication`, `TestAdminEnforcesSessionAndRecoveryPolicy`, `TestAuditDetectsMutation` |
| Delivery, storage and logs | `TestWebRejectsUnexpectedRequests`, `TestDatabaseCrossServiceIsolation`, `TestSubmissionLogsExcludeSensitiveData` |
| Review, replies and retention | `TestReviewEnforcesReleasePolicy`, `TestReviewDistinguishesResponsesFromParticipants`, `TestReviewPreservesDeviceBoundary`, `TestReplyEnforcesCapabilityPolicy`, `TestAbuseEnforcesRoundScope`, `TestRetentionRejectsExpiredKeyRestore` |

Reject wrong authority, replay, changed bindings and cross-round use without
revealing account participation or mailbox existence. Independent proof tests must
detect mutation/forks; retention tests must distinguish server denial from device erasure.

## Fuzz plan

Extend bounded native/WASM decoding checks to future enrollment CSV, forms,
certificate/revocation wrappers, tokens, replies and public proofs. Bound allocation,
recursion and work and license synthetic failures. [CI/CD](ci-cd.md) owns durations
and publication gates.

<!-- SPDX-FileCopyrightText: 2026 Anonce Contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Testing and evidence

Audience: contributors and security reviewers.

## Current executable checks

The [command reference](../AGENTS.md#commands) lists available repository,
documentation, and Go infrastructure checks. Installation is in
[CONTRIBUTING.md](../CONTRIBUTING.md). None tests a working submission protocol.

`make build` builds every current Go command with Go 1.27.3. `make test` runs race
detection and writes `coverage/out`, then prints statement coverage. The complete
Go module, including thin command wrappers and process signal handling, is included
in that report without exclusions. Process signal handling also needs manual
execution checks; unit coverage alone is not lifecycle evidence.

`make lint` runs vet, pinned gofumpt and golangci-lint, tidy diff, and module
verification. `make fuzz` runs `FuzzConfig` with two workers for 15 seconds by
default; `FUZZTIME` changes the time budget. Inputs are capped at 8192 bytes before
configuration parsing, which separately caps listen and source-URL lengths.
Go retains failures under `internal/service/testdata/fuzz/FuzzConfig`; review and
license any retained corpus before committing it.

`make vuln` runs govulncheck, gosec, module verification/inventory, and redacted
Gitleaks scanning of current files. Only Git internals and disposable tool/build
outputs are excluded by `.gitleaks.toml`. The module currently has no third-party
runtime dependencies. Module inventory is evidence for manual dependency review,
not automated license approval. Tool versions and admission are in
[dependencies](dependencies.md).

Infrastructure cases map to `TestConfig`, `TestConfigSourceURL`,
`TestInfrastructureRoutes`, `TestInfrastructureMethods`,
`TestUnavailableRoutesRespectServiceBoundary`,
`TestInfrastructureDoesNotReadOrReflectRequestData`, `TestServeRejectsBodyBeforeContinue`,
`TestServeLifecycle`, `TestServePropagatesCancellationToRequests`,
`TestServeClosesUnresponsiveRequests`,
`TestServeListenerFailureClosesRequests`,
`TestConnectionLimitAndClose`, `TestServerBounds`, and `TestRunFailures`.
These do not establish database isolation, anonymity, or any protocol attack result.

## Required runtime command contract

Build, test, lint, fuzz, and vulnerability targets below are implemented for the
current infrastructure only. All other rows remain requirements, not available
commands. See the [roadmap](roadmap.md).

| Target | Required behavior |
| --- | --- |
| `make build` | Build every Go command with the pinned stable toolchain |
| `make test` | `go test -race -coverprofile=coverage/out ./...` with a coverage report |
| `make lint` | go vet, gofumpt, golangci-lint, tidy diff, and module verification |
| `make vuln` | govulncheck, gosec, dependency review, and secret scanning |
| `make db-test` | Migrations, privileges, concurrency, backup/restore on real PostgreSQL |
| `make fuzz` | Bounded parser fuzzing with retained failing inputs |
| `make wasm` | Shared Go client build for `js/wasm`, matching loader, hash and size gate |
| `make web-lint` | HTML, CSS, JS, and asset-integrity checks |
| `make e2e` | Headless browser checks against the Compose stack |
| `make up` | `docker compose up --build --wait` with loopback-only demo exposure |
| `make smoke` | Health/readiness checks and service isolation checks |
| `make simulation` | Readable multi-user/attack coverage report with honest case status |
| `make container-scan` | Inspect the built image and its dependency inventory |
| `make sbom` | Produce a versioned SPDX or CycloneDX inventory |

## Test layers and gates

Use table-driven unit tests, boundary and failure cases, race detection, real-database
integration, browser interaction, and process-level smoke tests. A proposed runtime
coverage floor is 80% of executable first-party Go statements, with explicit scope
and a reviewed rationale for exclusions. Do not lower it merely to pass a change.
Coverage is not evidence that an invariant was actually tested.

Browser tests cover all routes, dark/light and mobile/desktop layouts, keyboard
navigation, accessibility rules, print styles, source links, CSP, SRI, and prohibited
outbound requests. Manual assistive-technology testing remains required.
Map administrative controls to versioned ASVS requirements and test factor
enrollment, recovery, session rotation, and expiry as well as ordinary login.
Measure native/WASM interoperability, bundle size, startup time, cryptographic
latency, and memory use on supported desktop and mobile browsers.

## Multi-user simulation

Run at least 24 dummy members across multiple cohorts and rounds, with separate
certificate keys and independent device state. Include valid, revoked, expired,
ineligible, non-participating, and duplicate-requesting members. Exercise multiple
reviewers, role boundaries, threshold policies, encrypted replies, and retention.
Do not reuse a single credential under several labels.
Include rounds with a limit of `1` and rounds with limits greater than `1`. For
each member, test unused, partially reserved, and exhausted allowances, parallel
devices, interrupted signing/delivery, and certificate replacement. Each valid
token must remain single-use, and distinct tokens from one member must not carry
shared identity-side slot metadata. Check that response counts are not reported
as distinct participant counts or used to claim a stronger release guarantee.

The readable report records revision, dummy population, actual cases executed,
pass/fail/unimplemented status, timing bounds, and non-sensitive evidence locations.
An empty suite or simulated success must never be published as a passing attack suite.

## Attack-simulation matrix

All named protocol tests below are **planned**, not present.

| Attack | Expected result | Planned test name |
| --- | --- | --- |
| Untrusted CA or forged certificate | Issuance rejected | `TestIssuerRejectsUntrustedCertificate` |
| Expired/revoked membership | Issuance rejected with fresh revocation policy | `TestIssuerRejectsRevokedOrExpired` |
| Stale or unavailable required revocation data | Fail closed | `TestIssuerRejectsStaleRevocations` |
| Wrong cohort | Issuance denied | `TestIssuerRejectsWrongCohort` |
| Reused or expired login challenge | No authenticated issuance | `TestChallengeRejectsReplay` |
| Reused enrollment code | No second certificate | `TestEnrollmentConsumesCodeAtomically` |
| Replaced enrollment code | Old unused code cannot enroll | `TestEnrollmentRejectsReplacedCode` |
| Unauthorized signing request | No signing operation or raw CA key exposure | `TestSignerEnforcesAuthorization` |
| Missing, zero, negative, fractional, overflowing, or unsupported response limit | Draft/publication or bulletin validation rejected; no unlimited fallback | `TestRoundRejectsInvalidResponseLimit` |
| Limit changed after publication or different limits served to members | Rejected under the same round ID; independent bulletin comparison detects inconsistent views | `TestRoundPreservesPublishedResponseLimit` |
| Parallel requests with limit one or greater than one | Total reserved allowance never exceeds the published limit; one signing per slot | `TestIssuerConcurrentQuotaEnforcement` |
| Interrupted issuance/retry | Reserved slot remains consumed; no refund, re-signing, or transcript persistence | `TestIssuerRecoveryPreservesUnlinkability` |
| Re-enrollment, replacement certificate, or another device/session | Existing membership quota remains consumed | `TestIssuerQuotaSurvivesCredentialReplacement` |
| Restored issuer backup predates reservations | Recovery cannot reset consumed allowance or exceed the limit | `TestIssuerQuotaSurvivesBackupRestore` |
| Several permitted responses | Distinct tokens accepted up to the allowance without identity-side slot metadata | `TestRoundAcceptsConfiguredResponseAllowance` |
| Malformed blinded request or malicious key | Library/profile validation rejects | `TestBlindProfileRejectsInvalidInputs` |
| Cross-round token | Rejected | `TestSubmissionRejectsWrongRound` |
| Parallel token spending | Exactly one acceptance | `TestSubmissionConcurrentSpend` |
| Alternate signature representation | Cannot bypass canonical spend identity | `TestSubmissionCanonicalSpendDigest` |
| Retry with different ciphertext | Existing spend cannot be rebound | `TestSubmissionRejectsPayloadRebinding` |
| Crash during acceptance/log publication | Durable spend and payload survive; outbox recovery loses no accepted commitment | `TestSubmissionRecoversLogPublication` |
| Modified ciphertext/context | AEAD opening fails locally | `TestClientRejectsEnvelopeTampering` |
| Changed form/reviewer key | Bulletin verification or independent comparison fails | `TestClientRejectsBulletinSubstitution` |
| Missing or mutated inclusion path | Receipt rejected | `TestReceiptRejectsMutation` |
| Forked log | Independent checkpoint comparison detects inconsistency | `TestLogDetectsSplitView` |
| Administrative role escalation | Forbidden server-side | `TestAdminEnforcesRoleMatrix` |
| Cross-site administrative write | Rejected without valid CSRF proof | `TestAdminRejectsCrossSiteWrite` |
| Password guessing or TOTP replay | Bounded throttling and replay rejection | `TestAdminRejectsRepeatedAuthentication` |
| Sensitive action without reauthentication | Rejected | `TestAdminRequiresRecentAuthentication` |
| Expired/rotated session or weaker recovery path | No administrative access or factor bypass | `TestAdminEnforcesSessionAndRecoveryPolicy` |
| Modified, removed, or reordered audit event | Independent anchor verification detects inconsistency | `TestAuditDetectsMutation` |
| Script injection or outbound tracking | Escaped content, CSP block, browser test failure | `TestWebRejectsUnexpectedRequests` |
| Issuer account accesses submission DB | Connection/query rejected | `TestDatabaseCrossServiceIsolation` |
| Plaintext, token, or IP in logs | Privacy assertion fails | `TestSubmissionLogsExcludeSensitiveData` |
| Early/over-filtered results | Policy rejects release; key-holder limit documented | `TestReviewEnforcesReleasePolicy` |
| Several responses from one member reach a count threshold | Not reported as distinct participants or a distinct-member privacy guarantee | `TestReviewDistinguishesResponsesFromParticipants` |
| Unauthorized review or plaintext export upload | Access denied; decrypted data stays local | `TestReviewPreservesDeviceBoundary` |
| Wrong, expired, replayed, or cross-round reply capability | Rejected without an identity or mailbox existence oracle | `TestReplyEnforcesCapabilityPolicy` |
| Unauthorized or cross-round abuse action | No flag/block change or identity lookup | `TestAbuseEnforcesRoundScope` |
| Corrupted or expensive keystore | Bounded reject with no partial plaintext | `TestKeystoreRejectsUnsafeParameters` |
| Native/WASM format or vector mismatch | Compatibility gate fails | `TestClientNativeWASMCompatibility` |
| Restored expired round key | Controlled backup restoration rejects active reuse | `TestRetentionRejectsExpiredKeyRestore` |

## Fuzz plan

Fuzz enrollment CSV, form-schema decoding, bounded keystore headers, certificate/CRL
parsing wrappers, token/envelope decoding, bulletin canonicalization, and receipt
proof parsing. Native and WASM clients must share decoding tests. Bound allocations,
recursion, input size, and work factors. Keep synthetic regression inputs licensed;
never retain real secrets in a crash corpus.

CI durations and publication rules are owned by [CI/CD](ci-cd.md).

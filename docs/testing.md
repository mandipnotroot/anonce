<!-- SPDX-FileCopyrightText: 2026 Anonce Contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Testing and evidence

Audience: contributors and security reviewers.

## Current executable checks

See [commands](../AGENTS.md#commands) and [setup](../CONTRIBUTING.md).
**No current check tests a working submission protocol.**

| Target | Current checks |
| --- | --- |
| `make build` | All Go commands with Go 1.27.3 |
| `make test` | Race detection, `coverage/out`, statement coverage report; whole module, no exclusions, including wrappers and signal handling |
| `make lint` | vet, pinned gofumpt/golangci-lint, tidy diff, module verification |
| `make fuzz` | `FuzzConfig` and `FuzzLookup`, two workers, 15 seconds each; override with `FUZZTIME` |
| `make vuln` | govulncheck, gosec, module verification/inventory, redacted current-file Gitleaks scan |
| `make web-lint` | Build/start loopback submission with/without development flag; inert markup, headings/landmarks, fragment/description targets, links, CSS restrictions, asset hashes, headers, unavailable protocol/readiness, bounded shutdown |

- Signal handling also requires manual execution checks; coverage is not lifecycle evidence.
- Fuzz configuration input is capped at 8192 bytes before parsing, with separate
  listen/source-URL limits. Retained failures belong in
  `internal/service/testdata/fuzz/FuzzConfig` or `internal/web/testdata/fuzz/FuzzLookup`.
  Review and license corpora before committing.
- `.gitleaks.toml` excludes only Git internals and disposable tool/build outputs.
  There are no third-party runtime modules. Inventory supports manual review, not
  automatic license approval. See [dependencies](dependencies.md) for pins/admission.

### Implemented test mapping

| Area | Tests |
| --- | --- |
| Configuration | `TestConfig`, `TestConfigSourceURL`, `TestRunFailures` |
| Routing and input isolation | `TestInfrastructureRoutes`, `TestInfrastructureMethods`, `TestUnavailableRoutesRespectServiceBoundary`, `TestInfrastructureDoesNotReadOrReflectRequestData`, `TestServeRejectsBodyBeforeContinue` |
| Lifecycle and limits | `TestServeLifecycle`, `TestServePropagatesCancellationToRequests`, `TestServeClosesUnresponsiveRequests`, `TestServeListenerFailureClosesRequests`, `TestConnectionLimitAndClose`, `TestServerBounds` |
| Shell paths, development gate, SRI, headers, methods, HEAD, no body reads/reflection | `TestSite`, `TestStylesheetIntegrity`, `TestSiteRejectsBrokenAssets`, `TestWebServiceBoundary`, `TestWebDelivery`, `TestDevelopmentStyleGuideFlag` |
| Rejection of scripts, handlers, remote assets, active controls, malformed markup, wrong asset hashes | `scripts/test_web_check.py` |

These establish neither database isolation, anonymity, nor protocol attack results.
Web checks validate allowlists/delivery, not full HTML/CSS grammar or browser execution.
No JavaScript exists. Screenshots, actual CSP enforcement, keyboard access, assistive
technology, contrast, and print rendering remain untested.

## Required runtime command contract

Build/test/lint/fuzz/vuln cover infrastructure only; web-lint covers the inert shell.
**All other targets below are required but unavailable.** See [roadmap](roadmap.md).

| Target | Required behavior |
| --- | --- |
| `make build` | Build every Go command with the pinned stable toolchain |
| `make test` | `go test -race -coverprofile=coverage/out ./...` with a coverage report |
| `make lint` | go vet, gofumpt, golangci-lint, tidy diff, and module verification |
| `make vuln` | govulncheck, gosec, dependency review, and secret scanning |
| `make db-test` | Migrations, privileges, concurrency, backup/restore on real PostgreSQL |
| `make fuzz` | Bounded parser fuzzing with retained failing inputs |
| `make wasm` | Shared Go client build for `js/wasm`, matching loader, hash and size gate |
| `make web-lint` | Implemented inert HTML/CSS and asset-delivery checks; extend for future JS and full syntax validation |
| `make e2e` | Headless browser checks against the Compose stack |
| `make up` | `docker compose up --build --wait` with loopback-only demo exposure |
| `make smoke` | Health/readiness checks and service isolation checks |
| `make simulation` | Readable multi-user/attack coverage report with honest case status |
| `make container-scan` | Inspect the built image and its dependency inventory |
| `make sbom` | Produce a versioned SPDX or CycloneDX inventory |

## Test layers and gates

- Use table-driven unit, boundary/failure, race, real-database, browser, and process smoke tests.
- Proposed coverage floor: 80% of executable first-party Go statements, with explicit
  scope and reviewed exclusions. Do not lower it to pass. Coverage does not prove invariants.
- Browser tests: all routes, light/dark, mobile/desktop, keyboard, accessibility,
  print, source links, CSP, SRI, and prohibited outbound requests. Manual
  assistive-technology testing is still required.
- Map admin controls to versioned [ASVS](https://owasp.org/www-project-application-security-verification-standard/)
  requirements. Test login, factor enrollment,
  recovery, session rotation, and expiry.
- Measure native/WASM interoperability, bundle size, startup, cryptographic latency,
  and memory on supported desktop/mobile browsers.

## Multi-user simulation

- At least 24 dummy members across multiple cohorts/rounds, each with separate
  certificate keys and device state. Never relabel one credential as several members.
- Member cases: valid, revoked, expired, ineligible, non-participating, duplicate-requesting.
- Exercise multiple reviewers, role boundaries, thresholds, encrypted replies, and retention.
- Include rounds with limits of `1` and greater than `1`. For each member, test
  unused/partial/exhausted allowances, parallel devices, interrupted signing/delivery,
  and replacement certificates.
- Verify single-use tokens, no shared identity-side slot metadata, and no response-count
  claims of distinct participation or stronger release guarantees.
- Report revision, population, executed cases, pass/fail/unimplemented status,
  timing bounds, and non-sensitive evidence locations. Never report empty suites
  or simulated success as passing attack tests.

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

- Fuzz enrollment CSV, form schemas, keystore headers, certificate/CRL wrappers,
  tokens/envelopes, bulletin canonicalization, and receipt proofs.
- Share native/WASM decoding tests. Bound allocation, recursion, input size, and work.
- License synthetic regression inputs. Never retain real secrets in crash corpora.

CI durations and publication rules are owned by [CI/CD](ci-cd.md).

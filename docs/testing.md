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
| `make test` | `go test -race -coverprofile=coverage/out ./...` and statement coverage report; no native-package exclusions, including wrappers and signal handling. JS-only code is checked separately below |
| `make lint` | Native and WASM entry-point vet, pinned gofumpt/golangci-lint, tidy diff, module verification |
| `make fuzz` | `FuzzConfig`, `FuzzLookup`, `FuzzBackup`, `FuzzMemberKeyPayload`, `FuzzMemberCSR`, `FuzzWASMRequest`, `FuzzReviewerKeyPayload`, `FuzzClientArguments`, `FuzzClientPassword`, and `FuzzClientRewrapPasswords`, two workers, 15 seconds each; override with `FUZZTIME` |
| `make vuln` | govulncheck, gosec, module verification/inventory, redacted current-file Gitleaks scan |
| `make web-lint` | Build/start loopback submission with/without development flag; inert markup, headings/landmarks, fragment/description targets, links, CSS restrictions, asset hashes, headers, unavailable protocol/readiness, bounded shutdown |
| `make wasm` | Go `js/wasm` public-request verifier; matching reviewed loader/notices, SHA-256 manifest, 8 MiB uncompressed size gate |
| `make wasm-test` | Rebuild artifacts, compare native and Node WASM public-request results, exercise the actual bridge, and run adapter unit tests under the Go JS/WASM runner |

- Signal handling also requires manual execution checks; coverage is not lifecycle evidence.
- `.gitleaks.toml` excludes only Git internals and disposable tool/build outputs.
  Module inventory supports manual review, not automatic license approval.
  See [dependencies](dependencies.md) for device-backup modules and pins/admission.

### Parser fuzzing and fixtures

| Parser | Input/work bounds |
| --- | --- |
| Configuration | 8192 bytes before parsing; separate listen/source-URL limits |
| Backup structure | Maximum backup size plus one byte; allocation-free parser, no Argon2id |
| Member/reviewer payload | 49-byte input cap, 48-byte ASN.1 profile; no KDF work |
| Member CSR | 130-byte fuzz input cap, 129-byte DER profile; bounded ASN.1 and signature verification, no KDF work |
| WASM request adapter | 259-byte fuzz input cap, exact 258-byte ASCII hex representation before bounded shared CSR parsing; no KDF work |
| CLI arguments | 8193-byte fuzz input cap; no file, network, or KDF work |
| CLI password framing | 2051 bytes for ordinary framing, 3076 for rewrap; no file, network, or KDF work |

Review and license synthetic regression inputs before committing. Retain failures
in the relevant package's `testdata/fuzz/<target>` directory:

- `internal/service`: `FuzzConfig`.
- `internal/web`: `FuzzLookup`.
- `internal/client/keystore`: `FuzzBackup`.
- `internal/client/memberkey`: `FuzzMemberKeyPayload`.
- `internal/client/membercsr`: `FuzzMemberCSR`, public requests or malformed data only.
- `internal/clientwasm`: `FuzzWASMRequest`, public hex requests or malformed data only.
- `internal/client/reviewerkey`: `FuzzReviewerKeyPayload`.

Key-payload seeds contain only malformed non-key data and public DER structure.
CLI seeds are synthetic, not credentials. Never retain real passwords or private
key fixtures.

Backup, key, and CLI unit tests use real profile costs, not reduced-cost test
profiles. Key tests generate keys at runtime and clear accessible owned buffers;
opaque library copies cannot be explicitly cleared. Generic backup tests use
synthetic non-key payloads; CLI filesystem tests use non-key stand-ins.

Unsafe-file fixtures set and verify their final permissions after creation so
CI's restrictive `umask 077` cannot make a public-file case owner-only. Tests do
not change the process-wide mask while parallel tests run. Reproduce CI defaults
locally with `BASH_ENV="$PWD/scripts/ci-shell.sh" bash -c 'make check'`.

The keystore's single `G407` annotation documents a scanner false positive:
`NewGCMWithRandomNonce` requires an empty nonce argument and generates the nonce
itself. `TestKeystoreFreshRandomness` and `TestKeystoreLibraryCompatibility` check
its nonce-prefix behavior. Production code does not use ordinary fixed-nonce GCM.

### Implemented test mapping

| Area | Tests |
| --- | --- |
| Configuration | `TestConfig`, `TestConfigSourceURL`, `TestRunFailures` |
| Routing and input isolation | `TestInfrastructureRoutes`, `TestInfrastructureMethods`, `TestUnavailableRoutesRespectServiceBoundary`, `TestInfrastructureDoesNotReadOrReflectRequestData`, `TestServeRejectsBodyBeforeContinue` |
| Lifecycle and limits | `TestServeLifecycle`, `TestServePropagatesCancellationToRequests`, `TestServeClosesUnresponsiveRequests`, `TestServeListenerFailureClosesRequests`, `TestConnectionLimitAndClose`, `TestServerBounds` |
| Shell paths, development gate, SRI, headers, methods, HEAD, no body reads/reflection | `TestSite`, `TestStylesheetIntegrity`, `TestSiteRejectsBrokenAssets`, `TestWebServiceBoundary`, `TestWebDelivery`, `TestDevelopmentStyleGuideFlag` |
| Rejection of scripts, handlers, remote assets, active controls, malformed markup, wrong asset hashes | `scripts/test_web_check.py` |
| Device-backup size, purpose, version/profile, reserved-byte and length validation before KDF work | `TestKeystoreRejectsInvalidInputs`, `TestKeystoreRejectsUnsafeParameters`, `FuzzBackup` |
| Backup round trips, owned buffers, fresh salt/nonce, wrong passwords, header/ciphertext tampering, independent library composition | `TestKeystoreRoundTrip`, `TestKeystoreFreshRandomness`, `TestKeystoreRejectsTampering`, `TestKeystoreLibraryCompatibility` |
| Backup cancelled/queued calls, cancellation at admission/derivation/output boundaries, and concurrent derivation admission | `TestKeystoreCancellation`, `TestKeystoreCancellationBoundaries`, `TestKeystoreConcurrent` |
| Fresh member keys, usable signatures, backup round trips, buffer ownership, fresh exports, independent library encoding | `TestMemberKeyGenerate`, `TestMemberKeyRoundTrip`, `TestMemberKeyLibraryCompatibility` |
| Invalid member keys/passwords, authenticated non-key or wrong-algorithm payloads, noncanonical DER, wrong purpose/password, ciphertext tampering | `TestMemberKeyRejectsInvalidInputs`, `TestMemberKeyRejectsInvalidPayloads`, `TestMemberKeyRejectsUnauthenticatedBackup`, `FuzzMemberKeyPayload` |
| Member-key cancellation at entry/output and concurrent shared-key export/import | `TestMemberKeyCancellation`, `TestMemberKeyConcurrent` |
| Fresh reviewer keys, library key agreement, backup ownership, fresh exports, independent PKCS #8 composition, preserved private encoding | `TestReviewerKeyGenerate`, `TestReviewerKeyRoundTrip`, `TestReviewerKeyLibraryCompatibility`, `TestReviewerKeyPreservesEncoding` |
| Invalid reviewer inputs, authenticated wrong-algorithm/non-key payloads, noncanonical DER, wrong passwords/purposes, ciphertext tampering, cross-wrapper purpose isolation | `TestReviewerKeyRejectsInvalidInputs`, `TestReviewerKeyRejectsInvalidPayloads`, `TestReviewerKeyRejectsUnauthenticatedBackup`, `TestReviewerKeyPurposeIsolation`, `FuzzReviewerKeyPayload` |
| Reviewer-key cancellation at entry/output and concurrent shared-key export/import | `TestReviewerKeyCancellation`, `TestReviewerKeyConcurrent` |
| CLI argument validation, bounded opaque password framing/confirmation, pipe and non-device stdin, help and secret-free failures | `TestClientArguments`, `TestClientPasswordInput`, `TestClientPasswordPipe`, `TestClientFailsClosed`, `FuzzClientArguments`, `FuzzClientPassword` |
| Offline generation/import through the shared profiles; exact public-only output; wrong password/purpose and ciphertext tampering | `TestClientRoundTrip` |
| Owner-only files/directories, bounded regular-file imports, symlink/dangling-symlink rejection, no overwrite and complete concurrent publication | `TestClientBackupFiles`, `TestClientBackupRejectsUnsafePaths`, `TestClientBackupConcurrentPublication` |
| Cancelled pipe reads, inherited stdin in a subprocess, file operations before/after publication, temporary-file cleanup | `TestClientPasswordPipeCancellation`, `TestClientInheritedPipeCancellation`, `TestClientBackupCancellation` |
| Rewrap opaque password framing, confirmation, bounds, owned outputs, and no partial passwords on failure | `TestClientRewrapPasswords`, `FuzzClientRewrapPasswords` |
| Rewrap exact private/public-key preservation, fresh salt/nonce, old-password rejection, unchanged source and no overwrite | `TestClientRewrapRoundTrip`, `TestClientRewrapConcurrent` |
| Rewrap wrong passwords/purposes, malformed/tampered/authenticated non-key backups, secret-free failures, cancellation and no output on failure | `TestClientRewrapRejectsInvalidBackup`, `TestClientRewrapCancellation`, `TestClientRewrapFailsClosed` |
| Member CSR library verification, deterministic fixed profile, buffer ownership, invalid/inconsistent keys, extra claims, algorithms, byte mutations, cancellation, concurrent calls | `TestMemberCSRRoundTrip`, `TestMemberCSRRejectsInvalidKeys`, `TestMemberCSRRejectsInvalidRequests`, `TestMemberCSRCancellation`, `TestMemberCSRConcurrent`, `FuzzMemberCSR` |
| CLI member CSR exact public DER, unchanged backup, wrong password/purpose, authenticated non-key or tampered input, secret-free errors, cancellation, help, short/failed writes | `TestClientCSRRoundTrip`, `TestClientCSRRejectsInvalidBackup`, `TestClientCSRFailsClosed`, `TestClientArguments`, `FuzzClientArguments` |
| CSR file export matching stdout, direct password-free verification, owner-only no-replace publication, unchanged backup/destination, unsafe paths, cancellation before/after publication, concurrent export and cleanup | `TestClientCSRRoundTrip`, `TestClientCSRFileRejectsUnsafePaths`, `TestClientCSRFileCancellation`, `TestClientCSRFileConcurrentPublication`, `TestClientCSRRejectsInvalidBackup`, `TestClientArguments`, `FuzzClientArguments` |
| Password-free CSR verification, exact matching public key, concurrent calls, unchanged input, malformed/claimed/tampered requests, owner-only bounded files, symlink rejection, cancellation and short/failed writes | `TestClientVerifyCSRRoundTrip`, `TestClientVerifyCSRRejectsInvalidRequests`, `TestClientVerifyCSRRejectsUnsafeFiles`, `TestClientVerifyCSRFailsClosed`, `TestClientCSRRoundTrip`, `FuzzClientArguments`, `FuzzMemberCSR` |
| WASM adapter valid/malformed hex, shared profile rejection, every-byte request mutations, concurrent native calls, bounded fuzzing | `TestWASMVerifyCSR`, `TestWASMVerifyCSRRejectsInvalidInput`, `FuzzWASMRequest` |
| Actual WASM bridge, type/arity/size rejection without object coercion, native/public result parity, shutdown and namespace collisions | `TestClientNativeWASMCompatibility` with `scripts/wasm_test.mjs`, through `make wasm-test` |
| Reviewed loader/notice digest rejection, invalid artifact headers and size bounds | `scripts/test_build_wasm.py` |

These establish neither database isolation, anonymity, nor protocol attack results.
Web checks validate allowlists/delivery, not full HTML/CSS grammar or browser execution.
The shell loads no JavaScript. Screenshots, actual CSP enforcement, keyboard access, assistive
technology, contrast, and print rendering remain untested.

Native backup costs can be measured with:

```sh
go test ./internal/client/keystore -run='^$' -bench=BenchmarkKeystore -benchmem
```

This measures the full 64 MiB, three-pass profile, not a weakened test substitute.
Browser costs, private-key/backup native/WASM compatibility, independent cryptographic review,
independent file-custody review, certificate/enrollment integration, and end-to-end device
confidentiality remain untested. Reviewer round binding, expiry enforcement, and
envelope-decryption workflows are not implemented.

### WASM verifier checks

`make wasm-test` requires Node.js 22.23.3 on `PATH`, in addition to the pinned Go
toolchain. No npm installation is needed. `make check` includes this target; CI
installs the pinned external runtime. `make wasm` needs only Go and Python.

`TestClientNativeWASMCompatibility` generates three fresh member requests natively,
checks their expected public keys, and sends only public hex requests/results to
the actual built WASM module. It checks both hex cases, every-byte mutations,
extra claims, malformed inputs, bridge argument types/arity, oversized strings,
hostile objects, shutdown, and namespace collisions. The runner verifies artifact
hashes before loading and rejects unexpected `fetch` calls. Failures and missing
tools/artifacts fail the target; it does not skip unavailable checks.

The Go JS/WASM runner also executes adapter unit tests and fuzz seeds. Native race
coverage does not instrument WASM; Node execution is not browser, CSP, accessibility,
private-key interoperability, or independent security evidence. Loader and compiler
must match under the official [Go WASM guidance](https://go.dev/wiki/WebAssembly)
(accessed 2026-10-27). See the [interface](key-management.md#local-wasm-request-verification)
and [dependency review](dependencies.md#wasm-runtime-support).

## Required runtime command contract

The [current targets](#current-executable-checks) cover infrastructure, shared key
packages, the offline CLI, and the inert shell. As components are added, build
every command with the pinned stable toolchain, retain failing fuzz inputs, and
extend security checks with dependency review. Extend `web-lint` for future
JavaScript and full syntax validation.

**Every target below is required but unavailable.** See [roadmap](roadmap.md).

| Target | Required behavior |
| --- | --- |
| `make db-test` | Migrations, privileges, concurrency, backup/restore on real PostgreSQL |
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
  requirements. No version is selected yet; select and record an official release
  before mapping controls. Test login, factor enrollment, recovery, session
  rotation, and expiry.
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
| Restored expired round key | Controlled backup restoration rejects active reuse | `TestRetentionRejectsExpiredKeyRestore` |

## Fuzz plan

- Fuzz enrollment CSV, form schemas, keystore headers, certificate/CRL wrappers,
  tokens/envelopes, bulletin canonicalization, and receipt proofs.
- Share native/WASM decoding tests. Bound allocation, recursion, input size, and work.
- License synthetic regression inputs. Never retain real secrets in crash corpora.

CI durations and publication rules are owned by [CI/CD](ci-cd.md).

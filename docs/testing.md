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
| `make fuzz` | `FuzzConfig`, `FuzzLookup`, `FuzzBackup`, `FuzzMemberKeyPayload`, `FuzzReviewerKeyPayload`, `FuzzClientArguments`, `FuzzClientPassword`, and `FuzzClientRewrapPasswords`, two workers, 15 seconds each; override with `FUZZTIME` |
| `make vuln` | govulncheck, gosec, module verification/inventory, redacted current-file Gitleaks scan |
| `make web-lint` | Build/start loopback submission with/without development flag; inert markup, headings/landmarks, fragment/description targets, links, CSS restrictions, asset hashes, headers, unavailable protocol/readiness, bounded shutdown |

- Signal handling also requires manual execution checks; coverage is not lifecycle evidence.
- Fuzz configuration input is capped at 8192 bytes before parsing, with separate
  listen/source-URL limits. Retained failures belong in
  `internal/service/testdata/fuzz/FuzzConfig` or `internal/web/testdata/fuzz/FuzzLookup`.
  Review and license corpora before committing.
- Backup fuzzing caps input at the maximum backup size plus one byte, exercises
  only the allocation-free structural parser, and never invokes Argon2id. Retain
  licensed synthetic failures in `internal/client/keystore/testdata/fuzz/FuzzBackup`.
  Unit tests use real profile costs and synthetic non-key payloads; no private
   key fixtures or reduced-cost test profiles exist.
- Member-key fuzzing caps payloads at 49 bytes and bounds ASN.1 parsing to the
  48-byte profile. It performs no KDF work; seeds contain only malformed non-key
  data and public DER structure. Review and license synthetic failures before
  retaining them in `internal/client/memberkey/testdata/fuzz/FuzzMemberKeyPayload`.
  Member-key unit tests generate keys at runtime, clear accessible owned buffers,
  and use real backup costs. No private key fixtures are retained.
- Reviewer-key fuzzing applies the same 49-byte input cap and 48-byte ASN.1 bound,
  without KDF work. Seeds contain only malformed non-key data and public DER
  structure. Review and license synthetic failures before retaining them in
  `internal/client/reviewerkey/testdata/fuzz/FuzzReviewerKeyPayload`. Unit tests
  generate keys at runtime, clear accessible private bytes, and use real backup
  costs. Opaque library key copies cannot be cleared through their public API.
- The keystore's single `G407` annotation documents a scanner false positive:
  `NewGCMWithRandomNonce` requires an empty nonce argument and generates the nonce
  itself. `TestKeystoreFreshRandomness` and `TestKeystoreLibraryCompatibility`
  check this API's nonce-prefix behavior; ordinary fixed-nonce GCM is not used
  in production code.
- CLI fuzzing caps argument input at 8193 bytes, ordinary password framing at 2051
  bytes, and rewrap password framing at 3076 bytes,
  with no file, network, or KDF work. Seeds are explicitly synthetic, not credentials.
  Never retain real password material in corpora. CLI unit tests exercise actual
  profile costs and runtime-generated keys; filesystem tests use non-key stand-ins.
- `.gitleaks.toml` excludes only Git internals and disposable tool/build outputs.
  Module inventory supports manual review, not automatic license approval.
  See [dependencies](dependencies.md) for device-backup modules and pins/admission.

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

These establish neither database isolation, anonymity, nor protocol attack results.
Web checks validate allowlists/delivery, not full HTML/CSS grammar or browser execution.
No JavaScript exists. Screenshots, actual CSP enforcement, keyboard access, assistive
technology, contrast, and print rendering remain untested.

Native backup costs can be measured with:

```sh
go test ./internal/client/keystore -run='^$' -bench=BenchmarkKeystore -benchmem
```

This measures the full 64 MiB, three-pass profile, not a weakened test substitute.
Browser costs, native/WASM compatibility, independent cryptographic review,
independent file-custody review, certificate/enrollment integration, and end-to-end device
confidentiality remain untested. Reviewer round binding, expiry enforcement, and
envelope-decryption workflows are not implemented.

## Required runtime command contract

Build/test/lint/fuzz/vuln cover infrastructure, the shared backup/member/reviewer-key foundation,
and the offline key CLI;
web-lint covers the inert shell.
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
| Native/WASM format or vector mismatch | Compatibility gate fails | `TestClientNativeWASMCompatibility` |
| Restored expired round key | Controlled backup restoration rejects active reuse | `TestRetentionRejectsExpiredKeyRestore` |

## Fuzz plan

- Fuzz enrollment CSV, form schemas, keystore headers, certificate/CRL wrappers,
  tokens/envelopes, bulletin canonicalization, and receipt proofs.
- Share native/WASM decoding tests. Bound allocation, recursion, input size, and work.
- License synthetic regression inputs. Never retain real secrets in crash corpora.

CI durations and publication rules are owned by [CI/CD](ci-cd.md).

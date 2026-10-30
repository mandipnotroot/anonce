<!-- SPDX-FileCopyrightText: 2026 Anonce Contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Testing and evidence

Audience: contributors and security reviewers.

## Current executable checks

### Connected browser MVP checks

`make browser-test` builds the commands and both matched WASM artifacts, then runs
`TestBrowserMVP` with real Chromium WebAuthn ceremonies, two fresh real PostgreSQL
instances, owner-applied migrations and actual runtime roles. It is opt-in, not
part of `make check`, and fails rather than skips missing prerequisites. Supply
the reviewed `MEMBER_BROWSER` executable, Node.js 22.23.3 on `PATH`, and
`BROWSER_TEST_PG` pointing to PostgreSQL 18.6's `bin` directory.

Run it inside an OS sandbox with isolated loopback networking, an empty allowlisted
environment, read-only source/toolchains, scratch-only writes and explicit CPU,
memory, process, disk/file and wall-clock limits. Never use existing databases.
Trust authentication applies only to its disposable synthetic clusters; application
startup uses independent SCRAM runtime credentials. Test TLS trust pins the fresh
test certificate public keys, never disabling verification globally. Browser
sandboxing, CSP, WebAuthn verification, protected cookies and CSRF remain enabled.

The driver uses Chromium's standard virtual-authenticator interface for real
registration/assertion verification. There is no test login endpoint or server
success bypass. It exercises administrator publication, member worker/vault and
enrollment, exact-origin handoff, blind finalization, anonymous encryption and
signed acceptance, concurrent exact retries, conflicting spending and authorized
local reviewer decryption. Wire inspection rejects passphrases, plaintext answers,
account cookies/referrers and unexpected origins. PostgreSQL subtests cover
persistence, isolation, grants, enrollment races and quota persistence across sessions.

Session checks use two independently authenticated browser contexts and a shared
partition tab, inspect session-control accessible names and activate verification
with Enter. Real passkey reauthentication changes the current selector without
extending expiry or changing siblings, rejects login-purpose confusion, and leaves
local member keys locked. Selected revocation and confirmed sign-out everywhere
exercise foreground invalidation, same-partition state clearing, later verified
sign-in and unchanged encrypted backup storage. Synthetic virtual authenticators
share test credentials with synchronized counters; no authentication bypass is added.

`session-management-http` exercises actual TLS/CSRF and runtime-role storage for
bounded metadata, absent/revoked bearers, current/foreign/stale selectors, historical
authentication rejection and account-isolated sign-out. Existing account-store
PostgreSQL tests retain lock-wait, race and cancellation coverage. The separate
`make browser-session-test`, also in `make check`, runs Node lifecycle tests for
confirmation, single-flight actions, local locking, uncertain failures, no automatic
retry, delayed-result rejection, visible-page observation and bounded inventory
validation. `TestSessionHTTPAdmission` and `FuzzSessionSelectorHTTP` exercise bounded
HTTP selector admission without a database; the fuzz target is included in `make fuzz`.
The nested `reauthentication-binding-and-consumption` HTTP case rejects swapped
same-account bearers, missing bearers, login-purpose confusion, malformed/replayed
assertions and revocation during a ceremony without changing remaining sessions.

These checks do not demonstrate instantaneous remote erasure, offline/suspended-page
cleanup, a supported-browser matrix or manual accessibility approval.

Native `TestProfileJourney`, `TestEnvelopeIsolation`, `TestBulletinBounds`,
`FuzzProfileRejection`, `TestIdentityGate`, `TestCookieEncoding` and
`TestAuthenticationLimiter` cover composition/admission. Existing member worker and
session checks cover cancellation, wrong expected keys and invalid backups. These
checks are not independent review, a supported-browser/provider matrix, mobile
costs, manual accessibility, protected signer custody, safe database restoration
or public transparency-log evidence.

`TestSignedTimestampBounds` rejects correctly signed out-of-profile dates before
integer conversion. `TestStateFileAdmission` and `TestInitializationDoesNotReplace`
cover scoped state files, owner-only permissions, rejected symlinks and no-replace
initialization. `TestBoundedTLSMetadata` checks that connection limiting preserves
the TLS metadata required by the HTTP gate. Embedded page tests check strict
runtime manifests, entry-asset integrity and origin-specific content policies.

`make browser-unit-test`, also included in `make check` and runtime CI, checks that
one malformed or undecryptable answer does not suppress later records or pages.
It checks plaintext-buffer cleanup and stops without publishing late results when
the reviewer owner closes, is replaced, becomes hidden, or reaches round expiry.
These Node checks do not replace the real-browser journey.

The journey also passes a corrupted envelope followed by an actual stored answer
through the shared reader and real reviewer worker. It requires a rejection
placeholder followed by the correctly decrypted answer, and checks that reaching
the review deadline terminates the actual worker.

See [commands](../AGENTS.md#commands) and [setup](../CONTRIBUTING.md).
The original foundation targets below do not test the connected browser protocol.

| Target | Current checks |
| --- | --- |
| `make build` | Default browser services, matched member/reviewer runtimes, original notices and operator tools with Go 1.27.3; excludes the user key CLI and inert demo servers |
| `make dev-tools` | Explicit developer-only CLI and inert-shell regression binaries, never the application image or a product workflow |
| `make test` | `go test -race -coverprofile=coverage/out ./...` and statement coverage report; no native-package exclusions, including wrappers and signal handling. JS-only code is checked separately below |
| `make lint` | Native and WASM entry-point vet, pinned gofumpt/golangci-lint, tidy diff, module verification |
| `make fuzz` | `FuzzMigrationAdmission`, `FuzzConfig`, `FuzzContainerListen`, `FuzzLookup`, `FuzzBackup`, `FuzzMemberKeyPayload`, `FuzzMemberCSR`, `FuzzMemberSessionUnlockInputs`, `FuzzMemberWASMSizes`, `FuzzMemberBrowserManifest`, `FuzzWASMRequest`, `FuzzWASMExpectedKey`, `FuzzReviewerKeyPayload`, `FuzzClientArguments`, `FuzzClientPublicKeyLine`, `FuzzClientPassword`, and `FuzzClientRewrapPasswords`, two workers, 15 seconds each; override with `FUZZTIME` |
| `make vuln` | govulncheck, gosec, module verification/inventory, redacted current-file Gitleaks scan |
| `make web-lint` | Build/start loopback submission with/without development flag; inert markup, headings/landmarks, fragment/description targets, links, CSS restrictions, asset hashes, headers, unavailable protocol/readiness, bounded shutdown |
| `make wasm` | Go `js/wasm` public-request verifier; matching reviewed loader/notices, SHA-256 manifest, 8 MiB uncompressed size gate |
| `make wasm-test` | Rebuild artifacts, compare native and Node WASM public-request results, exercise the actual bridge, and run adapter unit tests under the Go JS/WASM runner |
| `make member-wasm` | Separate local member-session module, dedicated-worker/client assets, matching reviewed loader/module notices, manifest, and 8 MiB gate |
| `make member-wasm-test` | Native race/lifecycle tests, actual Node direct bridge and dedicated-worker setup/restoration, rejection, termination, bidirectional encrypted-backup compatibility, owner lifecycle unit tests, and bounded command fuzzing |
| `make member-browser-test` | Opt-in pinned headless Chromium, isolated Go test host, native/worker backup compatibility, page CSP probes, event-loop progress, synthetic-clock expiry/restoration, same-origin peer lock, background-tab lock/foreground restoration, and navigation termination; requires `MEMBER_BROWSER`, not included in `make check` or CI |
| `make container-secrets` | Generate/validate separate database secret files without replacing existing files; no Docker daemon required |
| `make container-config` | Validate the real Compose parser's normalized configuration, image pin, loopback publication, networks, secret scopes, volumes, resource bounds, and hardening; requires Docker Compose but not a daemon |
| `make up`, `make smoke`, `make down` | Build/migrate/initialize/start and inspect the default browser application, or stop it without deleting state/database volumes; operator-only commands requiring Docker |
| `make container-test` | Fresh real browser-service containers and PostgreSQL: verified TLS pages/liveness, scoped read-only state/runtime credentials, restart persistence, hardening, grants and cross-instance rejection; disposable synthetic data only |
| `make db-migration-test` | Container checks plus separate embedded Goose histories on real PostgreSQL: failed and repeated/concurrent application, owner/runtime grants, wrong-target rejection, invalid/future histories, and missing boundary marker; disposable synthetic volumes only |
| `make db-account-test` | Migration/container checks plus race-enabled runtime-role account/session persistence, digest-only storage, expiry/cleanup, per-account session limits and concurrent admission, cross-account revocation isolation, concurrent disable, cancellation, SQL constraints/grants, and submission-store rejection |
| `make db-member-backup-test` | Account/migration/container checks plus race-enabled runtime-role member-backup persistence, owner scoping, revision/binding conflicts, tombstones, concurrent writes/disable, cancellation/rollback, constraints/grants, and submission-store rejection |
| `make db-submission-record-test` | Migration/container checks plus race-enabled runtime-role atomic submission records, cross-pool duplicate spends, exact-payload retries, round admission/cancellation, post-lock expiry, rollback, constraints/grants, and identity-store rejection; no token verification or HTTP submission |

- Signal handling also requires manual execution checks; coverage is not lifecycle evidence.
- `.gitleaks.toml` excludes only Git internals and disposable tool/build outputs.
  Module inventory supports manual review, not automatic license approval.
  See [dependencies](dependencies.md) for device-backup modules and pins/admission.

### Parser fuzzing and fixtures

`FuzzSubmissionAdmission` bounds round input to 17 bytes, bulletin/spend digests to
33 bytes, and ciphertext to 65537 bytes. It checks exact admission, unchanged inputs,
and fail-closed storage without database or cryptographic work. It runs in `make fuzz`;
regressions belong in `internal/submission/records/testdata/fuzz/FuzzSubmissionAdmission`.

`make fuzz` also runs `FuzzAccountToken`, bounded to 33 raw bytes, checking exact
32-byte admission and SHA-256 composition without database/network work. Synthetic
regressions belong in `internal/identity/accounts/testdata/fuzz/FuzzAccountToken`.
`FuzzAccountSessionAdmission` additionally bounds account input to 16 bytes and
exercises fixed-width lifetime validation, zero-value failure, and unchanged inputs
without database work. Capacity itself is checked against real PostgreSQL below.

| Parser | Input/work bounds |
| --- | --- |
| Configuration | 8192 bytes before parsing; separate listen/source-URL limits |
| Migration admission | `FuzzMigrationAdmission`: 1025-byte target and 65-byte credential caps; fixed service/hex admission only, no database or network work |
| Member-backup storage admission | `FuzzMemberBackupAdmission`: 33-byte public key, 109-byte envelope, and fixed-width revision; independent exact envelope/revision oracle, no KDF, database, or network work |
| Session-scoped backup admission | `FuzzMemberBackupSessionAdmission`: 33-byte token/public key, 109-byte envelope, fixed-width revision; fail-closed read/write/delete and unchanged token checks, no database or network work |
| Container bind opt-in | `FuzzContainerListen`: 129-byte listen input cap and one Boolean; only native loopback or explicitly opted-in IPv4 unspecified binding |
| Backup structure | Maximum backup size plus one byte; allocation-free parser, no Argon2id |
| Member/reviewer payload | 49-byte input cap, 48-byte ASN.1 profile; no KDF work |
| Member CSR | 130-byte fuzz input cap, 129-byte DER profile; bounded ASN.1 and signature verification, no KDF work |
| Member session admission | 1025-byte password, 65597-byte backup, and 33-byte expected-key fuzz caps; exercise invalid unlock password/key lengths and locked backup export, no KDF work; backup/payload parsing reuse the shared fuzzed implementations |
| Member WASM admission sizes | Fixed-width integer fuzz inputs for password/backup/key lengths and operation kind; exact member bounds, no allocations or KDF work; byte parsing reuses shared backup/payload validation |
| Browser-test asset manifest | `FuzzMemberBrowserManifest`: 4097-byte cap, exact fixed filename set, bounded synthetic assets, no KDF or network work |
| Member worker transport | `member_worker_test.mjs`: exhaustive byte-size boundary sweep and 2048 generated commands per run, each with at most four views of 1025 elements; independent metadata admission oracle, no KDF or I/O |
| Worker text passphrases | `member_worker_test.mjs`: 2048 generated Unicode strings per run, capped at 1025 UTF-16 units, checked against independent UTF-8 round-trip/byte-size admission; no KDF or I/O |
| WASM request adapter | 259-byte request fuzz input cap, exact 258-byte ASCII hex representation before bounded shared CSR parsing; expected-key fuzzing also caps the key input at 65 bytes for an exact 64-byte ASCII hex representation; no KDF work |
| CLI arguments | 8193-byte fuzz input cap; no file, network, or KDF work |
| CLI expected-key record | 75-byte data and 9-byte kind fuzz caps; exact 72/74-byte lowercase kind-tagged lines, no file, network, or KDF work |
| CLI password framing | 2051 bytes for ordinary framing, 3076 for rewrap; no file, network, or KDF work |

Review and license synthetic regression inputs before committing. Retain failures
in the relevant package's `testdata/fuzz/<target>` directory:

- `internal/service`: `FuzzConfig` and `FuzzContainerListen`.
- `internal/dbmigrate`: `FuzzMigrationAdmission`, synthetic nonsecret admission only.
- `internal/identity/memberbackup`: `FuzzMemberBackupAdmission`, public envelope
  structure and synthetic nonsecret bytes only.
- `internal/web`: `FuzzLookup`.
- `internal/client/keystore`: `FuzzBackup`.
- `internal/client/memberkey`: `FuzzMemberKeyPayload`.
- `internal/client/membercsr`: `FuzzMemberCSR`, public requests or malformed data only.
- `internal/client/membersession`: `FuzzMemberSessionUnlockInputs` and
  `FuzzMemberSessionConfirmation`, synthetic
  admission inputs only; no real passwords or private-key fixtures.
- `internal/clientwasm`: `FuzzWASMRequest` and `FuzzWASMExpectedKey`, public hex
  requests/expected keys or malformed data only.
- `internal/memberwasm`: `FuzzMemberWASMSizes`, integer admission bounds only;
  `FuzzMemberBrowserManifest`, synthetic manifests only.
- `internal/client/reviewerkey`: `FuzzReviewerKeyPayload`.
- `internal/clientcli`: `FuzzClientArguments`, `FuzzClientPublicKeyLine`,
  `FuzzClientPassword`, and `FuzzClientRewrapPasswords`.

Key-payload seeds contain only malformed non-key data and public DER structure.
CLI seeds are synthetic, not credentials. Never retain real passwords or private
key fixtures.

Backup, key, and CLI unit tests use real profile costs, not reduced-cost test
profiles. Key tests generate keys at runtime and clear accessible owned buffers;
opaque library copies cannot be explicitly cleared. Generic backup tests use
synthetic non-key payloads; CLI filesystem tests use non-key stand-ins.

Member-key and reviewer-key suites share backup contract checks in
`internal/client/internal/keytest`. Algorithm-specific validation and compatibility
tests stay in each wrapper. Wrapper cancellation tests exercise every observed
checkpoint rather than hard-coded nested call counts; the keystore suite retains
explicit admission, derivation, and output-boundary checks. CLI publication tests
share destination snapshots while retaining their command and unsafe-path cases.

Unsafe-file fixtures set and verify their final permissions after creation so
CI's restrictive `umask 077` cannot make a public-file case owner-only. Tests do
not change the process-wide mask while parallel tests run. Reproduce CI defaults
locally with `BASH_ENV="$PWD/scripts/ci-shell.sh" bash -c 'make check'`.

The keystore uses the library's RFC 8439 ChaCha20-Poly1305 AEAD with explicit
`crypto/rand` nonces and one export per freshly salted derived key.
`TestKeystoreFreshRandomness` and `TestKeystoreLibraryCompatibility` check the
profile-2 nonce prefix and library composition.

### Implemented test mapping

| Area | Tests |
| --- | --- |
| Submission storage bounds, schedule precision/order, nil/zero-value failure, cancellation, unchanged inputs, and bounded fuzzing | `TestSubmissionAdmission`, `TestSubmissionUnavailableAndCancellation`, `FuzzSubmissionAdmission` |
| Configuration | `TestConfig`, `TestConfigSourceURL`, `TestRunFailures`, `TestContainerNetwork`, `TestContainerNetworkFlag`, `FuzzContainerListen` |
| Migration service/credential/command bounds, cancelled/concurrent calls, regular-file/symlink/FIFO rejection, separate embedded files, and bounded admission fuzzing | `TestMigrationAdmission`, `TestMigrationCancellation`, `TestMigrationCredentialFiles`, `TestMigrationFiles`, `FuzzMigrationAdmission` |
| Account lifetime/token/cleanup admission, zero-value failure, concurrent cancelled calls, digest composition and unchanged inputs | `TestAccountAdmission`, `TestAccountUnavailableAndCancellation`, `TestAccountTokenDigest`, `FuzzAccountToken`, `FuzzAccountSessionAdmission` |
| Member-backup envelope bounds/profile/purpose, revision/key and session-token admission, zero-value failure, concurrent cancelled calls, and unchanged inputs | `TestMemberBackupEnvelope`, `TestMemberBackupAdmission`, `TestMemberBackupUnavailableAndCancellation`, `TestMemberBackupSessionAdmission`, `FuzzMemberBackupAdmission`, `FuzzMemberBackupSessionAdmission` |
| Fixed-target local liveness probe, exact bounded body/status, no redirect/credentials, response-header limit, cancellation, and unavailable targets | `TestProbe`, `TestProbeCancellationAndFailures` |
| No-replace/distinct secret generation, existing-file preservation, directory/file permissions, malformed/missing/duplicate files, symlinks/FIFOs, engine version boundary, and unsafe normalized Compose model rejection | `scripts/test_containers.py`, included in `make policy-test` |
| Routing and input isolation | `TestInfrastructureRoutes`, `TestInfrastructureMethods`, `TestUnavailableRoutesRespectServiceBoundary`, `TestInfrastructureDoesNotReadOrReflectRequestData`, `TestServeRejectsBodyBeforeContinue` |
| Lifecycle and limits | `TestServeLifecycle`, `TestServePropagatesCancellationToRequests`, `TestServeClosesUnresponsiveRequests`, `TestServeListenerFailureClosesRequests`, `TestConnectionLimitAndClose`, `TestServerBounds` |
| Shell paths, development gate, SRI, headers, methods, HEAD, no body reads/reflection | `TestSite`, `TestStylesheetIntegrity`, `TestSiteRejectsBrokenAssets`, `TestWebServiceBoundary`, `TestWebDelivery`, `TestDevelopmentStyleGuideFlag` |
| Rejection of scripts, handlers, remote assets, active controls, malformed markup, wrong asset hashes | `scripts/test_web_check.py` |
| Device-backup size, purpose, version/profile, reserved-byte and length validation for both key purposes before KDF work, without output or input mutation | `TestKeystoreRejectsInvalidInputs`, `TestKeystoreRejectsUnsafeParameters`, `FuzzBackup` |
| CLI inspection, rewrapping, and member CSR rejection of unsupported profiles without stdout, files, input mutation, or sensitive error reflection | `TestClientRejectsUnsupportedBackup` |
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
| Optional backup expected-key matching for member/reviewer keys, either-case hex, malformed/repeated flag rejection before stdin/file access, mismatches without output, unchanged source, concurrent calls, cancellation, failed/short writes, authenticated non-key rejection, and rewrapped-key checks | `TestClientExpectedPublicKeyArguments`, `TestClientInspectExpectedKey`, `TestClientInspectExpectedKeyRejectsInvalidPayload`, `TestClientRoundTrip`, `TestClientRewrapRoundTrip`, `FuzzClientArguments` |
| Owner-only files/directories, bounded regular-file imports, symlink/dangling-symlink rejection, no overwrite and complete concurrent publication | `TestClientBackupFiles`, `TestClientBackupRejectsUnsafePaths`, `TestClientBackupConcurrentPublication` |
| Cancelled pipe reads, inherited stdin in a subprocess, file operations before/after publication, temporary-file cleanup | `TestClientPasswordPipeCancellation`, `TestClientInheritedPipeCancellation`, `TestClientBackupCancellation` |
| Rewrap opaque password framing, confirmation, bounds, owned outputs, and no partial passwords on failure | `TestClientRewrapPasswords`, `FuzzClientRewrapPasswords` |
| Rewrap exact private/public-key preservation, fresh salt/nonce, old-password rejection, unchanged source and no overwrite | `TestClientRewrapRoundTrip`, `TestClientRewrapConcurrent` |
| Rewrap wrong passwords/purposes, malformed/tampered/authenticated non-key backups, secret-free failures, cancellation and no output on failure | `TestClientRewrapRejectsInvalidBackup`, `TestClientRewrapCancellation`, `TestClientRewrapFailsClosed` |
| Optional rewrap expected-key matching for both kinds, either-case hex, malformed/repeated flags rejected before stdin/file access, mismatch rejection before replacement encryption or file creation, unchanged source, preserved keys, no overwrite, cancellation and concurrent matching | `TestClientExpectedPublicKeyArguments`, `TestClientRewrapExpectedKey`, `TestClientRewrapRejectsInvalidBackup`, `TestClientRewrapCancellation`, `TestClientRewrapConcurrent`, `FuzzClientArguments` |
| Member CSR library verification, deterministic fixed profile, buffer ownership, invalid/inconsistent keys, extra claims, algorithms, byte mutations, cancellation, concurrent calls | `TestMemberCSRRoundTrip`, `TestMemberCSRRejectsInvalidKeys`, `TestMemberCSRRejectsInvalidRequests`, `TestMemberCSRCancellation`, `TestMemberCSRConcurrent`, `FuzzMemberCSR` |
| In-memory automatic member setup/restoration, profile compatibility, public-output ownership, fresh generation, opaque bounded passwords, invalid inputs/backups, every-byte expected-key mismatches, unchanged inputs, state admission, owned-key clearing, cancellation at installation boundaries, pending lock with a blocked derivation slot, and concurrent setup/request/lock | `TestMemberSessionRoundTrip`, `TestMemberSessionFreshSetup`, `TestMemberSessionPasswordOwnership`, `TestMemberSessionRejectsInvalidInputs`, `TestMemberSessionUnlockRejectsBackup`, `TestMemberSessionExpectedKey`, `TestMemberSessionState`, `TestMemberSessionCancellation`, `TestMemberSessionPendingLock`, `TestMemberSessionConcurrent`, `FuzzMemberSessionUnlockInputs` |
| Unlocked encrypted-backup export, exact private-key preservation, fresh salt/nonce, unchanged password/profile, old-backup validity, locked/busy/invalid admission, temporary-key ownership, pending cancel/lock without output, publication-boundary ciphertext clearing, retained key after operation cancellation, and concurrent export/lock | `TestMemberSessionBackup`, `TestMemberSessionBackupState`, `TestMemberSessionBackupCancellation`, `TestMemberSessionBackupPublication`, `TestMemberSessionBackupConcurrent`, `FuzzMemberSessionUnlockInputs` |
| Confirmed setup/export, minimum/maximum opaque matching bytes, mismatched lengths/contents, bounds, no output or state change on mismatch, unchanged inputs, preserved key/profile, busy/locked rejection, cancellation before/after confirmation, and pending lock | `TestMemberSessionConfirmation`, `TestMemberSessionRejectsConfirmation`, `TestMemberSessionConfirmationStateAndCancellation`, `TestMemberSessionPendingLock`, `TestMemberSessionBackupCancellation`, `FuzzMemberSessionConfirmation` |
| CLI member CSR exact public DER, unchanged backup, wrong password/purpose, authenticated non-key or tampered input, secret-free errors, cancellation, help, short/failed writes | `TestClientCSRRoundTrip`, `TestClientCSRRejectsInvalidBackup`, `TestClientCSRFailsClosed`, `TestClientArguments`, `FuzzClientArguments` |
| CSR file export matching stdout, direct password-free verification, owner-only no-replace publication, unchanged backup/destination, unsafe paths, cancellation before/after publication, concurrent export and cleanup | `TestClientCSRRoundTrip`, `TestClientCSRFileRejectsUnsafePaths`, `TestClientCSRFileCancellation`, `TestClientCSRFileConcurrentPublication`, `TestClientCSRRejectsInvalidBackup`, `TestClientArguments`, `FuzzClientArguments` |
| Optional CSR expected-key matching for stdout/file output, either-case hex, malformed/repeated flags rejected before stdin/file access, mismatches without output/files, unchanged source/profile, no overwrite, typed validation, short/failed writes, cancellation and concurrent publication | `TestClientExpectedPublicKeyArguments`, `TestClientCSRExpectedKey`, `TestClientCSRRejectsInvalidBackup`, `TestClientCSRFileCancellation`, `TestClientCSRFileConcurrentPublication`, `FuzzClientArguments` |
| Password-free CSR verification, exact matching public key, concurrent calls, unchanged input, malformed/claimed/tampered requests, owner-only bounded files, symlink rejection, cancellation and short/failed writes | `TestClientVerifyCSRRoundTrip`, `TestClientVerifyCSRRejectsInvalidRequests`, `TestClientVerifyCSRRejectsUnsafeFiles`, `TestClientVerifyCSRFailsClosed`, `TestClientCSRRoundTrip`, `FuzzClientArguments`, `FuzzMemberCSR` |
| Optional expected-key checking, either-case bounded hex, malformed/empty/repeated flag rejection before file access, every-byte key mismatches without output, and unchanged profile/signature checks | `TestClientExpectedPublicKeyArguments`, `TestClientVerifyCSRExpectedKey`, `TestClientVerifyCSRRoundTrip`, `TestClientVerifyCSRRejectsInvalidRequests`, `TestClientVerifyCSRFailsClosed`, `FuzzClientArguments` |
| Optional inspection/request-verification public-key file export, exact public-only lines, unchanged input, owner-only/no-replace paths, no stdout fallback, validation and expected-key checks before file creation, cancellation before/after publication, concurrent publication and cleanup | `TestClientPublicKeyFileArguments`, `TestClientPublicKeyFile`, `TestClientPublicKeyFileValidation`, `TestClientPublicKeyFileRejectsUnsafePaths`, `TestClientPublicKeyFileCancellation`, `TestClientPublicKeyFileConcurrentPublication`, `TestClientInspectExpectedKeyRejectsInvalidPayload`, `TestClientVerifyCSRRejectsInvalidRequests`, `TestClientExpectedPublicKeyArguments`, `FuzzClientArguments` |
| Expected-key file argument conflicts/bounds before file or stdin access, canonical kind-specific records, direct reuse of exports for all supported commands, mismatch and invalid-subject rejection, unchanged sources, no overwrite, unsafe files, cancellation, concurrent calls, and bounded record fuzzing | `TestClientExpectedKeyFileArguments`, `TestClientPublicKeyLine`, `TestClientExpectedKeyFile`, `TestClientExpectedKeyFileValidation`, `TestClientExpectedKeyFileRejectsUnsafePaths`, `TestClientExpectedKeyFileCancellation`, `TestClientExpectedKeyFileConcurrent`, `FuzzClientArguments`, `FuzzClientPublicKeyLine` |
| WASM adapter valid/malformed hex, shared profile rejection, every-byte request mutations, concurrent native calls, bounded fuzzing | `TestWASMVerifyCSR`, `TestWASMVerifyCSRRejectsInvalidInput`, `FuzzWASMRequest` |
| WASM expected-key matching in either hex case, malformed/empty/oversized keys, every-byte key mismatches, unchanged profile/signature rejection, concurrent calls and bounded two-input fuzzing | `TestWASMVerifyCSRForKey`, `TestWASMVerifyCSRForKeyRejectsInvalidInput`, `FuzzWASMExpectedKey` |
| Actual WASM bridge, type/arity/size rejection without object coercion, native/public result parity, shutdown and namespace collisions | `TestClientNativeWASMCompatibility` with `scripts/wasm_test.mjs`, through `make wasm-test` |
| Member bridge admission, confirmation bounds, cancellation before shared-session entry, cleanup-before-shutdown, repeated lock/close, concurrent lock/admission, and size fuzzing | `TestMemberWASMSizes`, `TestMemberWASMConfirmationSizes`, `TestMemberWASMLifecycle`, `TestMemberWASMConcurrent`, `FuzzMemberWASMSizes` |
| Actual member WASM bridge, opaque passwords, native backup restore, WASM backup opened natively, public CSR validation, wrong password/purpose, corruption/key mismatch, byte types/arity/bounds, hostile objects/shadowed getters, shared/detached arrays, input snapshots, public-output ownership, lock/close and namespace collision | `TestMemberNativeWASMCompatibility` with `scripts/member_wasm_test.mjs`, through `make member-wasm-test` |
| Worker owner single-instance/operation admission, snapshots/transfers, input types/arity/bounds, hostile properties, timeout/termination, late replies, protocol/transport failures, and bounded command fuzzing | Named `node:test` cases in `scripts/member_worker_test.mjs`, through `make member-wasm-test` |
| Ciphertext-only backup export, changed-password restoration, native exact-key/randomness compatibility, input snapshots, locked/invalid rejection, pending disposal/lock, unchanged deadlines, malformed reply rejection, and bounded command fuzzing | `TestMemberNativeWASMCompatibility`, `TestMemberNativeWorkerCompatibility`, named backup/protocol/deadline cases in `scripts/member_worker_test.mjs`, and synthetic export cases in `TestMemberNativeBrowserCompatibility` |
| Actual confirmed bridge/worker setup/export, native key/backup compatibility, mismatch without state change or fallback, dual input snapshots, hostile confirmation getters, invalid types/arity/bounds, terminal cancellation, unchanged deadlines, and bounded transport fuzzing | `TestMemberNativeWASMCompatibility`, `TestMemberNativeWorkerCompatibility`, named confirmed-operation/input/deadline/protocol cases in `scripts/member_worker_test.mjs`, and synthetic confirmation cases in `TestMemberNativeBrowserCompatibility` |
| Worker text UTF-8 preservation, Unicode/byte boundaries, malformed surrogate rejection, no coercion or normalization, shared confirmation, synchronous buffer clearing including partial/failed encoding, missing APIs without fallback, busy/closed rejection, unchanged deadlines, and bounded Unicode generation | Named text passphrase/buffer/API cases in `scripts/member_worker_test.mjs`; actual setup, byte/text restoration, native exact-key export, mismatch state, and cancellation in `TestMemberNativeWorkerCompatibility` and synthetic text cases in `TestMemberNativeBrowserCompatibility` |
| Stable secret-free closure Promise, every terminal path during startup/idle/pending work, failed/denied construction, cleanup before observers, late subscribers, unchanged readiness, no nonterminal settlement, and explicit replacement | Named `node:test` closed Promise cases in `scripts/member_worker_test.mjs`; actual Node worker lock/disposal/failure/expiry observations in `TestMemberNativeWorkerCompatibility` |
| Optional owner abort signal, pre-aborted/invalid admission without resources, startup/idle/pending cancellation, unchanged settled results, ignored reasons/shadowed properties, suppressed-event state checks, listener cleanup, no peer notification, and explicit replacement | Named `node:test` abort cases in `scripts/member_worker_test.mjs`; actual startup/idle/pending cancellation in `TestMemberNativeWorkerCompatibility` and `TestMemberNativeBrowserCompatibility` |
| Delayed startup/operation/lifetime deadline checks on each clock, exact boundaries, pre-admission/busy/reply/visibility rejection, unchanged lifetime after successful work, invalid/missing/failed/backward readings, captured clocks, local cleanup and explicit replacement | Named `node:test` deadline, lifetime, and clock cases in `scripts/member_worker_test.mjs`; valid actual-worker replies discarded after synthetic clock advances in `TestMemberNativeWorkerCompatibility` |
| Secret-free peer/global lock, startup/pending cancellation, no echo/restart, required coordination APIs, notification failures, local disposal, and cached-pagehide cleanup | Named `node:test` lock, channel failure, global lock, and pagehide cases in `scripts/member_worker_test.mjs`; controlled channels and lifecycle events, not actual browser tabs |
| Local visibility-loss lock in startup/idle/unlocked/pending states, hidden/missing/failed visibility admission, registration cleanup, pinned owner document, pre-admission/reply checks, no peer notification, no restart, and explicit replacement | Named `node:test` visibility cases in `scripts/member_worker_test.mjs`; actual Node worker termination under synthetic visibility events in `TestMemberNativeWorkerCompatibility` |
| Actual dedicated worker and owner, native restore, generated backup opened natively, wrong password/corruption/mismatch without replacement, public-output ownership, pending disposal, replay/malformed commands, failed/malformed/oversized runtime loads | `TestMemberNativeWorkerCompatibility` with `scripts/member_worker_integration.mjs` and test-only Node API adapter `scripts/member_worker_node.mjs` |
| Reviewed loader/notice digest rejection, invalid artifact headers and size bounds | `scripts/test_build_wasm.py` |
| Test-only browser asset bounds, complete manifest/digests, duplicate/traversal rejection, exact routes, hosts/origins, methods/HEAD, headers, and unread bodies | `TestMemberBrowserAssets`, `TestMemberBrowserDelivery`, `FuzzMemberBrowserManifest` |
| Actual browser member worker, native backup restore and browser backup opened natively, failed restoration without replacement, snapshots, admission, public output, pending disposal, UI event-loop progress, page CSP probes, synthetic-clock expiry/rollback and explicit restoration, same-origin peer lock, background-tab lock/foreground restoration, and navigation termination | `TestMemberNativeBrowserCompatibility` with `scripts/member_browser_test.mjs`, through the opt-in `make member-browser-test` |
| Synthetic setup form independent entries, immediate field clearing, busy/unlocked/saved admission, safe retention failures, cancellation and late-result rejection | `scripts/member_forms_test.mjs` in `make member-wasm-test`; actual keyboard submission, accessible names, screenshot, and native backup/request validation through `make member-browser-test` |
| Synthetic restoration form required expected key, bounded snapshots, unchanged record, no setup fallback, source errors, cancellation/closure, and hidden/foreground behavior | `scripts/member_forms_test.mjs`, including a 256-case bounded generated source/text sweep with no KDF/I/O; actual wrong-password, key-substitution, ciphertext-corruption, startup-cancellation, separate-page restoration, and background-lock checks in `scripts/member_browser_test.mjs` |

These establish neither database isolation, anonymity, nor protocol attack results.
Web checks validate allowlists/delivery, not full HTML/CSS grammar or browser execution.
The shell loads no JavaScript. Product-shell screenshots, browser CSP enforcement,
manual keyboard/assistive technology review, contrast, and print rendering remain
untested; the separate synthetic-form evidence does not cover that shell.

Native backup costs can be measured with:

```sh
go test ./internal/client/keystore -run='^$' -bench=BenchmarkKeystore -benchmem
```

This measures the full 64 MiB, three-pass profile, not a weakened test substitute.
Browser costs, reviewer-backup native/WASM compatibility, independent cryptographic review,
independent file-custody review, certificate/enrollment integration, and end-to-end device
confidentiality remain untested. Reviewer round binding, expiry enforcement, and
envelope-decryption workflows are not implemented.

### Container infrastructure checks

The default [browser stack](deployment.md#container-stack) has explicit container
checks, separate from the real-browser journey and broader protocol acceptance.
`make container-config` uses the real
Compose JSON model without starting containers. Python policy/secret unit tests run
in `make check` without a Docker dependency. Database privileges are not inferred
from those unit tests.

`make container-test` requires a local Linux Docker daemon, Engine 28 or newer,
Compose, Go 1.27.3, Python, and Make. It builds the matched runtimes, actual scratch image and both
PostgreSQL instances under a unique test project, with fresh secrets and ephemeral
loopback host ports. It never uses or resets the normal development stack's volumes.
Failures or missing tools fail the target rather than skipping it. Cleanup removes
only the test project's containers/networks/volumes; build cache/images remain.
Forced termination or a daemon failure can leave owned test resources for explicit
inspection and cleanup.

The checks inspect running users, read-only roots, capabilities, resource settings,
logging drivers, actual network attachments, scoped read-only application state and
own-runtime-only secrets, and port publication. Verified HTTPS requests check the
actual browser pages, peer origins, liveness, source discovery and no cookies.
Repeated startup retains server state and persisted account rows. Unit checks reject
incomplete state, unsafe metadata, cross-service credentials and implicit host mounts,
and verify migration-before-service ordering. `TestEmptyInitializationAdmission`,
`TestRuntimeDatabaseBoundary`, `FuzzRuntimeDatabaseBoundary`, `TestBrowserProbeTLS`
and `TestBrowserLiveness` cover native setup, database admission and trusted probes.
Real TCP-authenticated SQL checks run as the actual runtime/migration roles:
no ownership escalation, server-file reads, schema/public/temporary DDL, default table/function access,
wrong-password rejection, and successful use only after an explicit owner grant. The opposite instance must
reject a TCP connection using the first instance's runtime credential. Synthetic
test tables/functions exist only in disposable volumes. Passwords and SQL error
bodies are not printed.

The database race targets stop the disposable browser services after the connected
page/isolation checks. Their two eight-connection runtime pools then use the existing
16-connection role budget without competition from HTTP pools. Connection grants,
limits and admission checks are not increased or bypassed for tests.

On 2026-10-30, `make container-test db-account-test` passed for the default browser
stack on Linux x86_64 with Engine 29.9.2, Compose 5.6.1 and PostgreSQL 18.6. Cold
startup exercises the operator's actual `up` entry point without pre-created secrets;
repeat startup retains server state and a persisted account row. The separate
`make browser-test` passed in an isolated sandbox with the pinned Chromium/Node
runtimes, including account navigation, shared-review discovery and no user file controls.

This is not evidence for malicious-host isolation, production networking,
rootless/Podman support, encrypted database restoration, OS-package vulnerability
scanning, SBOMs or the broader protocol acceptance matrix. Those remain required work.

### Database migration checks

`make db-migration-test` uses the same local Docker prerequisites and disposable
stack as `make container-test`, including all infrastructure checks. It also builds
the separate migration image and executes its actual Go/pgx/Goose runner against
both PostgreSQL instances with only their respective migration credentials.

`migration_checks` in `scripts/containers.py` checks failed migration without history
advancement, simultaneous/repeated application, separate version tables, owner-created
objects, runtime marker reads, denied runtime DML/DDL and ledger access, wrong-target
rejection, future/duplicate/negative/unapplied/out-of-order histories, and a missing
marker. Identity checks force version-2, version-3, and version-4 failures after their preceding
versions, verify transactional object rollback and unchanged history, then apply
the additive upgrades. Version 4 also backfills existing sessions without changing
their token digests, owners, or timestamps, and preserves selectors on repeated runs.
No SQL privilege result is inferred from unit tests. `TestMigrationAdmission`,
`TestMigrationCancellation`, `TestMigrationCredentialFiles`, and `TestMigrationFiles`
run under native race coverage; bounded admission fuzzing is included in `make fuzz`.
`MigrationOperatorTests` checks command scope and failure cleanup without Docker;
it does not establish live database or network isolation.

On 2026-10-28, the original version-1 `make db-migration-test` passed on Linux x86_64
with PostgreSQL 18.6, Engine 29.9.2, and Compose 5.6.1. This is not quota/spend
concurrency, crash-at-commit testing, encrypted restoration, or the full `db-test`.
Those remain unavailable. Missing tools or failed assertions fail rather than skip.

### Account storage checks

`make db-account-test` uses the same disposable stack and prerequisites as
`make db-migration-test`, including all its checks. The separate `account-test`
Docker target builds a race-enabled Go test executable in the existing pinned
builder image. Only the eight account test source files are additionally admitted
through `.dockerignore`; no test fixtures or host credentials enter the build.
The build must produce an executable, not a successful no-test compilation.

`TestPostgresAccounts` runs against real PostgreSQL as `anonce_runtime`, first on
identity and then separately on submission. Each read-only, resource-bounded test
container receives only its selected runtime password and network; it receives no
owner/migration secret and publishes no ports. Assertions do not print tokens,
query parameters, SQL diagnostics, or connection strings. Missing configuration
fails rather than skips. Container/volume cleanup is limited to the fresh test project.

Named subtests cover:

- `lifecycle`: fresh accounts/tokens, unchanged input ownership, stored digest,
  unknown/revoked tokens, individual/all-session revocation, cross-account isolation,
  idempotent disable, and missing/disabled account rejection.
- `constraints-and-grants`: exact sizes, duplicate keys, foreign keys, state/expiry
  checks, denied session extension/account deletion/DDL/owner escalation/ledger access,
  and the fixed five-column session schema.
- `expiry-and-retention`: expired records reject before deletion, bounded cleanup
  preserves live sessions, and actual database-clock absolute expiry.
- `concurrent-disable`: concurrent session creation and disabling under the race
  detector leave no session rows for a disabled account.
- `blocked-cancellation`: a held account lock blocks creation until the caller's
  deadline; no token or session row is returned/retained, and closed-pool errors
  do not expose driver diagnostics.
- `disable-rollback`: a held session-row lock blocks deletion after the account
  update; cancellation rolls back both account disabling and session removal.
- `session-rotation`: fresh tokens, unchanged owner/absolute expiry, digest storage,
  old-token invalidation, sibling isolation, caller-account binding, and rejection
  of replaced, unknown, expired, future-dated, revoked, and disabled sessions.
- `concurrent-session-rotation`: competing rotations have exactly one winner;
  revoke-all/disable races leave no live successor.
- `rotation-cancellation-and-rollback`: held account/session-row locks cancel
  rotation without changing the old session; closed pools expose no driver data.
- `session-limit`: exact capacity, no material or eviction on denial, rotation and
  revocation at capacity, cross-account isolation, excess-row rejection, and disable.
- `concurrent-session-limit`: competing starts through independent pools admit
  exactly the fixed capacity with no evicted or unreachable successful tokens.
- `session-limit-after-lock-wait`: queued admission observes committed insertion,
  revocation, disable, and database-clock expiry; cancellation returns no material
  and leaves capacity unchanged.
- `session-inventory`: owner-derived creation/expiry metadata and current marker,
  old live bearer access, unchanged inputs/output ownership, cross-account isolation,
  malformed/unknown/future/expired/revoked/disabled bearer rejection, exact capacity,
  excess rows without partial output, and secret-free closed-pool failure.
- `inventory-after-lock-wait`: queued lookup observes committed sibling insertion,
  token revocation/rotation, disable, and database-clock expiry; cancellation returns
  no metadata. Native `TestAccountAdmission`, `TestAccountUnavailableAndCancellation`,
  and bounded `FuzzAccountToken` cover input admission and ownership without SQL.
- `session-selectors`: stable, independent non-secret inventory selectors across
  bearers, rejection as credentials, nonnull/nonzero/unique constraints, denied
  runtime updates, and fresh selectors on rotation without sibling changes.
  The migration harness checks version-4 failure rollback, existing-row backfill,
  unchanged token/account/timestamps, and stable selectors on repeated application.
- `revoke-other-sessions`: bearer-derived sibling removal at/exceeding capacity,
  expired/future-row cleanup, cross-account isolation, unchanged current token/expiry
  and input, repeat calls, later authenticated starts, invalid and old bearer denial,
  near-boundary admission and age-boundary rejection, trusted rotation, and secret-free
  closed-pool failure. The same native admission/cancellation/fuzz tests cover inputs.
- `concurrent-revoke-other-sessions`: independent pools using the same/competing
  bearers, sibling rotation, revoke-all, and disable leave only the expected survivor
  or no live sessions, without returning another account's references.
- `revoke-others-after-lock-wait`: queued operations recheck database-clock expiry
  and authentication age, observe revocation/disable and sibling insertion, and
  propagate cancellation without a count or unintended deletion.
- `revoke-others-cancellation-and-rollback`: a held sibling-row lock cancels deletion;
  all sibling rows survive rollback and the current session remains unchanged.
- `selected-session-revocation`: one sibling removed without changing current/foreign
  sessions; zero/current/missing/foreign/stale selectors, invalid and old bearers,
  trusted reauthentication, expired/future targets, excess capacity, unchanged input,
  and secret-free closed-pool failure. `TestSelectedSessionAdmission` and bounded
  `FuzzSelectedSessionAdmission` cover native bounds, cancellation, and ownership.
- `concurrent-selected-session-revocation`: independent pools selecting the same
  target, competing bearers, target rotation, and disable have only valid outcomes.
- `selected-session-after-lock-wait`: bearer expiry, authentication age, revocation,
  rotation, target rotation, disable, and cancellation are observed after waiting.
- `selected-session-rollback`: a held target-row lock cancels deletion without
  publishing removal or changing either session.
- `session-scoped-sign-out`: owner-derived removal including current/expired/future
  rows above capacity, foreign-account isolation, unchanged input, invalid/old bearer
  denial, recent/age boundaries, trusted reauthentication, and later login admission.
  `TestAllSessionsAdmission` and bounded `FuzzAllSessionsAdmission` cover native
  bounds, concurrent unavailable-store access, cancellation, and input ownership.
- `concurrent-session-scoped-sign-out`: independent pools using same/competing
  bearers, sibling rotation, starts, and disable produce only serialized outcomes.
- `sign-out-after-lock-wait`: expiry, authentication age, revocation, rotation,
  disable, and cancellation deny queued sign-out without deletion or a count.
- `sign-out-rollback`: a held session-row lock cancels deletion without publishing
  a count or removing the current/sibling sessions.
- `session-scoped-disable`: bearer-derived atomic disabling and removal of all
  references above capacity, foreign-account isolation, unchanged input, denial of
  invalid/old bearers and later session starts, recent/age boundaries, and trusted
  reauthentication. `TestSessionDisableAdmission` and bounded
  `FuzzSessionDisableAdmission` cover native bounds, concurrent unavailable-store
  access, cancellation, and input ownership.
- `concurrent-session-scoped-disable`: independent pools using same/competing
  bearers, sibling rotation, starts, sign-out everywhere, and trusted-owner disable
  produce only serialized account states and remove all expected references.
- `session-disable-after-lock-wait`: the shared sign-out/disable wait matrix
  rechecks expiry, authentication age, revocation, rotation, disable, and cancellation
  without changing account state or references on denial.
- `session-disable-rollback`: a held session-row lock cancels deletion after the
  account-state update; rollback restores the active state and both sessions,
  preserves current authorization, and releases locks for a later disable.

The submission run must reject store construction, and SQL checks verify that
neither account table exists there. This is persistence evidence only, not passkey
verification, HTTP owner authorization, login/logout UX, vault custody, membership
binding, production retention, or the complete browser acceptance journey.

On 2026-10-29, the account suite and version-2/version-3/version-4 upgrade/failure
checks passed as part of `make db-member-backup-test` on Linux x86_64 with PostgreSQL
18.6, Engine 29.9.2, and Compose 5.6.1, including all runtime-role race-enabled
subtests above.

### Member-backup storage checks

`make db-member-backup-test` includes the disposable account/migration/container
checks above, then runs `TestPostgresMemberBackups` as the actual runtime role on
identity and separately on submission. The `member-backup-test` image compiles a
race-enabled executable from only the two additionally admitted member-backup
test files, without fixtures. It receives only its selected runtime credential and
network. Missing configuration fails, and diagnostics contain no row contents.

Named subtests cover:

- `lifecycle-and-owner-scope`: persist and natively restore a runtime-generated
  encrypted key, unchanged inputs/owned outputs, cross-account read/write/delete
  isolation, fixed public binding, stale revisions, opaque ciphertext admission,
  deletion tombstones, explicit same-key recreation, and disabled/missing owners.
- `constraints-and-grants`: envelope/profile/purpose/size and revision bounds,
  foreign keys, fixed schema fields, and denied owner/public-key changes, row
  deletion, truncation, DDL, ledger reads, and ownership escalation.
- `concurrent-writes`: exactly one winner among competing creates and among mixed
  replacement/deletion attempts with the same expected revision.
- `concurrent-disable`: writes racing account disable cannot leave an accessible
  or writable backup after disable commits.
- `cancellation-and-rollback`: held account/backup locks cancel writes without
  revision changes; subsequent writes acquire the released locks. Constructor
  cancellation and closed-pool errors fail without driver diagnostics.
- `revision-exhaustion`: the final positive revision remains readable and cannot wrap.
- `session-owner-scope`: session-derived owner isolation, revision conflicts,
  fixed binding, deletion/recreation, and independent result buffers.
- `session-invalidation`: unknown/expired/revoked/disabled sessions cannot read,
  write, or delete; individual revocation leaves sibling sessions usable.
  All-sibling and selected-sibling revocation deny removed bearers while preserving
  the caller's backup access.
  Session-scoped sign-out denies both the current and sibling backup bearers.
  Session-scoped disable also denies both, retaining ciphertext, binding, and revision.
- `session-lock-order-and-cancellation`: individual/selected/sibling/all-session revocation and
  disable wait for admitted access; cancelled invalidation leaves sessions usable.
  Both bearer-derived sign-out and disable use the same lock order.
  Held account/backup locks cancel access without changing the slot.
- `session-expiry-after-lock-wait`: a session expiring while queued on the account
  lock cannot update its backup. The database clock determines expiry.
- `session-revocation-after-lock-wait`: queued reads, writes, and deletes observe
  revocation committed while they waited, returning no data or mutation.
- `session-recent-authentication`: fresh/near-boundary mutations succeed; at/after
  five minutes mutations fail before revision checks while reads remain available.
  Future-dated sessions fail closed. Verified-caller rotation restores mutation
  admission without extending expiry and invalidates the old token.
- `session-authentication-age-after-lock-wait`: queued replacement/deletion crossing
  the age boundary cannot mutate; the live token can still read unchanged state.
- `session-rotation-after-lock-wait`: rotation queued behind committed revocation,
  disable, or expiry returns no successor token or session.

The submission run rejects construction; separate SQL checks require all identity
account/session/member-backup tables to be absent there. These are internal storage
checks, not HTTP owner authorization, authentication ceremony verification, rate
limits, trusted enrollment binding, ciphertext authentication, malicious-server
rollback defense, production retention, encrypted database restoration, or the
browser vault journey.
Bounded native admission tests/fuzzing run in `make check`; real PostgreSQL remains
an explicit opt-in target.

On 2026-10-29, `make db-member-backup-test` passed on Linux x86_64 with PostgreSQL
18.6, Engine 29.9.2, and Compose 5.6.1, including version-3/version-4 upgrade/failure checks,
session selectors, rotation, all-sibling/selected-sibling revocation,
bearer-derived sign-out/account disabling, authentication-age admission,
cancellation, and all named runtime-role race checks above. No authentication
ceremony was exercised.

### Submission record storage checks

`make db-submission-record-test` provisions disposable real PostgreSQL instances,
checks bootstrap/migrations, and runs `TestPostgresSubmissionRecords` as the runtime
role against each boundary. Missing configuration fails rather than skips. It uses
only synthetic ciphertext stand-ins and random test IDs, never real answers or tokens.

Named cases cover:

- `persistence-and-retries`: cross-pool persistence, unchanged bytes, identical
  retries, changed-payload rejection, distinct spends, and independent round scopes.
- `concurrent-spending`: 24 cross-pool contenders with three payloads, exactly one
  stored record, shared references for identical contenders, no replacement.
- `constraints-and-grants`: SQL size/schedule constraints and denied runtime record
  changes/deletion, policy replacement, and schema ownership.
- `round-admission`: unknown/bulletin-mismatched, unopened, closed, and cancelled
  rounds, immutable provisioning, cancellation retaining accepted records.
- `post-lock-window-and-cancellation`: real row-lock waits followed by closure,
  committed cancellation, and context cancellation before any spend is stored.
- `uncommitted-conflict`: an initially invisible competing insert becomes observable
  after its commit, returning its original reference through a fresh snapshot.
- `cancellation-order-and-rollback`: cancellation waits for admitted acceptance;
  cancelling a queued cancellation leaves the round open and its records unchanged.
- `round-provisioning-rollback`: cancelled uniqueness waits cannot later create
  a round after the conflicting transaction rolls back.
- `cancelled-insert-rollback`: cancelled uniqueness waits and rollback consume no
  spend; the original input can subsequently be accepted.

Migration checks also force a version-2 table conflict, verifying round/table and
history rollback before repeated/concurrent upgrades. These tests do not verify
tokens, ciphertext validity, quotas, browser submission, receipts, outbox recovery,
or encrypted database restoration. Full `db-test` remains unavailable.

### WASM verifier checks

`make wasm-test` requires Node.js 22.23.3 on `PATH`, in addition to the pinned Go
toolchain. No npm installation is needed. `make check` includes this target; CI
installs the pinned external runtime. `make wasm` needs only Go and Python.

`TestClientNativeWASMCompatibility` generates three fresh member requests natively,
checks their expected public keys, and sends only public hex requests/results to
the actual built WASM module. It checks both hex cases, every-byte mutations,
extra claims, malformed inputs, expected-key matches and every-byte mismatches,
both methods' argument types/arity, oversized strings, hostile objects, shutdown,
and namespace collisions. The runner verifies artifact hashes before loading and
rejects unexpected `fetch` calls. Failures and missing
tools/artifacts fail the target; it does not skip unavailable checks.

The Go JS/WASM runner also executes adapter unit tests and fuzz seeds. Native race
coverage does not instrument WASM; Node execution is not browser, CSP, accessibility,
member-key custody, or independent security evidence. Loader and compiler
must match under the official [Go WASM guidance](https://go.dev/wiki/WebAssembly)
(accessed 2026-10-27). See the [interface](key-management.md#local-wasm-request-verification)
and [dependency review](dependencies.md#wasm-runtime-support).

### WASM member session checks

`make member-wasm-test` uses the same pinned Go/Node runtimes and build gates as
the verifier and is included in `make check` and CI. It generates a native member
backup at full profile costs, restores it through the actual bridge, creates a
fresh WASM backup, and validates that backup's key and CSR natively. The runtime
exchange contains only encrypted backups, public material, and a synthetic opaque
password; there are no committed private-key fixtures or plaintext key exports.

The Node runner verifies artifact hashes, rejects unexpected network calls, and
exercises the failure/lifecycle cases mapped above. Native race tests additionally
cover cancellation before the worker enters the shared session and admission held
until pending cleanup. WASM is not race-instrumented. Cooperative execution means
a lock/close event can arrive after KDF completion; tests do not claim preemption.

The same target also runs the [local dedicated-worker host](key-management.md#local-member-worker-host)
in real Node worker threads using a test-only browser API adapter. Production client,
worker, runtime, and WASM files are the built and hash-checked artifacts. The adapter
maps fixed WASM fetching to a local file and rejects other fetches. Backups and CSRs
are checked natively, just as for the direct bridge. Owner tests use controlled
timers for the fixed startup/operation/lifetime limits and verify synchronous
termination and pending settlement. These are not browser timing or erasure claims.
Separate controlled-clock tests advance either monotonic or wall time without
firing timers, check exact deadlines, reject clock failure/rollback, and ensure
late results cannot revive an owner. The actual Node worker checks also discard
valid restoration replies after synthetic clock advances, without waiting for
the timeout callback. They do not model real sleep or suspension.
The public `closed` Promise is also checked with actual Node workers, including
idle peer locking without polling. Controlled tests check cleanup before observer
callbacks and settlement for failed construction, without claiming worker exit.
Optional host-signal checks exercise already-aborted admission, local cancellation
during startup/idle/pending work, reason-free closure, cleanup of abort listeners,
and state rechecks when another listener suppresses abort event delivery. Actual
Node worker checks cancel startup, unlocked custody, and pending restoration.
Lock checks additionally model independent owner modules, inspect the exact
secret-free notification, reject missing/failed channel facilities, and exercise
local pagehide cleanup, including a synthetic back/forward cache event. The real
Node worker runner receives native BroadcastChannel notifications and handles a
synthetic pagehide and visibility loss with pending operations. Node does not model
browser origin or storage partition rules, navigation caching, suspension, or real logout.

Native/Node export checks open the new backup under a different synthetic password
and compare the complete restored key with the native original. Direct WASM work
may finish before its Promise-returning call returns; pending admission is checked
deterministically through native tests and the worker owner, not by assuming a
Promise means a derivation is still running.
Confirmed setup/export checks use separately copied synthetic password inputs,
mutate both caller buffers after invocation, and reject mismatches without public
or encrypted output. They test the byte interface, not independent human entry,
text encoding, password-manager behavior, or a browser prompt.
Separate worker text checks exercise strict UTF-8 encoding, immutable-string input
bounds, and synchronous mutable-buffer cleanup. Actual Node workers compare text
setup with independent byte restoration and export a native member key under a
synthetic 1024-byte Unicode passphrase, opened and compared natively. These checks
do not establish independent human entry, DOM cleanup, autofill behavior, or erasure
of JavaScript strings. The synthetic browser harness also exercises text setup,
byte/text restoration, encrypted export, mismatch handling, and pending cancellation.
Bounded transport fuzzing runs with `member-wasm-test`, not `make fuzz`; retain
failures as synthetic cases in `scripts/member_worker_test.mjs`, never key fixtures.

The separate opt-in browser target below adds isolated synthetic page delivery and
browser checks. The Node target supplies no mobile measurements, product CSP,
passkeys, account/vault authorization, recovery, or independent cryptographic review.
Neither target satisfies the
[browser acceptance cases](#browser-account-and-vault-acceptance).

### Member-worker browser checks

`make member-browser-test` requires Linux x86_64, the pinned Go/Node runtimes, and
the external open-source Chromium snapshot in `scripts/browser.toml`. It is an
opt-in development check, separate from `make check`, CI, and the unavailable
product `make e2e`. Missing tools, wrong versions, blocked sandbox startup, failed
assertions, and timeouts fail the target without skipping or disabling controls.

Download the exact archive URL in that manifest using the
[official Chromium snapshot instructions](https://www.chromium.org/getting-involved/download-chromium/#chromium).
Verify its SHA-256 against the manifest **before extracting or executing it**.
Keep the complete extraction and original notices in a trusted local directory.
Install the browser's Linux shared-library dependencies through the operating
system package manager, and run as an unprivileged user with a working sandbox.
Do not add `--no-sandbox` or disable CSP to bypass an environment failure.

```sh
MEMBER_BROWSER=/trusted/path/chrome-linux/chrome make member-browser-test
```

The Go test host binds an ephemeral `127.0.0.1` port. It verifies the complete
bounded WASM build manifest and serves only an exact in-memory asset allowlist,
not a working directory or product route. Unknown paths, queries, encoded aliases,
foreign hosts/origins, cross-site requests, and request bodies are rejected without
reading bodies or reflecting inputs. Responses use `no-store`, no-referrer,
nosniff, same-origin resource policy, and no cookies/CORS. The disposable page has
[synthetic local forms](ui-design.md#synthetic-member-forms), but no uploads,
persistence, or key display. Their encrypted/public output is page-memory-only;
never enter real secrets. The driver captures empty fields after lock into
`.cache/tests/member-forms.png`; the reviewed documentation image is copied from
that actual browser capture, not substitute rendering.

The page permits same-origin modules/workers but no fetches or WASM compilation.
Only the worker response permits same-origin fetches and `wasm-unsafe-eval`, never
JavaScript `unsafe-eval` or inline execution. Page probes check that inline script,
fetch, and main-thread WASM compilation are blocked; successful worker operations
exercise the worker policy. This uses
[CSP Level 3, Working Draft 2026-10-27](https://www.w3.org/TR/2026/WD-CSP3-20261027/),
not a final Recommendation, and the [HTML worker model](https://html.spec.whatwg.org/multipage/workers.html)
(consulted 2026-10-28). No product service or shell CSP changes.

The Node driver uses Chromium's private DevTools pipe, not an open debugging port
or npm package. Synthetic unlock inputs enter through the pipe, never HTTP. It
uses a fresh disposable profile, closes the browser/workers, and removes its owned
scratch directory. It returns only encrypted backup and public enrollment material
for native validation, with fixed failure diagnostics. Page network events are
checked against a fixed allowlist; this is not a complete browser/worker network
capture, proxy-log audit, or malicious-site isolation boundary.

The forms additionally use actual keyboard text insertion and Tab/Enter submission.
Setup confirmation errors leave no backup; successful encrypted/public output is
checked natively. Restoration preserves that record on wrong-password, substituted
expected-key, and corrupted-ciphertext failures, without generating a replacement.
A separate page restores the driver-supplied record with its retained expected key;
real backgrounding then terminates the owner and reenables explicit restoration.
Accessible-name checks inspect the browser accessibility tree, not a screen reader.
Node controller tests cover deterministic startup/pending cancellation, peer closure,
failed sources, owned snapshot cleanup, and idle-field clearing on visibility loss.
No additional parser grammar or cryptographic profile is introduced; shared worker,
UTF-8, backup, and key parsers retain their existing bounded fuzz targets.

These checks cover one headless desktop build and same-origin/same-partition pages.
Synthetic owner wall-clock advances exercise late startup/operation replies,
lifetime expiry, backward-clock termination, and explicit same-key restoration.
These are injected clock readings, not real suspension or operating-system time changes.
The driver switches real foreground tabs, observes a trusted hidden-state event
and worker disappearance before calling the owner again, rejects hidden-page startup,
and checks that returning cannot revive the old owner. Explicit new-owner restoration
then reuses the same native backup/key. No synthetic visibility dispatch or page
visibility override is used for these browser checks.
Peer-lock and visibility checks observe the public `closed` Promise, without an
extra notification channel or a data call to trigger termination. Other browser
checks cover closure after lock, disposal, startup denial, and synthetic expiry.
Browser abort-controller checks additionally cancel startup, unlocked custody, and
pending restoration, reject already-aborted startup, and explicitly restore the
same native backup/key through a new owner. Worker disappearance is checked after
the cancellation cases; this is not an erasure or hard cancellation-time guarantee.
On 2026-10-29, `make member-browser-test` passed on Linux x86_64 with the pinned
Chromium 159.0.8129.0 executable and Go/Node runtimes. This includes the host-signal,
encrypted-export, password-confirmation, UTF-8 text passphrase, and synthetic
setup/restoration form cases. The successful
run supersedes earlier attempts blocked by missing libraries or an unset executable
path. The driver retained the browser sandbox and CSP checks.

Navigation and tab-switch checks observe worker disappearance, not memory erasure
or reliable global revocation. Event-loop progress is not a mobile latency/memory budget.
Other engines, storage partitions, background suspension, back/forward-cache
restoration, real logout, provider/passkey compatibility, product screenshots,
manual keyboard/assistive technology review, and the complete account/vault journey
remain untested. The test-form screenshot is not product evidence.
No supported-browser matrix or readiness claim follows from this target.

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

## Browser account and vault acceptance

These are required, **unimplemented** acceptance cases for the
[account workflow](ui-design.md#account-and-review-workflow) and
[vault design](key-management.md#browser-account-vault). Add real browser and
PostgreSQL tests, not mock success or a CLI-only substitute.

| Area | Required evidence |
| --- | --- |
| Ordinary member journey | Fresh browser, account creation/sign-in, verified enrollment, automatic key/CSR/backup setup, common review link or dashboard, local encryption, anonymous submission, and locally verified receipt; no installed tooling or manual key files |
| Browser support | Record browser/OS/authenticator/provider versions, PRF extension results, user verification, synced and cross-device behavior; publish unsupported paths honestly |
| Local unlocking | Login can succeed without PRF; configured browser-passphrase unlocking works without weakening profile 2; missing PRF, failed authentication, corrupt backups, wrong passphrase, and cancelled ceremonies never trigger server decrypt or silent fallback |
| New device and credentials | Restore the same enrolled key locally; authorize adding/removing passkeys and wrapping methods, handle different PRF secrets, reject unauthorized replacement and account/key mismatch |
| Vault authorization and races | Another dummy account cannot read/write/delete backups; require CSRF and recent authentication for sensitive changes; bound input/work and reject stale concurrent replacement |
| Recovery | Distinguish login reset from key restoration; exercise reviewed recovery material, revoked credentials, all-methods-lost messaging, preserved quotas, and no expired reviewer-key reactivation |
| Privacy boundary | Capture requests, headers, URLs, referrers, storage, logs, and database rows; no raw keys, unlock/recovery secrets, or PRF outputs reach services; no identity credentials or vault/account identifiers reach anonymous requests |
| Dashboard and replies | Available rounds work without a server-side account-to-submission index; no account-linked receipt/mailbox lookup or token backup; member-key restore does not claim anonymous reply restore |
| Lifecycle and storage | Shared/private browsing, disabled/evicted storage, logout, account switch, multiple tabs, lock/expiry, and worker termination; no persisted plaintext keys, drafts, unlock material, or PRF outputs |
| Reviewer and accessibility | Automatic fresh round keys, authorized ciphertext retrieval and local decryption; mobile/desktop, keyboard, assistive technology, autofill/paste, safe errors, progress/cancellation, and unsent-answer warnings |

Test an ordinary user on actual browsers as well as automated flows. Record prompt
counts, task completion, startup/unlock latency, and peak memory on representative
mobile devices. Agree and document resource/UX budgets before claiming support.
Virtual authenticators do not establish provider sync, physical authenticator,
cross-device PRF behavior, or usable recovery. Retain no test secrets or real user
data in screenshots, traces, logs, or crash artifacts.

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
| Cross-account encrypted-backup access or replacement | Owner-scoped authorization denies read/write/delete without exposing backup contents | `TestVaultEnforcesOwnerIsolation` |
| PRF/unlock material serialized with login or persisted locally | Boundary assertion fails; no server decrypt fallback | `TestVaultKeepsUnlockMaterialLocal` |
| Login reset or unapproved new passkey used to open an existing vault | No key recovery without a configured local unlock/recovery method | `TestVaultSeparatesAccountAndKeyRecovery` |
| Changed binding or stale concurrent backup replacement | Reject mismatched keys/stale writes; disclose unresolved malicious-server rollback limits | `TestVaultRejectsBindingAndVersionMismatch` |
| Personalized round URL, session cookie, or vault ID crosses anonymous handoff | Credential-free round-scoped flow or fail closed; no identity fetch from anonymous pages | `TestBrowserPreservesAnonymousHandoff` |
| Account dashboard or backup stores receipt/token/mailbox mapping | Privacy assertion fails without an identity-to-submission record | `TestDashboardExcludesSubmissionHistory` |
| Logout/account switch leaves another tab unlocked | All controlled contexts lock and clear accessible buffers without an erasure guarantee | `TestVaultCoordinatesSessionLock` |
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

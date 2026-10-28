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
| `make fuzz` | `FuzzConfig`, `FuzzLookup`, `FuzzBackup`, `FuzzMemberKeyPayload`, `FuzzMemberCSR`, `FuzzMemberSessionUnlockInputs`, `FuzzMemberWASMSizes`, `FuzzMemberBrowserManifest`, `FuzzWASMRequest`, `FuzzWASMExpectedKey`, `FuzzReviewerKeyPayload`, `FuzzClientArguments`, `FuzzClientPublicKeyLine`, `FuzzClientPassword`, and `FuzzClientRewrapPasswords`, two workers, 15 seconds each; override with `FUZZTIME` |
| `make vuln` | govulncheck, gosec, module verification/inventory, redacted current-file Gitleaks scan |
| `make web-lint` | Build/start loopback submission with/without development flag; inert markup, headings/landmarks, fragment/description targets, links, CSS restrictions, asset hashes, headers, unavailable protocol/readiness, bounded shutdown |
| `make wasm` | Go `js/wasm` public-request verifier; matching reviewed loader/notices, SHA-256 manifest, 8 MiB uncompressed size gate |
| `make wasm-test` | Rebuild artifacts, compare native and Node WASM public-request results, exercise the actual bridge, and run adapter unit tests under the Go JS/WASM runner |
| `make member-wasm` | Separate local member-session module, dedicated-worker/client assets, matching reviewed loader/module notices, manifest, and 8 MiB gate |
| `make member-wasm-test` | Native race/lifecycle tests, actual Node direct bridge and dedicated-worker setup/restoration, rejection, termination, bidirectional encrypted-backup compatibility, owner lifecycle unit tests, and bounded command fuzzing |
| `make member-browser-test` | Opt-in pinned headless Chromium, isolated Go test host, native/worker backup compatibility, page CSP probes, event-loop progress, synthetic-clock expiry/restoration, same-origin peer lock, background-tab lock/foreground restoration, and navigation termination; requires `MEMBER_BROWSER`, not included in `make check` or CI |

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
| Member session unlock admission | 1025-byte password, 65597-byte backup, and 33-byte expected-key fuzz caps; exercise invalid password/key lengths only, no KDF work; backup/payload parsing reuse the shared fuzzed implementations |
| Member WASM admission sizes | Fixed-width integer fuzz inputs for password/backup/key lengths and operation kind; exact member bounds, no allocations or KDF work; byte parsing reuses shared backup/payload validation |
| Browser-test asset manifest | `FuzzMemberBrowserManifest`: 4097-byte cap, exact fixed filename set, bounded synthetic assets, no KDF or network work |
| Member worker transport | `member_worker_test.mjs`: exhaustive byte-size boundary sweep and 2048 generated commands per run, each with at most four views of 1025 elements; independent metadata admission oracle, no KDF or I/O |
| WASM request adapter | 259-byte request fuzz input cap, exact 258-byte ASCII hex representation before bounded shared CSR parsing; expected-key fuzzing also caps the key input at 65 bytes for an exact 64-byte ASCII hex representation; no KDF work |
| CLI arguments | 8193-byte fuzz input cap; no file, network, or KDF work |
| CLI expected-key record | 75-byte data and 9-byte kind fuzz caps; exact 72/74-byte lowercase kind-tagged lines, no file, network, or KDF work |
| CLI password framing | 2051 bytes for ordinary framing, 3076 for rewrap; no file, network, or KDF work |

Review and license synthetic regression inputs before committing. Retain failures
in the relevant package's `testdata/fuzz/<target>` directory:

- `internal/service`: `FuzzConfig`.
- `internal/web`: `FuzzLookup`.
- `internal/client/keystore`: `FuzzBackup`.
- `internal/client/memberkey`: `FuzzMemberKeyPayload`.
- `internal/client/membercsr`: `FuzzMemberCSR`, public requests or malformed data only.
- `internal/client/membersession`: `FuzzMemberSessionUnlockInputs`, synthetic
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
| Configuration | `TestConfig`, `TestConfigSourceURL`, `TestRunFailures` |
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
| Member bridge admission, cancellation before shared-session entry, cleanup-before-shutdown, repeated lock/close, concurrent lock/admission, and size fuzzing | `TestMemberWASMSizes`, `TestMemberWASMLifecycle`, `TestMemberWASMConcurrent`, `FuzzMemberWASMSizes` |
| Actual member WASM bridge, opaque passwords, native backup restore, WASM backup opened natively, public CSR validation, wrong password/purpose, corruption/key mismatch, byte types/arity/bounds, hostile objects/shadowed getters, shared/detached arrays, input snapshots, public-output ownership, lock/close and namespace collision | `TestMemberNativeWASMCompatibility` with `scripts/member_wasm_test.mjs`, through `make member-wasm-test` |
| Worker owner single-instance/operation admission, snapshots/transfers, input types/arity/bounds, hostile properties, timeout/termination, late replies, protocol/transport failures, and bounded command fuzzing | Named `node:test` cases in `scripts/member_worker_test.mjs`, through `make member-wasm-test` |
| Stable secret-free closure Promise, every terminal path during startup/idle/pending work, failed/denied construction, cleanup before observers, late subscribers, unchanged readiness, no nonterminal settlement, and explicit replacement | Named `node:test` closed Promise cases in `scripts/member_worker_test.mjs`; actual Node worker lock/disposal/failure/expiry observations in `TestMemberNativeWorkerCompatibility` |
| Delayed startup/operation/lifetime deadline checks on each clock, exact boundaries, pre-admission/busy/reply/visibility rejection, unchanged lifetime after successful work, invalid/missing/failed/backward readings, captured clocks, local cleanup and explicit replacement | Named `node:test` deadline, lifetime, and clock cases in `scripts/member_worker_test.mjs`; valid actual-worker replies discarded after synthetic clock advances in `TestMemberNativeWorkerCompatibility` |
| Secret-free peer/global lock, startup/pending cancellation, no echo/restart, required coordination APIs, notification failures, local disposal, and cached-pagehide cleanup | Named `node:test` lock, channel failure, global lock, and pagehide cases in `scripts/member_worker_test.mjs`; controlled channels and lifecycle events, not actual browser tabs |
| Local visibility-loss lock in startup/idle/unlocked/pending states, hidden/missing/failed visibility admission, registration cleanup, pinned owner document, pre-admission/reply checks, no peer notification, no restart, and explicit replacement | Named `node:test` visibility cases in `scripts/member_worker_test.mjs`; actual Node worker termination under synthetic visibility events in `TestMemberNativeWorkerCompatibility` |
| Actual dedicated worker and owner, native restore, generated backup opened natively, wrong password/corruption/mismatch without replacement, public-output ownership, pending disposal, replay/malformed commands, failed/malformed/oversized runtime loads | `TestMemberNativeWorkerCompatibility` with `scripts/member_worker_integration.mjs` and test-only Node API adapter `scripts/member_worker_node.mjs` |
| Reviewed loader/notice digest rejection, invalid artifact headers and size bounds | `scripts/test_build_wasm.py` |
| Test-only browser asset bounds, complete manifest/digests, duplicate/traversal rejection, exact routes, hosts/origins, methods/HEAD, headers, and unread bodies | `TestMemberBrowserAssets`, `TestMemberBrowserDelivery`, `FuzzMemberBrowserManifest` |
| Actual browser member worker, native backup restore and browser backup opened natively, failed restoration without replacement, snapshots, admission, public output, pending disposal, UI event-loop progress, page CSP probes, synthetic-clock expiry/rollback and explicit restoration, same-origin peer lock, background-tab lock/foreground restoration, and navigation termination | `TestMemberNativeBrowserCompatibility` with `scripts/member_browser_test.mjs`, through the opt-in `make member-browser-test` |

These establish neither database isolation, anonymity, nor protocol attack results.
Web checks validate allowlists/delivery, not full HTML/CSS grammar or browser execution.
The shell loads no JavaScript. Screenshots, actual CSP enforcement, keyboard access, assistive
technology, contrast, and print rendering remain untested.

Native backup costs can be measured with:

```sh
go test ./internal/client/keystore -run='^$' -bench=BenchmarkKeystore -benchmem
```

This measures the full 64 MiB, three-pass profile, not a weakened test substitute.
Browser costs, reviewer-backup native/WASM compatibility, independent cryptographic review,
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
Lock checks additionally model independent owner modules, inspect the exact
secret-free notification, reject missing/failed channel facilities, and exercise
local pagehide cleanup, including a synthetic back/forward cache event. The real
Node worker runner receives native BroadcastChannel notifications and handles a
synthetic pagehide and visibility loss with pending operations. Node does not model
browser origin or storage partition rules, navigation caching, suspension, or real logout.
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
no input controls, uploads, persistence, or key display.

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

Navigation and tab-switch checks observe worker disappearance, not memory erasure
or reliable global revocation. Event-loop progress is not a mobile latency/memory budget.
Other engines, storage partitions, background suspension, back/forward-cache
restoration, real logout, provider/passkey compatibility, screenshots, keyboard and
assistive technology, and the complete account/vault journey remain untested.
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

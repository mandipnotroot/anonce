<!-- SPDX-FileCopyrightText: 2026 Anonce Contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Dependencies and licenses

Audience: maintainers, redistributors, and license reviewers.

Accessed: 2026-10-26. Proposed versions below are observations, not a transitive
license or vulnerability audit. HTTP commands use only the standard library;
the shared device-backup, identity/submission stores, and separate migration packages import the admitted modules below. No runtime
dependencies or assets are vendored. Recheck artifacts, hashes, licenses, and
advisories before further imports.

## Current materials

| Material | License | Treatment |
| --- | --- | --- |
| Original code, documentation, and repository checks | AGPL-3.0-only | SPDX headers; [license](../LICENSE) |
| Read-only shell templates and CSS | AGPL-3.0-only | Original embedded assets; device fonts, no third-party product assets or browser packages |
| Contributor Covenant 3.0 adaptation | CC-BY-SA-4.0 | Upstream attribution and separate document license retained |
| Python standard library | PSF-2.0 | External interpreter, not copied into the project |
| [ExifTool](https://exiftool.org/#license), distribution-maintained package | Artistic-1.0-Perl OR GPL-1.0-or-later, under Perl's terms | External metadata inspector; Ubuntu 24.04 CI installs `libimage-exiftool-perl` and reports its version; not vendored or pinned to one upstream release |
| Git and GNU Make | GPL-2.0-only / GPL-3.0-or-later upstream tools | External development tools, not project relicensing |
| REUSE 6.2.0 | GPL-3.0-or-later upstream tool | External compliance check; [REUSE 3.3 specification](https://reuse.software/spec-3.3/) |
| [mdBook 0.5.4](https://github.com/rust-lang/mdBook/releases/tag/v0.5.4) | MPL-2.0 | Documentation-only tool; official release archives and asset notices pinned in `scripts/mdbook.toml` |
| pip-tools 7.6.2 | BSD-3-Clause | External documentation lock compiler |
| [Go 1.27.3](https://go.dev/dl/?mode=json) | BSD-3-Clause | Pinned standard-library runtime and external compiler; WASM build copies the matching loader and original notices unchanged |
| [Node.js 22.23.3](https://nodejs.org/dist/v22.23.3/) | MIT with bundled third-party notices | External development-only WASM test runtime; no npm dependencies or Node product build |
| Chromium 159.0.8129.0, Linux x86_64 snapshot 1728820 | BSD-3-Clause with bundled third-party notices | External opt-in browser-test runtime, URL/digest in `scripts/browser.toml`; no proprietary browser or npm dependency required |
| [x/crypto 0.58.0](https://pkg.go.dev/golang.org/x/crypto@v0.58.0/argon2) | BSD-3-Clause | Admitted Argon2id/BLAKE2b and ChaCha20-Poly1305 composition for device-backup profile 2; exact hashes in `go.sum` |
| [x/sys 0.49.0](https://pkg.go.dev/golang.org/x/sys@v0.49.0/cpu) | BSD-3-Clause | Indirect CPU-feature detection for x/crypto; exact hashes in `go.sum` |
| [gofumpt 0.12.0](https://github.com/mvdan/gofumpt) | BSD-3-Clause | External Go formatter |
| [golangci-lint 2.15.0](https://github.com/golangci/golangci-lint) | GPL-3.0-only | External Go lint aggregator |
| [govulncheck 1.9.0](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck) | BSD-3-Clause | External Go vulnerability check |
| [gosec 2.30.0](https://github.com/securego/gosec) | Apache-2.0 | External static security check; no hosted analysis configured |
| [Gitleaks 8.30.1](https://github.com/gitleaks/gitleaks) | MIT | External current-file secret scanner |

- No dual licensing: tool licenses do not change the project's AGPL-3.0-only grant.
- Redistributed upstream files keep their notices and license texts under `LICENSES/`.
- The module directive sets minimum Go; Make pins toolchain/tool versions and uses
  Go checksum verification. These external tools are not copied project files.
  Review transitive graphs before redistribution.
- Future binaries must include applicable Go runtime notices alongside the project license.

ExifTool's upstream licensing and read-only metadata-inspection role were reviewed
2026-10-29. Distribution security updates are retained; CI verifies availability
rather than assuming the runner includes it. Local setup is in
[contributing](../CONTRIBUTING.md#local-checks).

### Admitted Go modules

#### Browser MVP admission

Pinned module licenses and the selected APIs were inspected 2026-10-29. The
identity host uses go-webauthn 0.18.2 for complete WebAuthn verification, not
handwritten attestation/assertion checking. CIRCL 1.6.5 supplies the exact RFC 9474
randomized SHA-384/PSS composition. Go 1.27.3 supplies RFC 9180 HPKE. This is source
composition review, not independent cryptographic approval. `go.mod` and `go.sum`
pin the graph. Updates require advisory, source, license and interoperability
review together, with no algorithm fallback.

| Newly imported module | Version | License and purpose |
| --- | --- | --- |
| `github.com/go-webauthn/webauthn` | 0.18.2 | BSD-3-Clause; relying-party verification |
| `github.com/cloudflare/circl` | 1.6.5 | BSD-3-Clause with original Go notices; blind RSA |
| `github.com/go-webauthn/x` | 0.3.1 | BSD-3-Clause; library support |
| `github.com/fxamacker/cbor/v2` | 2.9.4 | MIT; library CBOR processing |
| `github.com/go-viper/mapstructure/v2` | 2.5.0 | MIT; library data decoding |
| `github.com/golang-jwt/jwt/v5` | 5.3.1 | MIT; upstream attestation support, not application session JWTs |
| `github.com/google/go-tpm` | 0.9.8 | Apache-2.0; upstream TPM attestation support |
| `github.com/google/uuid` | 1.6.0 | BSD-3-Clause; authenticator metadata |
| `github.com/philhofer/fwd` | 1.2.0 | MIT; upstream codec support |
| `github.com/tinylib/msgp` | 1.6.4 | MIT with original Go notices; upstream codec support |
| `github.com/x448/float16` | 0.8.4 | MIT; CBOR support |

No upstream source is copied or relicensed. `make build` preserves linked
module/runtime notices in `bin/browser-notices`; both WASM manifests retain the
original CIRCL/Go/x-crypto/x-sys notices. Redistribute those with generated binaries.
The default application image includes these notices and both matched worker
runtimes; it does not include the offline key CLI or inert servers. No npm
build, third-party browser library, CDN or authentication fallback is introduced.

x/crypto and x/sys are maintained Go project libraries that avoid a custom KDF
or AEAD. Admission for device-backup profile 2 includes Argon2id, BLAKE2b,
ChaCha20-Poly1305, its ChaCha20/Poly1305 and alias helpers, and CPU-feature detection.
The standard 12-byte-nonce `New` API is selected, not `NewX` or a custom primitive.
The [pinned API and source](https://pkg.go.dev/golang.org/x/crypto@v0.58.0/chacha20poly1305)
were reviewed against RFC 8439 on 2026-10-27. Package admission does not establish
independent cryptographic review or browser performance. FIPS-only configurations
may reject this algorithm; there is no algorithm fallback or FIPS-validation claim.

- **Licensing:** both pinned module `LICENSE` files use BSD-3-Clause and retain
  the original Go copyright holder; `PATENTS` grants remain upstream. No source is
  copied or relicensed. Client binaries must preserve these notices and terms.
  See the pinned [x/crypto](https://cs.opensource.google/go/x/crypto/+/v0.58.0:LICENSE)
  and [x/sys](https://cs.opensource.google/go/x/sys/+/v0.49.0:LICENSE) licenses.
- **Security:** `make vuln` checks the used package graph for known advisories,
  not correctness or independent audit. Upgrades require the same admission review;
  removal requires a reviewed replacement profile and compatibility plan, never
  a silent KDF fallback.
- **Excluded package:** the admission scan reports
  [GO-2026-5932](https://pkg.go.dev/vuln/GO-2026-5932) in x/crypto's unmaintained
  OpenPGP package, with no fixed version. It is neither imported nor reachable.
  Do not introduce OpenPGP through this dependency.

### Database migration modules

Admitted on 2026-10-28 for the separate local operator runner and internal identity
account store, also used by the internal submission record store from 2026-10-29.
The stores use pgx/pgxpool, not Goose or the SQL adapter. HTTP services,
device cryptography, and WASM import none of these modules. The native driver and
Goose Provider avoid custom PostgreSQL wire handling and migration parsing. Exact
direct/transitive pins and checksums are in `go.mod` and `go.sum`.

| Module | Version | License and linked purpose |
| --- | --- | --- |
| [pgx/v5](https://github.com/jackc/pgx/tree/v5.11.0) | 5.11.0 | MIT; PostgreSQL protocol and `database/sql` adapter |
| [pgpassfile](https://github.com/jackc/pgpassfile/tree/v1.0.0) | 1.0.0 | MIT; pgx configuration helper |
| [pgservicefile](https://github.com/jackc/pgservicefile/tree/5a60cdf6a761) | 0.0.0-20240606120523-5a60cdf6a761 | MIT; pgx configuration helper |
| [puddle/v2](https://github.com/jackc/puddle/tree/v2.2.3) | 2.2.3 | MIT; pgx adapter's linked pool helpers |
| [goose/v3](https://github.com/pressly/goose/tree/v3.29.0) | 3.29.0 | MIT; embedded transactional SQL and version history |
| [interpolate](https://github.com/mfridman/interpolate/tree/v0.0.2) | 0.0.2 | MIT; Goose SQL parser dependency; environment substitution stays disabled |
| [go-retry](https://github.com/sethvargo/go-retry/tree/v0.5.0) | 0.5.0 | Apache-2.0; Goose initialization retries |
| [multierr](https://github.com/uber-go/multierr/tree/v1.11.0) | 1.11.0 | MIT; Goose error composition |
| [x/sync](https://pkg.go.dev/golang.org/x/sync@v0.24.0) | 0.24.0 | BSD-3-Clause; synchronization helpers |
| [x/text](https://pkg.go.dev/golang.org/x/text@v0.43.0) | 0.43.0 | BSD-3-Clause; PostgreSQL text preparation |

The pinned modules' license files and imported package graph were reviewed. Their
original licenses are copied unchanged into the separate migration image, with
Go patent notices for x/sync and x/text. No upstream source is copied or relicensed.
Goose's other database drivers/CLI and dependency test packages are not linked.
The runner does not load `.env`, arbitrary SQL files, or alternate drivers.

`make vuln` checks reachable advisories and static errors, not protocol correctness
or an independent audit. `make db-migration-test` tests actual pgx/Goose behavior and
PostgreSQL privileges. Updates require reviewing the imported graph, upstream
licenses/security status, Docker notice paths, and migration tests together. Remove
unused modules if their importing components are removed; do not substitute a handwritten
SQL migration parser. Production TLS and HTTP storage integration need separate review.

The `account-test` Docker target is development-only and retains the existing Go
builder image, including its upstream notices, to run a compiled race-enabled
PostgreSQL test binary. It is not the scratch application image or a release asset.
No new module version or product dependency is introduced.

The `submission-record-test` target uses the same builder and admitted pgx graph
for race-enabled runtime-role storage checks. Its test binary links no additional
module or cryptographic package. Like the account/backup test images, it is not an
application or release asset. Original builder and module notices remain unchanged.

### WASM runtime support

The public-only verifier imports only standard-library packages and the shared
member-request parser. `make wasm` copies Go 1.27.3's unmodified
[loader](https://github.com/golang/go/blob/go1.27.3/lib/wasm/wasm_exec.js),
[license](https://github.com/golang/go/blob/go1.27.3/LICENSE), and
[patent grant](https://github.com/golang/go/blob/go1.27.3/PATENTS) beside the build.
Their reviewed SHA-256 hashes are pinned in `scripts/wasm.toml`; original upstream
notices stay intact. No upstream asset or generated WASM is checked in or served
by the shell. Updating Go requires reviewing these pins and rerunning compatibility
and security checks (sources accessed 2026-10-27).

The separate `make member-wasm` module also links the already admitted x/crypto
and x/sys packages through the shared session. It copies each module's unchanged
`LICENSE` and `PATENTS` alongside the artifact as `LICENSE.x-crypto`,
`PATENTS.x-crypto`, `LICENSE.x-sys`, and `PATENTS.x-sys`. Their contents match the
reviewed Go notice hashes above and are verified independently from module-cache
sources; replaced module sources are rejected. No additional dependency is admitted.
On an empty cache, the build downloads the selected module versions before reading
their notices, including modules omitted by platform-specific imports. The same
source and notice-hash checks apply after download.
It also packages first-party worker/client modules using standard browser APIs,
without an npm install, third-party asset, or JavaScript cryptographic dependency.

Node.js is pinned in the same manifest and CI. Use official
[22.23.3 archives and checksums](https://nodejs.org/dist/v22.23.3/SHASUMS256.txt)
and retain its upstream notices if redistributing that external test runtime.
Only built-in assertion, crypto, filesystem, module, path, URL, test, and worker-thread
facilities are used by the test runners. The public verifier runner handles no
passwords. The member runner handles only synthetic unlock bytes, encrypted backups,
and public enrollment material for interoperability checks, never private-key
fixtures or real credentials.

### Browser-test runtime

The opt-in [member-worker browser checks](testing.md#member-worker-browser-checks)
use the open-source Chromium snapshot, not branded Chrome. The
[official snapshot distribution](https://www.chromium.org/getting-involved/download-chromium/#chromium)
and [Chromium license](https://chromium.googlesource.com/chromium/src/+/main/LICENSE)
were consulted 2026-10-28. The external browser retains its BSD-3-Clause license
and bundled third-party notices. No binary, browser library, or upstream source
is copied into this repository or distributed with the product.

The exact archive digest and version are pinned in `scripts/browser.toml`; the
driver checks the executable's version and requires an explicitly supplied path.
Users must verify the archive digest before extraction/execution. This does not
authenticate a hostile replacement executable or its shared libraries. The
snapshot has no automatic security updates and is admitted only for local synthetic
tests, not ordinary browsing or a product support promise. Review upstream security
status, source/notices, version/digest, and browser tests when updating it. A broader
reviewed browser suite may replace this focused runtime. No automatic installer,
third-party driver, or browser package manager is added.

### Container runtime and images

The default local stack uses open-source Docker Engine and Compose, not a required Docker
Desktop subscription. Both upstream projects use Apache-2.0. Local observations on
2026-10-28 are Engine 29.9.2 and Compose 5.6.1. Engine 28 or newer is required for
the documented loopback publication boundary. Other engines/platforms need separate
validation before support is claimed.

| Image | Admitted purpose and index SHA-256 |
| --- | --- |
| `golang:1.27.3-bookworm` | Build-only official image; `df4bb0305771186a85d0fd3a40f5c5da9af97ac8053d391ffce2c070817a20c6` |
| `postgres:18.6-bookworm` | Independent development databases; `5c4783a8cc3f0074912164f94dfa1be4e043438f0f707cf968d7af9a0d31a2c8` |

Digests were retrieved from the official registry on 2026-10-28. Reviewed upstream
build definitions are [Go](https://github.com/docker-library/golang/tree/41d9b4da70324ae7b6461ac2cc401b06719ff57d/1.27/bookworm)
and [PostgreSQL](https://github.com/docker-library/postgres/tree/e00e1bd34ec5c8a8e7ad89b273b3d42efaf6d5bc/18/bookworm).
Go's BSD-3-Clause license/patent notice and the project AGPL license are copied
unchanged into the scratch application image. The browser services link the
already admitted authentication, protocol and pgx modules; `make build` collects
their unchanged notices for the image, together with matched WASM notices. The separate `migration` target
contains only the operator binary and its reviewed module notices above. Builder
operating-system packages do not enter that final image.

PostgreSQL uses the [PostgreSQL License](https://www.postgresql.org/about/licence/).
Its official Debian image retains original package notices and bundled licenses;
it is not relicensed as project code. No upstream source is copied into this
repository. Image admission is not a complete transitive license or vulnerability
audit. `make vuln` does not scan operating-system packages; container scanning and
SBOM generation remain unavailable. Keep this stack synthetic-only.

Updating a pin requires reviewing upstream packages, licenses, security status,
non-root IDs, volume layout, and real-container checks. Update `Dockerfile`, Compose,
the policy check, and this reference together. Never fall back to floating tags.
Secret preparation uses Python's standard OS-backed `secrets` module, with no new
application module or Python package.

### Documentation theme

mdBook setup verifies official release-API digests and reviewed notice hashes.
Generated docs preserve holders/licenses in `assets/upstream-licenses/`. No upstream
executable or asset is checked in.

| Component | Bundled version | License and treatment |
| --- | --- | --- |
| mdBook theme | 0.5.4 | MPL-2.0; unmodified script contents and [corresponding source](https://github.com/rust-lang/mdBook/tree/v0.5.4/crates/mdbook-html/front-end) remain available |
| Highlight.js | 10.1.1 | BSD-3-Clause; embedded notice and full license retained |
| clipboard.js | 2.0.4 | MIT; embedded copyright retained, with the same holder's full MIT text from the upstream 2.0.11 license file |
| mark.js | 8.11.1 | MIT; embedded notice and full license retained |
| elasticlunr.js | 0.9.5 | MIT; embedded notice and full license retained |
| Font Awesome Free SVG icons | 6.2.0, via font-awesome-as-a-crate 0.3.1 | CC-BY-4.0 for icons; original Font Awesome license/attribution file retained |

Versions come from pinned mdBook source/Cargo lockfile on the access date above,
not an independent audit. Current tools can bundle old browser libraries.
Docs contain no private data or runnable remote playground. Device fonts replace
bundled fonts; no font binaries are published. Docs assets are separate from product dependencies.

## Proposed product dependencies

Browser accounts target [WebAuthn Level 3](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/)
as the authentication design reference (consulted 2026-10-27). PRF unlocking needs
actual browser/provider evidence and a separately reviewed wrapping profile; the
presence of a passkey library is not proof of encrypted-key recovery support.
See [the decision and research](key-management.md#browser-account-vault).
No new library or browser asset is admitted by this design update.

| Dependency | Observed version | License | Purpose |
| --- | --- | --- | --- |
| [PostgreSQL](https://www.postgresql.org/support/versioning/) | 18.6 | PostgreSQL | Independent service databases |
| [pgx](https://github.com/jackc/pgx) | 5.11.0 | MIT | Native PostgreSQL driver |
| [Goose](https://github.com/pressly/goose) | 3.29.0 | MIT | Separate SQL migration histories |
| [CIRCL](https://github.com/cloudflare/circl) | 1.6.5 | BSD-3-Clause | Blind RSA implementation |
| [x/mod](https://pkg.go.dev/golang.org/x/mod/sumdb/tlog) | 0.42.0 | BSD-3-Clause | Tree/proof and signed-note routines |
| [go-webauthn](https://pkg.go.dev/github.com/go-webauthn/webauthn) | 0.18.2 | BSD-3-Clause | Passkey verification |
| [otp](https://pkg.go.dev/github.com/pquerna/otp) | 1.5.0 | Apache-2.0 | TOTP fallback |
| [Pico](https://github.com/picocss/pico) | 2.1.1 | MIT | Vendored CSS |
| [Inter](https://github.com/rsms/inter) | 4.1 | OFL-1.1 | Unmodified local font assets |
| [Lucide](https://lucide.dev/license) | Exact icon revision pending | ISC and MIT for inherited icons | Selected static SVGs, both notice sets retained |
| [SoftHSM](https://github.com/softhsm/SoftHSMv2) | 2.7.0 | BSD-2-Clause | Optional PKCS#11 simulation |

See [architecture](architecture.md), [cryptography](cryptography.md),
[database](database.md), and [UI design](ui-design.md) for requirements.
Pin toolchain and module/asset hashes on implementation. Keep browser-development
packages outside the product build and review transitive licenses. Admit test/release
tools with real targets, not speculative inventories.

## Review method

- Require purpose, maintained upstream, exact version/hash, compatible license,
  retained copyright, security review, and removal/update plan.
- Reject unknown/incompatible licenses. Review fonts/icons as assets, not modules.
  Never replace upstream copyright with project authorship.
- Required tools must be openly licensed and locally runnable. Optional hosted
  services cannot become hidden build/check prerequisites.
- Follow [dependency-update review and identity rules](../CONTRIBUTING.md#dependency-updates).

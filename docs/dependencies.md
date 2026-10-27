<!-- SPDX-FileCopyrightText: 2026 Anonce Contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Dependencies and licenses

Audience: maintainers, redistributors, and license reviewers.

Accessed: 2026-10-26. Proposed versions below are observations, not a transitive
license or vulnerability audit. HTTP commands use only the standard library;
the shared device-backup package imports the admitted modules below. No runtime
dependencies or assets are vendored. Recheck artifacts, hashes, licenses, and
advisories before further imports.

## Current materials

| Material | License | Treatment |
| --- | --- | --- |
| Original code, documentation, and repository checks | AGPL-3.0-only | SPDX headers; [license](../LICENSE) |
| Read-only shell templates and CSS | AGPL-3.0-only | Original embedded assets; device fonts, no third-party product assets or browser packages |
| Contributor Covenant 3.0 adaptation | CC-BY-SA-4.0 | Upstream attribution and separate document license retained |
| Python standard library | PSF-2.0 | External interpreter, not copied into the project |
| Git and GNU Make | GPL-2.0-only / GPL-3.0-or-later upstream tools | External development tools, not project relicensing |
| REUSE 6.2.0 | GPL-3.0-or-later upstream tool | External compliance check; [REUSE 3.3 specification](https://reuse.software/spec-3.3/) |
| [mdBook 0.5.4](https://github.com/rust-lang/mdBook/releases/tag/v0.5.4) | MPL-2.0 | Documentation-only tool; official release archives and asset notices pinned in `scripts/mdbook.toml` |
| pip-tools 7.6.2 | BSD-3-Clause | External documentation lock compiler |
| [Go 1.27.3](https://go.dev/dl/?mode=json) | BSD-3-Clause | Pinned standard-library runtime and external compiler; WASM build copies the matching loader and original notices unchanged |
| [Node.js 22.23.3](https://nodejs.org/dist/v22.23.3/) | MIT with bundled third-party notices | External development-only WASM test runtime; no npm dependencies or Node product build |
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

### Admitted Go modules

x/crypto and x/sys are maintained Go project libraries that avoid a custom KDF
or AEAD. Admission for device-backup profile 2 includes Argon2id, BLAKE2b,
ChaCha20-Poly1305, its ChaCha20/Poly1305 and alias helpers, and CPU-feature detection.
The standard 12-byte-nonce `New` API is selected, not `NewX` or a custom primitive.
The [pinned API and source](https://pkg.go.dev/golang.org/x/crypto@v0.58.0/chacha20poly1305)
were reviewed against RFC 8439 on 2026-10-27. No module version or hash changes are
needed; package admission does not establish independent cryptographic review or
browser performance. FIPS-only configurations may reject this algorithm; there
is no AES fallback or FIPS-validation claim.

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

Node.js is pinned in the same manifest and CI. Use official
[22.23.3 archives and checksums](https://nodejs.org/dist/v22.23.3/SHASUMS256.txt)
and retain its upstream notices if redistributing that external test runtime.
Only built-in assertion, crypto, filesystem, module, and path facilities are used
by the test runner. No Node code handles passwords or private-key fixtures.

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

<!-- SPDX-FileCopyrightText: 2026 Anonce Contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Dependencies and licenses

Audience: maintainers, redistributors, and license reviewers.

Accessed: 2026-10-26. Versions below are observations, not a transitive license or
vulnerability audit. Runtime uses only the Go standard library; proposed modules/assets
are not imported or vendored. Recheck exact artifacts, hashes, licenses, and advisories before import.

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
| [Go 1.27.3](https://go.dev/dl/?mode=json) | BSD-3-Clause | Pinned standard-library runtime and external compiler; no third-party runtime modules |
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
- mdBook setup verifies official release-API digests and individually reviewed notice
  hashes. Generated docs keep unchanged holders/licenses in `assets/upstream-licenses/`.
  No upstream executable or asset is checked in.

Published theme components:

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

| Dependency | Observed version | License | Purpose |
| --- | --- | --- | --- |
| [PostgreSQL](https://www.postgresql.org/support/versioning/) | 18.6 | PostgreSQL | Independent service databases |
| [pgx](https://github.com/jackc/pgx) | 5.11.0 | MIT | Native PostgreSQL driver |
| [Goose](https://github.com/pressly/goose) | 3.29.0 | MIT | Separate SQL migration histories |
| [CIRCL](https://github.com/cloudflare/circl) | 1.6.5 | BSD-3-Clause | Blind RSA implementation |
| [x/crypto](https://pkg.go.dev/golang.org/x/crypto/argon2) | 0.58.0 | BSD-3-Clause | Argon2id |
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

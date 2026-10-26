<!-- SPDX-FileCopyrightText: 2026 Anonce Contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Dependencies and licenses

Audience: maintainers, redistributors, and license reviewers.

Verified access date: 2026-10-26. Version observations are not a completed transitive
license or vulnerability audit. Runtime dependencies are not installed or vendored
yet. Recheck each exact artifact, checksum, license, and advisory before import.

## Current materials

| Material | License | Treatment |
| --- | --- | --- |
| Original documentation and repository checks | AGPL-3.0-only | SPDX headers; [license](../LICENSE) |
| Contributor Covenant 3.0 adaptation | CC-BY-SA-4.0 | Upstream attribution and separate document license retained |
| Python standard library | PSF-2.0 | External interpreter, not copied into the project |
| Git and GNU Make | GPL-2.0-only / GPL-3.0-or-later upstream tools | External development tools, not project relicensing |
| REUSE 6.2.0 | GPL-3.0-or-later upstream tool | External compliance check; REUSE 3.3 specification |
| [mdBook 0.5.4](https://github.com/rust-lang/mdBook/releases/tag/v0.5.4) | MPL-2.0 | Documentation-only tool; official release archives and asset notices pinned in `scripts/mdbook.toml` |
| pip-tools 7.6.2 | BSD-3-Clause | External documentation lock compiler |

Upstream tool licenses do not change the project's AGPL-3.0-only grant. The project
does not offer dual licensing. Every redistributed upstream file must keep its own
notice and have the applicable license text under `LICENSES/`.

The mdBook installer verifies release archive digests reported by the official
release API, and downloads original notices with individually reviewed hashes.
Generated documentation retains those texts under `assets/upstream-licenses/`
without changing upstream holders or licenses. No upstream executable or asset is
checked into this repository. The published theme uses these bundled components:

| Component | Bundled version | License and treatment |
| --- | --- | --- |
| mdBook theme | 0.5.4 | MPL-2.0; unmodified script contents and [corresponding source](https://github.com/rust-lang/mdBook/tree/v0.5.4/crates/mdbook-html/front-end) remain available |
| Highlight.js | 10.1.1 | BSD-3-Clause; embedded notice and full license retained |
| clipboard.js | 2.0.4 | MIT; embedded copyright retained, with the same holder's full MIT text from the upstream 2.0.11 license file |
| mark.js | 8.11.1 | MIT; embedded notice and full license retained |
| elasticlunr.js | 0.9.5 | MIT; embedded notice and full license retained |
| Font Awesome Free SVG icons | 6.2.0, via font-awesome-as-a-crate 0.3.1 | CC-BY-4.0 for icons; original Font Awesome license/attribution file retained |

These versions are observations from the pinned mdBook source and Cargo lockfile
on the access date above, not an independent transitive security audit. Do not
infer that old bundled browser libraries are current merely because the tool is
current. Documentation contains no private data or runnable remote playground.
Device fonts replace the bundled font files; no font binaries are published.
Documentation assets are separate from future product browser dependencies.

## Proposed product dependencies

| Dependency | Observed version | License | Purpose |
| --- | --- | --- | --- |
| [Go](https://go.dev/dl/?mode=json) | 1.27.3 | BSD-3-Clause | HTTP, templates, embedding, cryptography, CLI/WASM |
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

Technical requirements belong in [architecture](architecture.md),
[cryptography](cryptography.md), [database](database.md), and [UI design](ui-design.md).
Pin the toolchain and exact module/asset hashes when implementation is introduced.
Browser-development packages remain separate from the product build and require
transitive license review. Admit testing and release tools when their real targets
are added, rather than maintaining a speculative tool inventory.

## Review method

Require a purpose, maintained upstream, exact version/hash, compatible grant, retained
copyright, security review, and a removal/update plan. Reject unknown licenses or
copyleft incompatibilities rather than guessing. Review fonts/icons as assets, not
Go modules. Upstream copyright notices are not replaced with project authorship.
Optional hosted services cannot become a hidden prerequisite for product builds or
required checks. Required tools must be openly licensed and locally runnable. Follow
[contributing](../CONTRIBUTING.md#dependency-updates) for update review and identity rules.

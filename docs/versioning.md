<!-- SPDX-FileCopyrightText: 2026 Anonce Contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Versioning and compatibility

Audience: maintainers, integrators, and client authors.

Consult and follow the official [SemVer 2.0.0 specification](https://semver.org/spec/v2.0.0.html).
The requirements below define its project-specific application, not a replacement
for the specification. Use `vMAJOR.MINOR.PATCH` tags.
First release: `v0.1.0`; no tag yet.
Unstable `0.y.z` changes still require compatibility review.

## Public API boundary

Public contracts include:

- CLI commands, flags, exits; HTTP paths, statuses, schemas.
- Wire/token/envelope formats; keystores/backups; certificate profiles and trust rules.
- Database migration ranges; configuration keys/environment variables.
- Versioned forms/bulletins; documented client-visible asset hashes and receipt profiles.

Internal Go packages are unstable implementation details. Future public modules
must use `/vN` module/import paths for breaking v2+ releases, even in a monorepo.

**Current interfaces:** commands report `development`; see [API](api.md) and
[deployment](deployment.md#local-development). Infrastructure and shell additions
are unreleased, not stable wire profiles or a product. Future crypto formats need
explicit breaking review.

The [browser account/vault direction](key-management.md#browser-account-vault)
is a documentation requirement, not a new supported API or cryptographic profile.
Existing CLI, WASM, and HTTP contracts remain unchanged; making the CLI optional
for product use does not remove its documented interfaces. Before implementation,
review account/vault APIs, recovery and wrapping formats, credential binding, and
anonymous handoff compatibility explicitly. Do not silently reinterpret profile 2
as a PRF-based format or migrate keys during a failed unlock.

The [in-memory member session](key-management.md#in-memory-member-sessions) is an
unstable internal Go component, not a public account/vault or browser interface.
It reuses the existing backup, member-key, and CSR profiles. No wire format,
parameter, CLI, HTTP, or WASM contract changes; the formats' independent-review
and breaking-impact requirements remain in force.

### Cryptographic file compatibility

The following formats are unreleased breaking additions requiring `semver:major`
review and independent security review before real-key use. No released
compatibility baseline exists.

| Contract | Compatibility boundary |
| --- | --- |
| [Device-backup profile 2](cryptography.md#device-backup-profile-2) | Argon2id and ChaCha20-Poly1305; format version 1/profile byte 2; unsupported profiles fail before derivation |
| [Member-key payload profile 1](cryptography.md#member-key-payload-profile-1) | Canonical Ed25519 PKCS #8 inside member-purpose backups |
| [Reviewer-key payload profile 1](cryptography.md#reviewer-key-payload-profile-1) | Canonical X25519 PKCS #8 inside reviewer-purpose backups |
| [Member CSR profile 1](cryptography.md#member-csr-profile-1) | Fixed identity-free Ed25519 PKCS #10 DER; no alternate claims or enrollment transport |

Typed key importers reject opaque, wrong-algorithm, and noncanonical payloads.
Their addition does not change the outer format, generic opaque keystore API,
or HTTP/CLI contracts.

### Shell compatibility

Submission `/` changed from JSON `404` to HTML `200`,
breaking HTTP behavior even before release. Consumers expecting root errors must
use explicit infrastructure endpoints. `/about`, hashed CSS, and opt-in
`-dev-styleguide` are new. CA/issuer roots remain JSON `404`; infrastructure JSON is unchanged.

### Local key CLI compatibility

`client generate` and `client inspect` are new
opt-in commands requiring `semver:minor` review. Their flags, stdin framing, exits,
file-custody rules, and public-key output are documented in
[key management](key-management.md#local-key-cli). Existing HTTP commands and
encrypted backup/payload formats are unchanged. This does not remove the existing
breaking-impact or independent-review requirements for those unreleased formats.

`client rewrap` is an additive opt-in command requiring `semver:minor` review.
Its three-line password framing applies only to that command. Existing commands,
password framing, backup/payload formats, and HTTP behavior remain unchanged.

The optional `client rewrap -expect-public-key HEX` is an additive interface requiring
`semver:minor` review. It checks the complete public key after typed backup validation,
before replacement-password derivation or file creation. Omitting it preserves
existing rewrapping. Password framing, backup/payload formats, other commands,
WASM, and HTTP behavior are unchanged.

The optional `client inspect -expect-public-key HEX` is an additive interface
requiring `semver:minor` review. For either supported key kind it checks the complete
public key after typed backup validation, before output. Omitting it preserves
existing inspection. Password framing, backup/payload formats, request verification,
WASM, and HTTP behavior are unchanged.

`client csr` adds an opt-in member-only command with one-line password framing and
binary DER stdout. The new cryptographic request profile requires `semver:major`
review under the format policy above. Existing commands, encrypted backups, and
HTTP behavior are unchanged. No certificate or enrollment compatibility is claimed.

The optional `client csr -out PATH` is an additive interface requiring
`semver:minor` review. It selects owner-only, no-replace file publication instead
of stdout. Omitting it preserves the existing stdout contract; other commands,
password framing, cryptographic profiles, and HTTP behavior are unchanged.

The optional `client csr -expect-public-key HEX` is an additive interface requiring
`semver:minor` review. It checks the complete member public key after typed backup
validation, before request signing or file creation, for both stdout and `-out`.
Omitting it preserves existing CSR creation. Password framing, cryptographic
profiles, other commands, WASM, and HTTP behavior are unchanged.

`client verify-csr` is an additive opt-in command requiring `semver:minor` review.
It reads an owner-only request file, does not read stdin, and prints the same
public-key line as `inspect` after validating the existing CSR profile. Existing
commands, password framing, cryptographic formats, and HTTP behavior are unchanged.

The optional `client verify-csr -expect-public-key HEX` is an additive interface
requiring `semver:minor` review. It checks the complete expected public key after
validating the request, before output. Omitting the flag preserves existing
behavior. Cryptographic profiles and the WASM interface are unchanged.

Optional `client inspect -out PATH` and `client verify-csr -out PATH` are additive
interfaces requiring `semver:minor` review. They select owner-only, no-replace file
publication of the existing public-key line after validation and optional expected-key
matching. Omitting the flag preserves stdout behavior. Password framing, cryptographic
profiles, WASM, and HTTP behavior are unchanged.

Optional `-expect-public-key-file PATH` on `inspect`, `rewrap`, `csr`, and
`verify-csr` is an additive interface requiring `semver:minor` review. It reads the
existing canonical public-key export for the selected kind and is mutually exclusive
with `-expect-public-key HEX`. Omitting it preserves existing behavior. Password
framing, output, cryptographic profiles, WASM, and HTTP behavior are unchanged.
See [expected-key files](key-management.md#local-expected-key-files) for exact grammar,
file-custody requirements, and trust limits.

### WASM verifier compatibility

The [public-only WASM verifier](key-management.md#local-wasm-request-verification)
is an additive opt-in development interface requiring `semver:minor` review. Its
namespace, methods, bounded hex input, public-key output, rejection, and shutdown
behavior are new contracts. Existing CLI commands, HTTP behavior, and cryptographic
profiles are unchanged. No browser delivery or private-key compatibility is claimed.

`verifyCSRForKey(hex, expectedHex)` is an additive opt-in method requiring
`semver:minor` review. It requires an independently trusted expected key, validates
the unchanged request profile/signature, and rejects mismatches without public
output. Existing `verifyCSR` arity, output, and rejection behavior, shutdown, CLI,
HTTP, and cryptographic profiles are unchanged.

### WASM member session compatibility

The [member-session bridge](key-management.md#local-wasm-member-sessions) is a
separate opt-in development interface requiring `semver:minor` review. Its namespace,
byte-array inputs/outputs, Promise/null results, single-session admission, and lock/
shutdown behavior are new contracts. The existing public verifier, CLI, HTTP,
and cryptographic profiles are unchanged. This adds no browser page, account/vault
API, PRF/recovery format, or supported-browser claim. Existing format-breaking and
independent-review requirements still apply.

The [local worker owner](key-management.md#local-member-worker-host) is an additive
opt-in development interface requiring `semver:minor` review. Its module export,
readiness, version-1 correlated transport, singleton/admission limits, timeouts,
and terminal lock/disposal are new contracts. Unlike direct-bridge lock, owner lock
permanently terminates its instance; restoration requires a new explicit instance.
Direct WASM bridge methods, cryptographic formats, CLI, and HTTP are unchanged.
No page delivery, account API, or supported-browser claim is added.

Requiring BroadcastChannel and global page event APIs and notifying peers on explicit
owner lock is a breaking development lifecycle change requiring `semver:major`
review under the current pre-1.0 policy. Hosts must provide those browser facilities
or startup fails closed. Use the new `lockMemberWorkers()` export for future logout
or account-switch notifications even after local disposal; use `close()` for local
disposal only. Hosts must handle terminal pagehide without reusing the old instance.
The [fixed notification contract and delivery limits](key-management.md#lock-notifications-and-page-disposal)
are separate from the unchanged version-1 worker command transport. Direct bridge
methods, cryptographic profiles, CLI, and HTTP behavior are unchanged.

The opt-in [browser check target](testing.md#member-worker-browser-checks) adds only
test-binary delivery and external development-tool setup. It changes no product
HTTP route, shell CSP, worker contract, or cryptographic format, and carries no
automatic release bump under the test-change policy below.

## Change classification

Use the official SemVer definitions for stable releases. During `0.y.z`, apply
this project policy:

| Impact | Project policy during `0.y.z` |
| --- | --- |
| MAJOR | Increase MINOR; document breaking impact and migration |
| MINOR | Increase MINOR |
| PATCH | Increase PATCH |

Treat removed flags/configuration, unsafe migration ranges, and incompatible
public contracts as breaking changes. Security fixes are not automatically PATCH:
rejecting unsafe parameters or changing trust anchors may require operator action.
Cryptographic, wire-format, and parameter changes are breaking without a reviewed
compatibility mechanism. Never retain insecure paths for compatibility.

## Commit and PR mapping

Follow the official [Conventional Commits 1.0.0 specification](https://www.conventionalcommits.org/en/v1.0.0/)
for commit meaning and breaking-change notation. Project requirements:

- Compatible `perf` changes normally have PATCH impact; all breaking changes require review.
- Docs/tests/CI/maintenance: no automatic bump unless public behavior changes.
- Review the diff; labels do not replace compatibility analysis.
- Every PR needs exactly one `semver:major`, `semver:minor`, or `semver:patch`.
  `semver:major` means breaking impact during `0.y.z` too; apply the unstable policy above.
- Non-release work may use `semver:patch` plus `changelog:not-needed` with maintainer rationale.

## Changelog contract

Consult and follow the official [Keep a Changelog 1.1.0 guidance](https://keepachangelog.com/en/1.1.0/)
for format, categories, dates, links, and withdrawn releases. Project requirements:

- Maintain the human-curated [CHANGELOG.md](../CHANGELOG.md).
- PRs change content inside Unreleased unless a maintainer applies `changelog:not-needed`.
- Automation extracts reviewed sections, never replaces the changelog with commit
  messages or reformats curated prose.

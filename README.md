<!-- SPDX-FileCopyrightText: 2026 Anonce Contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# anonce

**Anonymous submissions. Verified members. Configurable response limits.**

[![License: AGPL-3.0-only](docs/images/license.svg)](LICENSE)
[![Development status](docs/images/status.svg)](docs/README.md)

anonce is designed for feedback, reports, and ballots from verified members without
linking identities to submissions.

The intended experience is entirely web-based: sign in, open a shared review link
or choose an available round, complete the form, and submit. Members, reviewers,
and administrators need no installed app or CLI. The browser manages cryptographic
keys automatically, with encrypted member-key backups on the identity side.
The separate opt-in local browser MVP implements this path for one free-text
question, one reviewer and an explicitly selected one-response limit. See
[browser startup](docs/deployment.md#browser-mvp-local-startup),
[the user flow](docs/ui-design.md#account-and-review-workflow) and
[key custody and recovery](docs/key-management.md#browser-account-vault).

> **Development only.** The browser MVP is for synthetic data and has no independent
> security approval. Original demonstration services remain inert. Do not collect
> sensitive information or run an election.

## Planned capabilities

- Membership certificates, published revocation information, and device-held keys.
- Administrator-set response limits per member and round, enforced through blind
  authorization tokens that each permit one submission.
- An independently deployed submission service storing ciphertext rather than answers.
- Reviewer-side decryption, private replies, and response-threshold controls.
- Public inclusion receipts and a separate administrative audit trail.
- A self-hosted browser interface using shared device-side Go cryptography;
  optional CLI tools are not prerequisites for users.

See the [roadmap](docs/roadmap.md) and [threat model](docs/threat-model.md)
for scope and required evidence.

The administrator sets one response limit for all eligible members before publishing
a round. Changing the published limit requires a new round ID.

## Contribute now

Use Go 1.27.3, Python 3.11 or newer, Node.js 22.23.3, Git, GNU Make, and REUSE 6.2.0 for local checks.
The Go launcher can download the pinned toolchain. ExifTool is required when tracked
binary images, fonts, or PDFs are added.

```sh
git clone git@github.com:mandipnotroot/anonce.git
cd anonce
make setup
make check
```

Read [CONTRIBUTING.md](CONTRIBUTING.md) for the workflow and [AGENTS.md](AGENTS.md)
for repository rules. The [roadmap](docs/roadmap.md) tracks implementation and
local deployment.

## Run the local infrastructure

For the connected workflow, use the separate
[browser MVP startup](docs/deployment.md#browser-mvp-local-startup) and
[real-browser/PostgreSQL checks](docs/testing.md#connected-browser-mvp-checks).
It has signed storage acceptance, not public-log inclusion or rollback protection.
Recovery, protected signers and reviewer server backups are excluded.

The commands and foundation limitations below describe the original demonstration
services, not the opt-in browser hosts.

For containerized development, follow the [Compose setup](docs/deployment.md#container-stack):
prepare `.env` and local secret files, then use `make up`, `make smoke`, and
`make down`. The stack builds the Go services in Docker and runs two independent
PostgreSQL instances. `make container-test` checks disposable infrastructure, not a
working submission product.

Separate [local database migrations](docs/deployment.md#local-database-migrations)
are opt-in through `make migrate-identity` and `make migrate-submission`.
`make db-migration-test` checks their histories and grants on disposable PostgreSQL;
identity version 2 adds internal account/session tables. `make db-account-test`
checks persistence, expiry, revocation, concurrency, and grants as the runtime role.
Identity version 3 adds internal encrypted member-backup slots, checked by
`make db-member-backup-test`. Account authentication, product vault access, and
HTTP persistence remain unavailable.

Submission version 2 adds internal atomic ciphertext/spend storage with exact-payload
retries and round admission/cancellation. `make db-submission-record-test` checks it
on disposable real PostgreSQL. This is not token verification or a working submission
endpoint. See the [storage contract](docs/database.md#implemented-submission-record-storage).

To run the HTTP demonstration natively instead:

```sh
make build test
./bin/server -source-url "$ANONCE_SOURCE_URL"
```

Set `ANONCE_SOURCE_URL` to the HTTPS location of this build's exact corresponding
source, including local modifications. There is no default.

- Default binds: server `127.0.0.1:8080`, issuer port `8081`, CA port `8082`.
- Infrastructure: `/healthz`, `/api/v1/status`, and `/source`.
- Unavailable operations: `/readyz` always returns `503`; owned protocol routes
  return `501` without reading request bodies.
- Read-only server pages: `/` and `/about`. `-dev-styleguide` enables labelled mocks.
- No forms, application database integration, signing, enrollment, or submission operations.

See [deployment](docs/deployment.md#local-development) for flags and limits and
[API](docs/api.md) for endpoint behavior.

Optional local development key tools are also available:

- Shared Go packages for [ChaCha20-Poly1305 backup encryption](docs/cryptography.md#device-backup-profile-2)
  and [member/reviewer-key generation, encrypted export, and validated import](docs/key-management.md#device-keystores).
- Shared [in-memory member sessions](docs/key-management.md#in-memory-member-sessions)
  for automatic key/backup/request preparation, expected-key restoration, and lock;
  no private-key export or account integration.
- An [offline CLI](docs/key-management.md#local-key-cli) for encrypted backup
  generation, public-key-only inspection, backup password changes, and local member
  certificate requests. Requests do not enroll a member or issue a certificate.
- A [public-only WASM request verifier](docs/key-management.md#local-wasm-request-verification),
  built with `make wasm` and checked with `make wasm-test`.
- A separate [WASM member-session bridge](docs/key-management.md#local-wasm-member-sessions)
  for automatic setup/restoration and lock, built with `make member-wasm` and
  checked with `make member-wasm-test`; only public material and encrypted backups leave it.

The [local dedicated-worker host](docs/key-management.md#local-member-worker-host)
adds bounded ownership and termination, checked in Node. Browser page/delivery and
account integration are unavailable. Independent review is required before real-key use.

## Architecture at a glance

```text
member device -> membership CA / token issuer -> identity database
member device -> submission service          -> ciphertext database
reviewer device -> encrypted submissions and replies
independent verifier -> public log checkpoints and receipts
```

See [architecture](docs/architecture.md) for service boundaries and
[deployment](docs/deployment.md) for operational requirements.

## Security and scope

The design does not protect against compromised devices, identifying answers, all
operator collusion, or global traffic observation. It is not coercion-resistant.
See the [threat model](docs/threat-model.md).

Report vulnerabilities privately using [SECURITY.md](SECURITY.md). For ordinary
questions, see [SUPPORT.md](SUPPORT.md).

## Find your way

| Need | Read |
| --- | --- |
| Documentation index and evidence status | [docs/README.md](docs/README.md) |
| Technical design | [Architecture](docs/architecture.md), [protocol](docs/protocol.md) |
| Planned components | [Roadmap](docs/roadmap.md) |
| Ownership and decisions | [Governance](GOVERNANCE.md) |
| Versions and changes | [Versioning](docs/versioning.md), [changelog](CHANGELOG.md) |

## License

Original work is **AGPL-3.0-only**. Upstream materials retain their licenses, including
CC-BY-SA-4.0 for the Contributor Covenant adaptation. See [LICENSE](LICENSE) and the
[dependency ledger](docs/dependencies.md).

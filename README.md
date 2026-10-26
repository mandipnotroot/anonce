<!-- SPDX-FileCopyrightText: 2026 Anonce Contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# anonce

**Anonymous submissions. Verified members. Configurable response limits.**

[![License: AGPL-3.0-only](docs/images/license.svg)](LICENSE)
[![Development status](docs/images/status.svg)](docs/README.md)

anonce designs feedback, reports, and ballots from verified members without attaching
their identities to their submissions.

> **Development only.** Local Go services expose infrastructure endpoints, not a
> working submission protocol. Do not collect sensitive information or run an election.

## Planned capabilities

- Membership certificates, published revocation information, and device-held keys.
- Administrator-set response limits per member and round, enforced through blind
  authorization tokens that each permit one submission.
- An independently deployed submission service storing ciphertext rather than answers.
- Reviewer-side decryption, private replies, and response-threshold controls.
- Public inclusion receipts and a separate administrative audit trail.
- Shared Go client code for a CLI and a self-hosted browser interface.

See the [roadmap](docs/roadmap.md) and [threat model](docs/threat-model.md)
for scope and required evidence.

An administrator chooses the response limit before publishing a round: for example,
one for a ballot or several for feedback. The same published limit applies to every
eligible member; it cannot change after publication under the same round ID.

## Contribute now

Use Go 1.27.3, Python 3.11 or newer, Git, GNU Make, and REUSE 6.2.0 for local checks.
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

```sh
make build test
./bin/server -source-url "$ANONCE_SOURCE_URL"
```

Set `ANONCE_SOURCE_URL` to the HTTPS location of the exact corresponding source,
including local modifications, before running. It has no default or example value
that silently claims to describe your build.

The submission process binds `127.0.0.1:8080`; `bin/issuer` and `bin/ca` use ports
8081 and 8082. `/healthz` reports liveness, `/api/v1/status` lists only implemented
infrastructure, and `/source` redirects to the configured source. `/readyz` always
returns `503`; owned protocol routes return `501` without reading request bodies.
There is no UI, database, signing, enrollment, or submission support yet.
See [deployment](docs/deployment.md#local-development) for flags and limits.

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

The intended design does not protect against compromised devices, identifying
answers, all operator collusion, or global traffic observation. It is not a
coercion-resistant voting system. Read the [threat model](docs/threat-model.md).

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

<!-- SPDX-FileCopyrightText: 2026 Anonce Contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# anonce

**Anonymous submissions. Verified members. Configurable response limits.**

[![License: AGPL-3.0-only](docs/images/license.svg)](LICENSE)
[![Development status](docs/images/status.svg)](docs/README.md)

anonce is designed for feedback, reports, and ballots from verified members without
linking identities to submissions.

The product workflow is entirely web-based: sign in, open a shared review link
or choose an available round, complete the form, and submit. Members, reviewers,
and administrators need no installed app or CLI. The browser manages cryptographic
keys automatically, with encrypted member-key backups on the identity side.
The default application implements this path for one free-text
question, one reviewer and an explicitly selected one-response limit. See
[browser startup](docs/deployment.md#browser-mvp-local-startup),
[the user flow](docs/ui-design.md#account-and-review-workflow) and
[key custody and recovery](docs/key-management.md#browser-account-vault).

> **Development only.** The browser MVP is for synthetic data and has no independent
> security approval. Do not collect
> sensitive information or run an election.

## Next capabilities

- Broader membership/revocation administration and reviewed recovery.
- Generalized forms and administrator-set response limits beyond one per member/round.
- Encrypted private replies and reviewed result-release controls.
- Public inclusion receipts, independent checkpoints and a separate anchored audit trail.
- Protected signer custody, retention/restoration evidence and tested browser/provider support.

These extend the same browser journey. No user CLI, key files, manual key
generation or certificate-request handling is part of the product.

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

## Use the browser application

Members, reviewers and administrators open the same account application at
`https://identity.localhost:8443/`. Members sign in, set up or unlock private access,
verify their invitation, and choose an available review or open its shared link.
Administrators create invitations and publish reviews. Assigned reviewers set up
review access and read answers decrypted in their browser. Session management is
part of the account page. No user installs a CLI or manages key files.

Anonymous answers use the separate `https://submit.localhost:8444/` origin. The
browser connects the account authorization window to the response form without
sending account cookies or plaintext answers to the wrong service. Keeping these
two origins and databases separate is a privacy boundary, not a second user workflow.

## Start the application as an operator

Follow [local startup](docs/deployment.md#browser-mvp-local-startup). Prepare `.env`
from `.env.example`, set `ANONCE_SOURCE_URL` to this exact build's HTTPS source, then:

```sh
make up
make smoke
```

`make up` builds the matched browser runtimes and service image, prepares server
state and database secrets without replacement, starts the two isolated databases,
applies their migrations through separate operator containers, and starts both TLS
browser services. Trust the local development certificate as described in the
startup guide before opening the account page. `make down` preserves state and data.
These commands are server administration, never onboarding steps for ordinary users.

`make container-test` checks the actual connected containers, pages and storage
boundaries. `make browser-test` exercises passkeys and the complete browser journey
with real PostgreSQL. See [testing](docs/testing.md) for prerequisites and limitations.
Signed acceptance is not public-log inclusion; recovery, protected signers and
reviewer server backups are not implemented.

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

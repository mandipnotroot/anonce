<!-- SPDX-FileCopyrightText: 2026 Anonce Contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Deployment

Audience: operators, maintainers, and organizations planning a demo or deployment.

Status: the default application connects the browser workflow to independent
PostgreSQL databases. Browser forms are the only product workflow for members,
reviewers and administrators. Production deployment and the broader protocol remain unavailable.
Do not collect real data.

## Local development

### Browser MVP local startup

The default browser application connects the limited MVP. **Use synthetic data only.**
This is not production readiness or independent security approval. Inert shell and
offline key commands are developer-only regression tools, excluded from the default
build and application image. They are not onboarding alternatives.

Use Linux, Go 1.27.3, PostgreSQL 18.6 through the pinned Compose databases, and a
browser supporting WebAuthn JSON conversion, module workers, BroadcastChannel,
IndexedDB and a user-verifying passkey authenticator. The commands here are
operator setup. Ordinary administrators, members and reviewers use browser forms.

Prepare `.env` from `.env.example` without replacing existing configuration and set
its `ANONCE_SOURCE_URL` to the exact modified source's HTTPS location. From the
repository root, run:

```sh
make up
make smoke
```

`make up` builds the matched member/review WASM assets and service image, prepares
no-replace database secrets, starts the isolated databases, applies both migration
histories through separately scoped operator containers, initializes empty server
state, and starts both TLS browser services. There is no browser overlay to select.
Database ports are never published. Each application receives only its own runtime
credential and read-only service state, never another service's state or migration password.

Initialization admits only an empty owner-only directory and never replaces existing
files. Startup refuses incomplete state or a new state directory against databases
already containing browser accounts or publications. Restore original state instead
of generating replacement keys. Initialization prepares a local trust root, separate TLS keys/certificates,
membership/publication/receipt keys, public cross-service trust files and one
administrator invitation. Each command opens only its own `identity/` or
`submission/` subdirectory and runtime database. Containers run as the non-root
operator's numeric UID/GID so they can read owner-only state. A shared host/daemon
administrator can still access both services. These plaintext development signing files are not
protected production custody. TLS leaves expire after 30 days.

Import `.browser/local-root.crt` into the test browser's trusted certificate
authorities through its certificate settings. Trust only this local test root.
Do not disable certificate verification, browser sandboxing, CSP, user verification,
Secure cookies or CSRF controls. Remove this test trust when finished.
`make up` has already started both services. No separate per-service launch is needed.

Open `https://identity.localhost:8443/`. For the first administrator only, obtain
the code from `.browser/identity/administrator-invitation` through the operator's
private file viewer and enter it at registration. Services never print it. Database
uniqueness prevents a second administrator claim. Members leave that field empty.

Browser journey:

- Register administrator, reviewer and member accounts with passkeys. Separate
  browser profiles are useful for local role testing, not required for ordinary use.
- The administrator creates and privately delivers a membership invitation. The
  member sets up its encrypted key with two local passphrase entries, then verifies
  membership by entering the invitation.
- The administrator creates a draft with one question, reviewer account,
  opening/closing/review-expiry times and the explicitly selected response limit of one.
- The assigned reviewer refreshes and prepares its round key. The encrypted copy
  stays only in that browser's IndexedDB. Do not clear it.
- The administrator refreshes, confirms publication and shares the common response
  link. After interrupted delivery, **Deliver signed publication** sends the same
  signed bulletin without changing its keys or schedule.
- The member opens the link, unlocks and authorizes in the identity popup, returns
  to the anonymous page, completes the answer and explicitly submits. Keep the
  anonymous page open while it verifies signed durable acceptance locally.
- The reviewer refreshes, unlocks the round key and reads locally decrypted answers.
  Identifying text can reveal its author.

Passkey login is not vault unlocking. Lost passphrases or reviewer browser storage
can permanently lose keys. There is no PRF, credential addition, recovery,
account-linked receipt history or reviewer server backup. Issuance interruption
can consume the one response without acceptance. Only an unchanged pending
ciphertext can be retried while open. Signed acceptance is not a transparency proof.

The operator-only browser command flags are `-listen`, `-origin`, `-peer-origin`, `-state`,
`-database`, `-password-file`, `-runtime` and required `-source-url`. Listeners and
native database connections remain loopback. Explicit `-container-network` admits
only the matching `identity-db` or `submission-db` hostname on port 5432 and an
IPv4 wildcard listener inside its container. Database URLs must select the correct
runtime role/database without passwords. Credentials come from files, never URL
arguments. No proxy headers are trusted or request/IP/SQL-parameter logs enabled.
Protected signers, independent checkpoints, retention/restoration, distributed
abuse controls and a supported-browser matrix remain unavailable.

`make build` is the default browser build, including matched runtimes and original
upstream notices. `make browser-build` is a compatibility alias, not another
workflow. Neither builds the key CLI or inert demonstration servers. Contributors
may explicitly use `make dev-tools` for the
[legacy shell regression checks](api.md#implemented-read-only-shell) and
[offline parser/backup diagnostics](key-management.md#local-key-cli). These tools
are not distributed in the application image or required of any product user.

| Resource | Per-process limit |
| --- | --- |
| Accepted connections | 64 |
| Headers | 8 KiB plus Go parser's fixed read allowance |
| Header reads | 5 seconds |
| Full reads / writes | 10 seconds |
| Idle connections | 30 seconds |
| Shutdown | Interrupt/SIGTERM cancels request contexts, drains up to 5 seconds, then closes connections |

No request/access logs or HTTP error diagnostics are retained. Handlers close
body-bearing requests without reading or draining; the network stack may buffer bytes.
Loopback is not authentication or isolation from local users/processes.
**Do not expose these services through an external proxy.**

The public-only WASM verifier remains a development check. The product uses the
matched member and reviewer workers built automatically by `make build`; it needs
no Node runtime or build tool in a user's browser or in the final application image.

### Container stack

The root `Dockerfile` builds the two browser services, one-shot initializer and
TLS liveness probe with the pinned Go compiler. `make build` first generates the
matched worker runtimes and notices, which are the only generated materials admitted
to the build context. The final `scratch` image contains static binaries, browser
assets and original upstream/project notices, with no shell, compiler, user key CLI,
browser executable or Node runtime. Secrets, `.env`, Git metadata and unrelated
artifacts stay outside the build context. This is not a production image or signed release.

`compose.yaml` runs `identity`, `submission`, `identity-db`, and
`submission-db`. Membership issuance belongs to the authenticated identity service;
there is no extra CA application for users to start. PostgreSQL 18.6 and the Go builder use pinned image-index digests;
see [dependency review](dependencies.md#container-runtime-and-images).
Use a local Linux Docker Engine 28 or newer and Compose with `up --wait` and JSON
configuration support. Older engines are rejected because their loopback publication
can expose ports to the local network; see the official
[port-publishing guidance](https://docs.docker.com/engine/network/port-publishing/)
(consulted 2026-10-28). Podman, remote daemons, and other platforms are not validated.
Docker access is privileged. Do not relax socket permissions to bypass a failure.

Copy `.env.example` to `.env` without replacing existing settings.
Set `ANONCE_SOURCE_URL` to an HTTPS location for this exact build's complete source,
including these container files. The example intentionally has no working URL or
passwords. From the repository root, run:

```sh
make up
make smoke
```

Startup generates six independent random passwords without replacing existing
files and validates the whole set. `make container-secrets` is an optional operator
preparation command, not another user workflow. The `.secrets` directory must be
owned by the current user with mode `0700`; files use `0444` so database user `999`
can read their individual Compose bind mounts. The enclosing directory prevents
other host users from traversing to the files. Protect its ancestors and backups.
These are plaintext database credentials, not encrypted device-key backups.
`ANONCE_SECRETS_DIR` may select another trusted directory under the same rules.
Never commit them or put passwords in `.env`, arguments, or images. Python/runtime
copies cannot be explicitly erased.

Each database receives only its own admin, migration, and runtime passwords. The
official image reads the admin secret through `POSTGRES_PASSWORD_FILE`; its internal
process handling is not an erasure guarantee. Each browser service receives its
own runtime password and fixed own-database connection settings, never admin or
migration credentials.
[Bootstrap roles and grants](database.md#local-container-bootstrap) prepare that
boundary. Separate operator containers apply the histories before the browser services start.

| Boundary | Local configuration |
| --- | --- |
| HTTPS | Only `127.0.0.1:8443` for accounts and `:8444` for anonymous responses; exact configured origins and certificate names remain enforced |
| Database networks | Internal identity network for identity/identity DB; separate internal submission network for submission/submission DB; no published PostgreSQL ports |
| Edge networks | Each application has its own non-internal bridge for host port publication, not a shared identity/submission network; this permits application outbound traffic and is not an egress firewall |
| Storage | Independent named database volumes; PostgreSQL 18 mounts at `/var/lib/postgresql`; each application mounts only `.browser/<own-service>` read-only and its own runtime secret |
| Hardening | Non-root users, read-only roots, dropped capabilities, no-new-privileges, and disabled Docker logging for every service; database writes use its volume and bounded temporary filesystems |
| Limits | Each application: one CPU, 128 MiB memory/no extra swap, 64 processes; each database: one CPU, 512 MiB memory/no extra swap, 128 processes |
| Shutdown | Applications get 10 seconds around their existing five-second shutdown; PostgreSQL gets 60 seconds and its upstream fast-shutdown signal |

This follows the [Compose service specification](https://docs.docker.com/reference/compose-file/services/)
and [file-mounted secrets](https://docs.docker.com/compose/how-tos/use-secrets/)
(consulted 2026-10-28). A shared host/daemon administrator can still access both
instances, secrets, and traffic. Local TLS, passkey authentication and storage
integration do not establish production readiness or an anonymity guarantee.
Never publish these ports publicly or use `-container-network`
on a normal host process.

`make up` builds, validates configuration and state, migrates and starts the connected
application, then checks the running stack. Container health verifies TLS liveness,
not production readiness. `make smoke` checks the current
stack without starting or deleting services. `make container-test` runs the
[real-container checks](testing.md#container-infrastructure-checks) in a fresh project
with generated secrets, ephemeral loopback ports, and disposable volumes. It removes
only its own test containers, networks, and volumes; build images/cache remain.

Startup stops the two browser services before applying migrations. A project still
containing old `server`, `issuer` or `ca` containers is rejected rather than silently
keeping an alternate interface or deleting containers. After reviewing that project's
data/state and stopping its old deployment, an operator may run
`docker compose down --remove-orphans` without `--volumes`, then `make up`.
The removed `compose.browser.yaml` overlay is no longer needed. Old HTTP port settings
do not configure the browser origins; use the default HTTPS ports above.

`make down` preserves database volumes. Initialization runs only on empty volumes;
changing files does not rotate existing database passwords, and bootstrap SQL is
not an upgrade runner. After failed initialization, inspect the failure and data
before deciding whether to discard a synthetic volume. No automatic reset is used.

Only when deliberately discarding **all local demo data**, remove the current
Compose project's volumes with:

```sh
docker compose down --volumes
```

This does not delete `.secrets` or `.browser`. Never use volume deletion as recovery
for real data. Protect both directories together with the database volumes. Partial
or missing server state must not silently rotate keys. Older complete state may gain
only public trust-root copies for each service. Certificates must pass strict TLS
verification, including authority identifiers; expired or nonconforming certificates
require operator review, not disabled verification or state reinitialization.
Encrypted restoration exercises, container scanning, SBOMs and production deployment
remain Next work. Kubernetes/Helm stays optional.

### Local database migrations

`make up` applies both independent histories before starting the browser services.
For an explicit operator rerun against already running local databases:

```sh
make migrate-identity
make migrate-submission
```

These commands build the Dockerfile's separate `migration` target, then run a
non-root, read-only, resource-bounded, logging-disabled one-shot operator container.
It attaches only to the selected internal database network, publishes no ports,
and mounts only that database's migration password read-only. Neither the admin nor
runtime credential is supplied. Browser services receive no migration binary or
migration password. Nothing migrates inside the request-serving processes.

The binary accepts only a fixed service name, reads exactly 64 lowercase hexadecimal
credential bytes from `/run/secrets/migration_password`, and rejects symlinks and
nonregular files. It has no arbitrary connection string or SQL-directory argument.
Failure returns a fixed secret-free diagnostic; do not enable driver/SQL logging to
investigate it. Inspect the selected database's schema/history as an authorized
operator instead. A timeout removes only the invocation's randomly named operator
container. Forced termination or daemon failure can leave it for manual inspection.

The [migration contract](database.md#local-migration-runner) defines ownership,
locking, supported versions, timeouts, and immutable SQL. Repeated runs are safe for
an unchanged valid history; corruption or unsupported versions fail rather than
repairing, downgrading, or deleting data. Use `make db-migration-test` for disposable
[real-PostgreSQL checks](testing.md#database-migration-checks), never normal volumes.

Identity version 2 creates the [internal account/session tables](database.md#implemented-account-storage).
The browser service composes that store with verified WebAuthn login. Use
`make db-account-test` for the separate, disposable runtime-role persistence checks;
its development-only `account-test` image runs a race-enabled compiled test binary,
with only one network and runtime secret at a time. Do not deploy this test image
as an application or admit real account data into the local stack.

Identity version 3 adds the internal
[encrypted member-backup slot](database.md#local-member-backup-storage-contract).
It upgrades existing version-2 databases without rewriting earlier migrations.
`make db-member-backup-test` adds a separate race-enabled `member-backup-test`
image to the disposable account/migration checks, with the same single-network,
single-runtime-secret restrictions. The browser vault uses the session-derived
owner contract. Deletion affects only live ciphertext; do not treat it as erasure
from WAL, snapshots, or backups. Real member keys remain prohibited in this stack.

Identity version 4 adds independent non-secret session selectors and backfills
existing rows without changing their tokens or timestamps. Apply it before using
the updated account store and browser session-management routes.
Its volatile default rewrites the session table and indexes under an exclusive
table lock. Allow local downtime and sufficient disk space; the runner's existing
timeouts still apply. Large-table or online upgrades have not been demonstrated.
See PostgreSQL 18 [`ALTER TABLE` notes](https://www.postgresql.org/docs/18/sql-altertable.html#SQL-ALTERTABLE-NOTES)
(consulted 2026-10-29).

Submission version 2 creates the internal
[submission record tables](database.md#implemented-submission-record-storage).
Apply `make migrate-submission` before constructing that store. Existing version-1
databases upgrade additively; no existing records are rewritten. The normal HTTP
submission service verifies anonymous authorization and encrypted envelopes before storage.
`make db-submission-record-test` uses a separate race-enabled `submission-record-test`
image on disposable databases with one network/runtime secret at a time. Do not
deploy the test image or treat a storage reference as a cryptographic receipt.

## Production separation

- Deliver the product through the browser for every role; users install no app,
  extension, CLI, or Node runtime. Offline key diagnostics are developer-only tooling.
- Separate issuer/CA and submission origins and operational trust boundaries.
- Keep account login, dashboard, encrypted member-key vault, and their sessions
  on the identity side. Use narrowly scoped WebAuthn RP IDs and exact allowed
  origins; do not authorize the anonymous submission origin for account assertions
  or PRF evaluation. Reviewer retrieval/decryption needs its own reviewed context.
- Use independent database instances, credentials, network access, migration privileges,
  backup authorization, monitoring access, and operator accounts.
- No cross-database joins or identity authentication in submissions. Shared proxies
  or administrators can still correlate traffic.
- Disable submission access logs in the app, proxy, load balancer, service mesh,
  and hosting layer. Retain no client IP, forwarded-for, user agent, cross-service
  trace ID, or identity-bearing error context.
- Document actual infrastructure logging; application code alone cannot enforce it.

## Transport and headers

**Local shell:**

- CSP: `default-src 'none'`, `frame-ancestors 'none'`, `base-uri 'none'`,
  `form-action 'none'`; shell adds only `style-src 'self'`.
- No scripts, fonts, images, network APIs, inline styles, or input forms.
- Every page links `/source`. Embedded CSS uses full SHA-256 names and matching SRI.
  All responses use `no-store`.

**Deployment requirements:**

- Maintained open-source TLS termination and an organization-appropriate certificate process.
- HSTS on verified HTTPS origins, no framing, `X-Content-Type-Options: nosniff`,
  strict referrer policy, and reviewed Permissions Policy.
- Strict CSP: no inline scripts, third-party origins, ordinary script evaluation,
  or broad wildcards. Permit `wasm-unsafe-eval` only if the tested Go loader needs it;
  match loader and compiler.
- Vendor assets, publish hashes, use supported SRI, and verify signed WASM manifests
  against independently trusted checkpoints. Same-origin hashes are not independent trust anchors.
- Account/admin cookies: Secure, HttpOnly, host-only, reviewed SameSite policy,
  bounded lifetime and rotation, no cross-origin/domain sharing. SameSite alone
  does not isolate sibling origins. Test the anonymous handoff without credentials,
  account referrers, credential IDs, or personalized link parameters.
- Explicit trusted proxies. Never trust arbitrary client forwarding headers.

## Backup, recovery, and retention

- Encrypt identity/ciphertext backups with separate access and keys.
- Member-key material in identity backups is limited to client-encrypted copies and
  reviewed metadata under the [vault contract](key-management.md#browser-account-vault),
  never unlock material. Database backup encryption is an additional layer,
  not a substitute for browser-side private-key encryption. Include vault deletion,
  snapshots, old wrapping methods, and account closure in retention exercises.
- Rehearse isolated restoration with dummy principals. Validate migration versions
  and grants; record evidence without secrets.
- Recovery must not silently reactivate expired round keys or consumed capabilities,
  or reset issuance slots/counts to allow extra tokens. Review reconciliation and
  trust assumptions before claiming safe recovery.
- Include backup expiry, snapshots, and signer exports in retention plans.
- Exclude plaintext device keys, all reviewer-key copies by default, and decrypted
  exports from server backups. Any encrypted reviewer backup requires separate
  round/retention review before enablement. See
  [key management](key-management.md#retention-and-destruction) for copy limits.

## AGPL section 13

- Every page must prominently link `/source` to the deployed build's exact source,
  including modifications and required build/install material.
- Local builds require an explicit URL. Future defaults must identify that exact
  build's source, never an unrelated upstream homepage.
- Keep notices, license texts, build instructions, configuration interface, and
  redistributed asset licenses available.
- Operators must ensure source availability; a footer alone is insufficient.
  Review [AGPL-3.0-only](../LICENSE) and seek legal advice when needed.

## Operational readiness

Before real use, require authenticated administration, sensitive-action
reauthentication, fresh validated revocations, separately held review keys,
independent checkpoints, anonymity-set policy, incident procedures, and complete
security tests. [Verify releases](releasing.md) before accepting future binaries/images.

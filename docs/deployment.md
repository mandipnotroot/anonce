<!-- SPDX-FileCopyrightText: 2026 Anonce Contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Deployment

Audience: operators, maintainers, and organizations planning a demo or deployment.

Status: local HTTP infrastructure, read-only shell, and an opt-in Docker Compose
stack with separate PostgreSQL instances. Application persistence, production
deployment, and the submission protocol remain unavailable. Do not collect real data.

## Local development

Build with `make build` (Go 1.27.3). Run each command in a separate terminal or
supervisor. The separate offline `bin/client` is documented under
[local key CLI](key-management.md#local-key-cli); it does not start an HTTP service.
For the HTTP commands, set `-source-url` to the exact corresponding source, including
modifications and build/install material:

```sh
./bin/server -source-url "$ANONCE_SOURCE_URL"
./bin/issuer -source-url "$ANONCE_SOURCE_URL"
./bin/ca -source-url "$ANONCE_SOURCE_URL"
```

`ANONCE_SOURCE_URL` is a shell convenience, not an application environment setting.

| Flag | Validation |
| --- | --- |
| `-listen` | Unzoned loopback IP literal, canonical decimal port `0`–`65535`; no hostname, wildcard, or non-loopback bind. Port `0` is ephemeral; use a fixed port for manual inspection |
| `-container-network` | Default false; explicitly permits the additional IPv4 literal `0.0.0.0` with `-listen`. Use only behind container isolation and loopback host publication; this flag does not detect containers or enforce firewall policy |
| `-source-url` | Required absolute HTTPS URL; no credentials, query, or fragment. Missing value fails startup |
| `-help` | Available on all HTTP commands |
| `-dev-styleguide` | Submission only, default false; rejected by identity commands and configuration validation |

Unknown flags and positional arguments fail. The process does not fetch or verify
source contents; completeness is the operator's responsibility.

| Command | Default bind |
| --- | --- |
| `bin/server` | `127.0.0.1:8080` |
| `bin/issuer` | `127.0.0.1:8081` |
| `bin/ca` | `127.0.0.1:8082` |

The [API reference](api.md#implemented-infrastructure) lists liveness, demonstration
status, unavailable readiness (`503`), and protocol rejection (`501`). Submission
also serves read-only pages/CSS. The opt-in style guide has labelled mocks and a
disabled publication button, not forms or working administration.

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

The separate [WASM verifier](key-management.md#local-wasm-request-verification)
builds with `make wasm`; `make wasm-test` requires development-only Node.js 22.23.3.
Artifacts remain in `bin/wasm/` and are not served by the HTTP commands. This does
not add a browser deployment or change the shell's CSP.

### Container stack

The root `Dockerfile` builds the HTTP commands and a liveness probe
with the pinned Go compiler. The final `scratch` image contains static binaries and
original project/Go license notices, runs as `65532:65532`, and has no shell,
compiler, key CLI, browser, or Node runtime. The allowlisted build context excludes
secrets, `.env`, Git metadata, tests, and generated artifacts. This is a local
development build, not a production image or signed release.

`compose.yaml` runs `server`, `issuer`, `ca`, `identity-db`, and
`submission-db`. PostgreSQL 18.6 and the Go builder use pinned image-index digests;
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
make container-secrets
make container-config
make up
make smoke
```

`container-secrets` generates six independent random passwords without replacing
existing files. Startup validates the whole set. The `.secrets` directory must be
owned by the current user with mode `0700`; files use `0444` so database user `999`
can read their individual Compose bind mounts. The enclosing directory prevents
other host users from traversing to the files. Protect its ancestors and backups.
These are plaintext database credentials, not encrypted device-key backups.
`ANONCE_SECRETS_DIR` may select another trusted directory under the same rules.
Never commit them or put passwords in `.env`, arguments, or images. Python/runtime
copies cannot be explicitly erased.

Each database receives only its own admin, migration, and runtime passwords. The
official image reads the admin secret through `POSTGRES_PASSWORD_FILE`; its internal
process handling is not an erasure guarantee. Applications receive no database
password or connection setting yet because their handlers do not use storage.
[Bootstrap roles and grants](database.md#local-container-bootstrap) prepare that
boundary without claiming account, vault, or protocol persistence.

| Boundary | Local configuration |
| --- | --- |
| HTTP | Only `127.0.0.1:8080`, `:8081`, and `:8082`; `ANONCE_SERVER_PORT`, `ANONCE_ISSUER_PORT`, and `ANONCE_CA_PORT` may change host ports, never the loopback address |
| Database networks | Internal identity network for issuer/identity DB; separate internal submission network for server/submission DB; no published PostgreSQL ports |
| Signer | Issuer and CA share an internal signer network; CA has no database-network attachment |
| Edge networks | Each application has its own non-internal bridge for host port publication, not a shared identity/submission network; this permits application outbound traffic and is not an egress firewall |
| Storage | Independent named database volumes; PostgreSQL 18 mounts at `/var/lib/postgresql`; no application host mounts |
| Hardening | Non-root users, read-only roots, dropped capabilities, no-new-privileges, and disabled Docker logging for every service; database writes use its volume and bounded temporary filesystems |
| Limits | Each application: one CPU, 128 MiB memory/no extra swap, 64 processes; each database: one CPU, 512 MiB memory/no extra swap, 128 processes |
| Shutdown | Applications get 10 seconds around their existing five-second shutdown; PostgreSQL gets 60 seconds and its upstream fast-shutdown signal |

This follows the [Compose service specification](https://docs.docker.com/reference/compose-file/services/)
and [file-mounted secrets](https://docs.docker.com/compose/how-tos/use-secrets/)
(consulted 2026-10-28). A shared host/daemon administrator can still access both
instances, secrets, and traffic. No TLS, production authentication, or anonymity
guarantee is added. Never publish these ports publicly or use `-container-network`
on a normal host process.

`make up` validates secrets/configuration, runs `docker compose up --build --wait`,
and checks the running stack. Container health means liveness and database bootstrap,
not product readiness: `/readyz` remains `503`. `make smoke` checks the current
stack without starting or deleting services. `make container-test` runs the
[real-container checks](testing.md#container-infrastructure-checks) in a fresh project
with generated secrets, ephemeral loopback ports, and disposable volumes. It removes
only its own test containers, networks, and volumes; build images/cache remain.

`make down` preserves database volumes. Initialization runs only on empty volumes;
changing files does not rotate existing database passwords, and bootstrap SQL is
not an upgrade runner. After failed initialization, inspect the failure and data
before deciding whether to discard a synthetic volume. No automatic reset is used.

Only when deliberately discarding **all local demo data**, remove the current
Compose project's volumes with:

```sh
docker compose down --volumes
```

This does not delete `.secrets`. Never use volume deletion as recovery for real data.
Credential/membership tables, protocol verification, product vault integration, encrypted backup/restore exercises, container scanning,
SBOMs, and production deployment remain Next work. Kubernetes/Helm stays optional.

### Local database migrations

After `make up`, explicitly apply each independent history:

```sh
make migrate-identity
make migrate-submission
```

These commands build the Dockerfile's separate `migration` target, then run a
non-root, read-only, resource-bounded, logging-disabled one-shot operator container.
It attaches only to the selected internal database network, publishes no ports,
and mounts only that database's migration password read-only. Neither the admin nor
runtime credential is supplied. The normal HTTP image and services receive no
migration binary, module notices, or database secrets. Nothing migrates at HTTP
startup; `/readyz` stays `503`.

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
No HTTP service receives runtime credentials or exposes login as a result. Use
`make db-account-test` for the separate, disposable runtime-role persistence checks;
its development-only `account-test` image runs a race-enabled compiled test binary,
with only one network and runtime secret at a time. Do not deploy this test image
as an application or admit real account data into the local stack.

Identity version 3 adds the internal
[encrypted member-backup slot](database.md#local-member-backup-storage-contract).
It upgrades existing version-2 databases without rewriting earlier migrations.
`make db-member-backup-test` adds a separate race-enabled `member-backup-test`
image to the disposable account/migration checks, with the same single-network,
single-runtime-secret restrictions. No HTTP service gets vault access or new
credentials. Deletion affects only live ciphertext; do not treat it as erasure
from WAL, snapshots, or backups. Real member keys remain prohibited in this stack.

Identity version 4 adds independent non-secret session selectors and backfills
existing rows without changing their tokens or timestamps. Apply it before using
the updated internal account store. It enables no HTTP session-management route.
Its volatile default rewrites the session table and indexes under an exclusive
table lock. Allow local downtime and sufficient disk space; the runner's existing
timeouts still apply. Large-table or online upgrades have not been demonstrated.
See PostgreSQL 18 [`ALTER TABLE` notes](https://www.postgresql.org/docs/18/sql-altertable.html#SQL-ALTERTABLE-NOTES)
(consulted 2026-10-29).

Submission version 2 creates the internal
[submission record tables](database.md#implemented-submission-record-storage).
Apply `make migrate-submission` before constructing that store. Existing version-1
databases upgrade additively; no existing records are rewritten. The normal HTTP
services still receive no runtime credential and accept no submissions.
`make db-submission-record-test` uses a separate race-enabled `submission-record-test`
image on disposable databases with one network/runtime secret at a time. Do not
deploy the test image or treat a storage reference as a cryptographic receipt.

## Production separation

- Deliver the product through the browser for every role; users install no app,
  extension, CLI, or Node runtime. The offline CLI remains optional tooling.
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

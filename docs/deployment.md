<!-- SPDX-FileCopyrightText: 2026 Anonce Contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Deployment and operator obligations

Audience: operators, maintainers, and organizations planning a demo or deployment.

Status: local Go HTTP infrastructure is available. No Dockerfile, Compose stack,
production image, or working protocol exists. Do not collect real data.

## Local development

Build with `make build` using Go 1.27.3. Run each command separately with
`-source-url` set to an HTTPS location containing its exact corresponding source,
including modifications and build/install material:

```sh
./bin/server -source-url "$ANONCE_SOURCE_URL"
./bin/issuer -source-url "$ANONCE_SOURCE_URL"
./bin/ca -source-url "$ANONCE_SOURCE_URL"
```

These commands are long-running; use separate terminals or a process supervisor.
The shell variable is an operator convenience, not an application environment
setting. A missing value fails startup. Only `-listen`, `-source-url`, and `-help`
are supported; positional arguments and unknown flags fail.

| Command | Default bind |
| --- | --- |
| `bin/server` | `127.0.0.1:8080` |
| `bin/issuer` | `127.0.0.1:8081` |
| `bin/ca` | `127.0.0.1:8082` |

`-listen` accepts an unzoned loopback IP literal and canonical decimal port from
0 to 65535. Port 0 requests an ephemeral port; use a fixed port for manual inspection.
Hostnames, wildcard binds, and non-loopback addresses are rejected. The source URL
must be absolute HTTPS without credentials, query, or fragment. Its contents are
not fetched or verified by the process; source completeness remains an operator duty.

`GET /healthz` reports process liveness. `/api/v1/status` explicitly reports
demonstration mode. `/readyz` always fails with `503` because storage, migrations,
and protocol controls do not exist. Owned protocol routes return `501`; other
routes return `404`. There are no UI pages or input forms. See [API](api.md).

Each process bounds accepted connections at 64, headers at 8 KiB plus the Go HTTP
parser's fixed read allowance, header reads at 5 seconds, full reads and writes at
10 seconds, and idle connections at 30 seconds. Shutdown on interrupt or SIGTERM
cancels request contexts, drains for up to 5 seconds, then closes remaining
connections. No request/access logs or HTTP error diagnostics are retained.
Handlers never read request bodies; body-bearing requests close the connection
without draining for reuse. The network stack can still buffer incoming bytes.
Loopback is not authentication and does not isolate other users or processes on
the same host. Do not put these services behind an externally reachable proxy.

The remaining runtime work must provide a reproducible Docker/Podman-compatible image
and a Compose stack with an issuer, a submission/web service, and independent
PostgreSQL services. Expose development ports on loopback only, run as non-root, bound
resources, use health checks, and document volume removal explicitly. Provide
`.env.example` without working secrets; startup must reject absent required secrets
rather than provide convenient credentials.

The future quick start is `make up` after documented secret creation, as specified
in [testing](testing.md#required-runtime-command-contract). Kubernetes/Helm remains
optional future work, not a prerequisite for local development.

## Production separation

Place issuer/CA and submission services on distinct origins and operational trust
boundaries. Use independent database instances, credentials, network access,
migration privileges, backup authorization, monitoring access, and operator accounts.
Never enable a cross-database join or reuse identity authentication in submission
requests. A shared reverse proxy or administrator can still correlate traffic.

Disable submission-path access logs at the application, proxy, load balancer, service
mesh, and upstream hosting layer. Do not retain client IP, forwarded-for, user agent,
cross-service trace IDs, or identity-bearing error context. Document the actual
infrastructure behavior; application code alone cannot ensure this policy.

## Transport and headers

Terminate TLS with maintained open-source software and an organization-appropriate
certificate process. Enable HSTS on verified HTTPS origins, deny framing, set
`X-Content-Type-Options: nosniff`, a strict referrer policy, and a reviewed Permissions
Policy. Use a strict CSP without inline scripts, third-party origins, ordinary script
evaluation, or broad wildcard sources. Allow `wasm-unsafe-eval` only when required
by the tested Go loader; do not broaden it to ordinary script evaluation. Match
the loader to the compiler. Vendor assets, publish integrity hashes, use SRI where
supported, and verify signed WASM manifests against independently trusted
checkpoints. A hash served by the same origin is not independent verification.

Administrative cookies require Secure, HttpOnly, a reviewed SameSite policy, bounded
lifetime, and no cross-origin/domain sharing. Configure trusted proxies explicitly;
never accept arbitrary client-supplied forwarding headers as trusted transport state.

## Backup, recovery, and retention

Encrypt identity and ciphertext backups with separate access and keys. Rehearse
restoration in isolated environments with dummy principals, validate migration
versions and grants, and record restoration evidence without secret contents.
Point-in-time recovery must not silently reactivate expired round keys or consumed
capabilities. Include backup expiry, snapshots, and signer exports in retention plans.
Restoration must preserve consumed issuance slots and quota counts; an older backup
must not restore allowance that could produce additional valid tokens. Review the
reconciliation and trust assumptions before claiming safe recovery.

Keep reviewer keys and decrypted exports out of server backups. Follow
[key management](key-management.md#retention-and-destruction) for controlled-copy limits.

## AGPL section 13

Every web page must offer a prominent `/source` link to the exact corresponding
source for the deployed version, including modifications and the material needed
to build/install it as required by the license. The local processes require an
explicit source URL flag because an unversioned modified build has no trustworthy
default. A future release may supply a build-linked default only when it names
that exact build's corresponding source. Never substitute an unrelated upstream
homepage for a modified build.

Keep notices, license texts, build instructions, configuration interface, and
redistributed asset licenses available. Source availability is an operator duty;
a footer alone does not establish compliance. Review the actual
[AGPL-3.0-only text](../LICENSE) and obtain legal advice when needed.

## Operational readiness

Require authenticated administration, reauthentication of sensitive actions, validated
revocation freshness, separately held review keys, independent log checkpoints,
an anonymity-set policy, incident procedures, and complete security tests before
real use. Use the [release verification contract](releasing.md) before accepting
future binaries or images.

<!-- SPDX-FileCopyrightText: 2026 Anonce Contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Deployment

Audience: operators, maintainers, and organizations planning a demo or deployment.

Status: local HTTP infrastructure and read-only shell only. No Dockerfile, Compose
stack, production image, or working protocol. Do not collect real data.

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

Required future local stack:

- Reproducible Docker/Podman-compatible image; Compose issuer, submission/web,
  and independent PostgreSQL services.
- Loopback-only ports, non-root processes, bounded resources, health checks,
  and explicit volume-removal instructions.
- `.env.example` without working secrets. Startup rejects missing required secrets.
- `make up` after documented secret creation, per the
  [command contract](testing.md#required-runtime-command-contract).
- Kubernetes/Helm is optional, not a local-development prerequisite.

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

<!-- SPDX-FileCopyrightText: 2026 Anonce Contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# HTTP API contract

Audience: transport implementers and client authors.

Status: local demonstration infrastructure only. The [API definition](openapi.yaml)
uses the official [OpenAPI 3.1.0 specification](https://spec.openapis.org/oas/v3.1.0)
and separates implemented endpoints from proposed discovery APIs. Cryptographic
schemas await encoding and profile review.

The separate [local WASM verifier](key-management.md#local-wasm-request-verification)
provides request validation and opt-in expected-key matching through an in-process
JavaScript interface, not an HTTP route. These commands serve no verifier artifacts;
HTTP routes and OpenAPI schemas are unchanged.

The separate [local member-session bridge](key-management.md#local-wasm-member-sessions)
also uses only an in-process interface. It adds no HTTP endpoint or OpenAPI schema;
the services still handle no passwords, private keys, or encrypted member backups.
Its unlocked `backup(password)` method returns only local encrypted bytes; it is
not a vault upload or password-change HTTP operation.
Its [worker lock notifications](key-management.md#lock-notifications-and-page-disposal)
are local browser messages, not a logout endpoint or server revocation API. HTTP
behavior and OpenAPI schemas remain unchanged.

The worker owner's local [`closed` Promise](key-management.md#local-member-worker-host)
observes terminal cleanup without a server request or new worker message. It is not
a logout acknowledgement; HTTP and OpenAPI contracts are unchanged.

## Implemented infrastructure

All three commands expose:

| Path | `GET` response |
| --- | --- |
| `/healthz` | `200`, `ok` |
| `/readyz` | Always `503`, code `not_ready`; no storage or protocol readiness |
| `/api/v1/status` | Version `development`, `demonstration: true`; exactly `liveness`, `status`, `source-discovery` capabilities |
| `/source` | Bodyless `302` to the required configured HTTPS source URL |

- `HEAD` has no body. Other methods return `405`, `Allow: GET, HEAD`.
- All handler responses use `Cache-Control: no-store` and
  [restrictive headers](deployment.md#transport-and-headers), without cookies or CORS access.
- CA reserves enrollment, CA discovery, and `/admin`; issuer reserves challenges,
  issuances, CA discovery, and `/admin`. Submission reserves rounds, submissions,
  receipts, log, and reply mailboxes. Reserved roots and descendants return `501`,
  code `not_implemented`, for every method.
- Unknown paths, including another process's exclusive routes, return `404`, code `not_found`.
- Handlers read no request bodies and reflect no request data in errors. They perform
  no authentication or protocol parsing and consume no capabilities or private state.
- JSON errors contain only `code` and `message`. Go's transport parser may reject
  malformed HTTP or oversized headers before handlers, without application JSON/headers.

See [deployment](deployment.md#local-development) for limits and configuration.

## Implemented read-only shell

- **Pages:** submission only, at `/` and `/about`. `/dev/styleguide` requires
  `-dev-styleguide`; otherwise JSON `404`. CA/issuer serve no shell pages or assets.
  The infrastructure-only status capability list is unchanged.
- **CSS:** one embedded `/assets/shell.{sha256}.css`, with the full lowercase
  hexadecimal SHA-256 digest and matching page SRI. Only the current exact path
  exists; no listing, unhashed alias, or template download.
- **Delivery:** `GET`/`HEAD` only; other methods return JSON `405`, `Allow: GET, HEAD`.
  `HEAD` has no body. Use `no-store`, no cookies/CORS, and the
  [shell CSP](deployment.md#transport-and-headers).
- **Input:** no request data in templates. Body-bearing requests close without
  reading or draining. No forms, authentication, or protocol calls.
- **Compatibility:** root HTML `200` replaces JSON `404`, a
  [breaking HTTP change](versioning.md#public-api-boundary), not a stable profile or product interface.

## Endpoint ownership

Account login, credential management, the eligible-round dashboard, and encrypted
member-key backup operations belong only to the identity side. Their routes,
schemas, session/recovery contracts, and wrapping metadata are not specified or
implemented yet. Do not infer new endpoints from proposed UI paths. Follow the
[vault requirements](key-management.md#browser-account-vault) before defining them
in OpenAPI. This documentation change adds no working route or wire format.

| Origin | Planned endpoints | Input boundary |
| --- | --- | --- |
| CA/issuer | `/healthz`, `/readyz`, `/api/v1/status`, `/api/v1/ca/certificate`, `/api/v1/ca/revocations` | Public discovery; no private material |
| CA | `/api/v1/enrollments` | Enrollment code/CSR |
| Issuer | `/api/v1/challenges`, `/api/v1/issuances` | Challenge context, authenticated blinded request |
| Submission | `/healthz`, `/readyz`, `/api/v1/status`, `/api/v1/rounds/{round_id}/bulletin` | Public signed round data |
| Submission | `/api/v1/submissions`, `/api/v1/receipts/{record_id}`, `/api/v1/log/checkpoint` | Anonymous token and ciphertext; public receipt commitments |
| Submission | `/api/v1/reply-mailboxes/{mailbox_id}` | Anonymous capability and encrypted replies |
| Identity-side admin | `/admin/*` | Authenticated role-scoped management operations |
| Go web shell | UI routes in [UI design](ui-design.md), `/source` | Static shell/public source link; no plaintext answer API |

Reviewer retrieval and reply-write endpoints require a separate authorization design
that does not reuse membership cookies. Never introduce a decrypt endpoint.

## HTTP behavior

- HTTPS outside loopback development; configured trusted proxies only.
- Bounded bodies, headers, timeouts, concurrency, and pagination.
- JSON errors contain a stable public code and safe summary, never raw internal errors.
- `400` for malformed input; `401` for absent authentication; `403` for denied
  authority; `409` for a consumed capability or incompatible state; `413` for size
  limits; `429` with bounded retry guidance for rate limits.
- Unimplemented protocol operations return `501` without consuming any capability.
- Database or signer unavailability returns a safe failure, not a partial success.
- Idempotency rules require payload binding and storage review; do not add generic
  request-ID logging across origins.

Error distinctions on anonymous mailboxes and receipt queries must not become
existence or participation oracles. Where necessary, use equivalent safe responses.

## Authentication and caching

Administrative writes require server-side authorization, CSRF protection, and recent
reauthentication for sensitive actions. Never share issuer session cookies or
authentication headers with the submission origin.

Future account/vault APIs require owner authorization, bounded encrypted input,
CSRF protection for session-authenticated writes, secret-free errors, and no-store
responses. Plaintext device private keys, unlock passphrases, key-recovery secrets,
and PRF outputs must not appear in requests or responses. A client must serialize
only the intended authentication fields, not arbitrary browser extension results.
There is no decrypt endpoint, account-linked submission-history API, or
identity-authenticated reply API.

Public certificate, bulletin, checkpoint, and asset responses may use explicit
caches with freshness requirements. Secret or identity-bearing responses use
`Cache-Control: no-store`.

## Response-limit contract

Follow the [protocol rules](protocol.md#round-response-limit): `response_limit`
must be a bounded positive integer, explicitly confirmed at publication, and
signed as a common immutable limit. Clients and issuers validate it without
defaults; each token permits one accepted ciphertext.

- Bind slot/bulletin context to the authenticated issuance challenge. No quota state
  or slot indices in anonymous submissions or receipt requests; public bulletins
  expose the common limit, not remaining allowances.
- Quota exhaustion returns safe authenticated-issuance `409`. No quota reset or
  identity-authenticated submission fallback.
- Forms/bulletins follow [public API versioning](versioning.md), including wire/profile
  compatibility and migration ranges. Configurable limits are a breaking replacement
  for fixed single-response semantics, not an optional field. No released runtime
  needs migration; require the limit in the reviewed wire profile.

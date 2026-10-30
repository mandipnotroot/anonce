<!-- SPDX-FileCopyrightText: 2026 Anonce Contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# HTTP API contract

Audience: transport implementers and client authors.

Status: the default browser services implement the [browser API definition](browser-openapi.yaml)
and the contract below. The original [API definition](openapi.yaml)
uses the official [OpenAPI 3.1.0 specification](https://spec.openapis.org/oas/v3.1.0)
and separates demonstration endpoints from proposed discovery APIs. Browser
cryptographic encodings are specified separately in
[profile 1](cryptography.md#browser-mvp-profile-1).

The separate [local WASM verifier](key-management.md#local-wasm-request-verification)
provides request validation and opt-in expected-key matching through an in-process
JavaScript interface, not an HTTP route. These commands serve no verifier artifacts;
HTTP routes and OpenAPI schemas are unchanged.

The [local member-session bridge](key-management.md#local-wasm-member-sessions)
itself uses an in-process interface, not HTTP. Browser hosts compose it with the
backup API below; original demonstration commands still handle no backups.
Its unlocked `backup(password)` method returns only local encrypted bytes; it is
not a vault upload or password-change HTTP operation.
Local `createConfirmed` and `backupConfirmed` add password confirmation in shared
Go only; neither introduces a request, server password handling, or OpenAPI change.
Its [worker lock notifications](key-management.md#lock-notifications-and-page-disposal)
are local browser messages, not a logout endpoint or server revocation API. HTTP
behavior and OpenAPI schemas remain unchanged.

The worker owner's local [`closed` Promise](key-management.md#local-member-worker-host)
observes terminal cleanup without a server request or new worker message. It is not
a logout acknowledgement; HTTP and OpenAPI contracts are unchanged.

Its [text passphrase methods](key-management.md#browser-passphrase-text-interface)
encode only locally into existing worker commands. No text passwords enter HTTP,
and no OpenAPI schema or product route is added.

## Implemented infrastructure

### Browser HTTP contract

See [startup](deployment.md#browser-mvp-local-startup). All browser routes require
the configured HTTPS host, bounded headers, 32 KiB JSON bodies, 32 in-flight
requests, ten-second request deadlines and `no-store`. Identity writes additionally
require exact `Origin`, `Sec-Fetch-Site: same-origin`, and `X-Anonce-CSRF: 1`.
Only JSON is accepted; unknown fields and trailing values fail. The stable public
error shape remains `code` and `message`, without internal diagnostics.

Identity session and ceremony cookies are `__Host-` prefixed, Secure, HttpOnly,
host-only, path `/`, SameSite Strict, with one-hour and two-minute lifetimes.
Session secrets use the existing digest-only store. WebAuthn verifies the exact RP
and origin with user verification required. Ceremonies are single-use even after
failed verification. Login replaces the local bearer after verified authentication;
logout revokes it and locks local workers. One credential per account, no recovery,
no credential addition and no PRF unlocking are the initial limits.

#### Browser session management

The identity page lists at most 16 live account sessions with a non-secret selector,
authentication/expiry timestamps and a current-session marker. It collects no device,
IP, user-agent or anonymous-activity metadata. These routes use the same protected
session cookie and identity transport gate:

| Method and path | Contract |
| --- | --- |
| `GET /api/browser/sessions` | Own live sessions, newest first; `id`, `created_at`, `expires_at`, `current` only |
| `POST /api/browser/sessions/revoke` | Exactly `{"id":"<22-character selector>"}`; recent authentication required; returns `removed` |
| `POST /api/browser/logout-all` | Empty object; recent authentication required; removes all own sessions and expires the cookie |
| `POST /api/browser/auth/reauthenticate/begin` | Empty object; derives the account from a live bearer; returns WebAuthn assertion options |
| `POST /api/browser/auth/reauthenticate/finish` | Standard WebAuthn assertion; verifies the same account, purpose and original bearer before rotation |

Recent authentication means admission within five minutes, rechecked after account
lock waits. Old live sessions may list metadata but receive `403` for revocation.
Missing, expired or revoked bearers receive `401`. Inventory/revocation storage
failures receive `503`; ceremony admission and verification errors remain opaque.
Malformed or zero selectors receive `400`. Current, missing, rotated and foreign
selectors all return `removed: false`, without revealing another account's sessions.
Mutations publish no successful result before commit. On uncertain outcomes,
refresh inventory or sign in again, never automatically repeat a mutation.

Reauthentication uses the existing two-minute, single-use ceremony store but is
purpose-separated from login and bound to the original bearer's SHA-256 digest.
The verified assertion rotates only that bearer and its selector, preserving its
absolute expiry and every sibling session. It cannot create a session after
revocation or extend a one-hour sign-in. No account name, freshness assertion or
owner override is accepted. The client locks keys before reauthentication and
requires a separately chosen mutation afterward.

Current-session logout requires an empty JSON object. Sign-out everywhere requires
explicit browser confirmation and locks local workers before the request. Successful
logout also attempts a secret-free same-partition notification to clear other identity
pages. Visible running pages check `/me` every 30 seconds and on foreground/focus;
an observed `401` locks keys, clears plaintext/passwords and hides account controls.
These checks are not remote erasure: suspended/offline pages, previously admitted
work and keys or plaintext already copied elsewhere cannot be recalled. Encrypted
backups, membership and anonymous receipts are unchanged. No session data enters
the anonymous origin. See [test evidence](testing.md#connected-browser-mvp-checks).

#### Browser admission and origin boundaries

Authentication begins allow ten attempts per hashed account name per five minutes,
with at most 1024 in-memory entries, plus 120 global POST requests per minute and
256 outstanding persisted ceremonies. Rate counters are per process and reset on
restart; run one instance of each local host. No IP address is collected. These
bounds do not stop distributed saturation or replace production abuse review.

The anonymous host rejects all cookie and Authorization headers on API requests.
Its submit route rejects identity-origin calls. Only public publication and
round-scoped review allow exact-origin CORS from the configured identity host,
without `Access-Control-Allow-Credentials`. Reviewer proofs are not account
credentials. Tokens and unlock material never appear in URLs. Public common round
IDs may appear in query parameters. The API accepts no account-linked submission
history or plaintext-answer endpoint.

Binary fields are canonical unpadded base64url, except WebAuthn's standard JSON
ceremony representation. Formats and signature contracts are fixed in
[cryptography](cryptography.md#browser-mvp-profile-1). The browser API is unreleased
and incompatible with the proposed `/api/v1/` schemas; no automatic fallback exists.

### Developer-only infrastructure contract

The original demonstration commands, built only by `make dev-tools`, retain the
inert infrastructure contract below. They are neither the default application nor
an alternative user workflow.

The internal [submission record store](database.md#implemented-submission-record-storage)
adds no HTTP endpoint or OpenAPI schema. It trusts a future verifier, so exposing
its digest/byte arguments directly would bypass token authorization and envelope
validation. Submission routes still return `501`; readiness remains unavailable.

The [local container stack](deployment.md#container-stack) changes deployment only.
Its explicit `-container-network` flag permits container-local IPv4 wildcard binding
while Compose publishes only host loopback ports. `/healthz` still reports liveness,
`/readyz` remains unavailable, and no HTTP route or OpenAPI schema is added.

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

Internal [session-scoped backup access](database.md#session-scoped-member-backup-access)
uses existing identity sessions within Go storage transactions. The separate browser
host composes these operations with the authenticated API above; the original
demonstration commands do not expose them.

Account login, credential management, the eligible-round dashboard, and encrypted
member-key backup operations belong only to the identity side. Their routes,
schemas and MVP session contract are defined above. Broader recovery and wrapping
profiles remain unspecified. Do not infer new endpoints from proposed UI paths. Follow the
[vault requirements](key-management.md#browser-account-vault) before defining them
in OpenAPI.

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

<!-- SPDX-FileCopyrightText: 2026 Anonce Contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# HTTP API contract

Audience: transport implementers and client authors.

The browser application uses one [OpenAPI definition](openapi.yaml), following
[OpenAPI 3.1.0](https://spec.openapis.org/oas/v3.1.0), consulted 2026-10-30.
Its `/api/browser/` transport and [profile 1](cryptography.md#browser-mvp-profile-1)
are unreleased and synthetic-only. There is no plaintext-answer, private-key or
server-decryption API. See [startup](deployment.md#browser-mvp-local-startup).

## Browser HTTP contract

All browser routes require the configured HTTPS host, bounded headers, 32 KiB JSON
bodies, 32 in-flight requests, ten-second request deadlines and `no-store`.
Identity writes require exact `Origin`, `Sec-Fetch-Site: same-origin` and
`X-Anonce-CSRF: 1`. Application JSON admission rejects unknown fields, duplicate
keys, excessive nesting and trailing values. WebAuthn responses use the library's
bounded parser. Errors contain only `code` and a safe `message`.
Binary fields use canonical unpadded base64url, except standard WebAuthn JSON.

Each origin serves its own page at `/`, verified local assets, `/healthz`
and `/source`. Liveness returns `ok`, not database or production readiness.
Source discovery redirects to the
configured exact-build HTTPS source. Pages/assets support GET and HEAD.

### Browser session management

Identity session and ceremony cookies are `__Host-` prefixed, Secure, HttpOnly,
host-only, path `/`, SameSite Strict, with one-hour and two-minute lifetimes.
WebAuthn verifies the exact RP/origin and requires user verification. Ceremonies
are single-use, including after failed verification. One credential per account,
no credential addition, no PRF and no recovery are the current limits.

| Method and path | Contract |
| --- | --- |
| `GET /api/browser/sessions` | At most 16 own live sessions, newest first; `id`, `created_at`, `expires_at`, `current` only |
| `POST /api/browser/sessions/revoke` | Exactly `{"id":"<22-character selector>"}`; recent authentication; returns `removed` |
| `POST /api/browser/logout-all` | Empty object; recent authentication; removes all own sessions and expires the cookie |
| `POST /api/browser/auth/reauthenticate/begin` | Empty object; derives account from a live bearer; returns assertion options |
| `POST /api/browser/auth/reauthenticate/finish` | Standard WebAuthn assertion; verifies purpose, account and original bearer before rotation |

Recent authentication means admission within five minutes, rechecked after
account-lock waits. Old live sessions may list metadata but cannot revoke sessions.
Missing/expired/revoked bearers receive `401`, stale authentication `403`, malformed
selectors `400` and storage failures `503`. Current, stale, missing and foreign
selectors all return `removed: false`, without revealing another account's sessions.
No successful mutation result is published before commit. Uncertain outcomes
require explicit refresh or fresh sign-in, never automatic mutation retries.

Reauthentication uses a two-minute single-use ceremony bound to its purpose,
account and the original bearer's SHA-256 digest. Successful verification rotates
only that bearer/selector, preserves absolute expiry and does not alter siblings.
It cannot revive a revoked session. The page locks local keys first and requires a
separately chosen sensitive action afterward. No caller-supplied account or
freshness assertion overrides the bearer.

Current-session logout accepts an empty object. Sign-out everywhere requires
explicit confirmation and locks workers before transport. Successful logout
attempts a secret-free same-partition notification. Visible identity pages check
`/me` every 30 seconds and on foreground/focus; observed `401` clears local keys,
plaintext, password fields and account controls. This is not remote erasure of
suspended pages, copied material or already admitted work. Backups, membership
and anonymous receipts remain unchanged. No session metadata enters anonymous requests.

### Browser admission and origin boundaries

Authentication begins permit ten attempts per hashed account name per five minutes,
with at most 1024 in-memory entries, 120 global POSTs per minute and 256 outstanding
persisted ceremonies. Counters reset on process restart; run one instance per local
host. No IP is collected. These bounds do not replace production abuse review.

The submission API rejects cookies and Authorization headers. Submit rejects
identity-origin calls. Only signed publication and round-scoped review allow exact
identity-origin CORS, without `Access-Control-Allow-Credentials`. Review proofs are
not account credentials. Common round IDs may appear in URLs; tokens, passphrases,
member bindings and receipt capabilities must not.

## Endpoint ownership

| Origin | Implemented responsibility |
| --- | --- |
| Identity | WebAuthn registration/login/reauthentication, sessions/logout, encrypted member backup, membership invitations/enrollment, eligible rounds, draft review and publication |
| Submission | Common signed round publication, anonymous token/ciphertext submission, signed storage acceptance and proof-authorized ciphertext review |

Exact paths, methods and schemas are in [OpenAPI](openapi.yaml). Local worker
messages are not HTTP endpoints. Member keys and enrollment requests never reach
the anonymous origin. Reviewers decrypt locally, never through a decrypt endpoint.
Replies, recovery and wider administration require reviewed contracts before routes
or UI claims are added.

## HTTP behavior

Bound bodies, headers, timeouts, concurrency and pagination. Fail closed on unknown
versions, malformed encodings, unavailable storage or invalid authority. Never
reflect raw internal errors, credentials or body contents. No request/IP/SQL-parameter
logs or cross-origin request identifiers are allowed. Do not trust proxy headers.

Payload-bound submission retries reuse only the exact pending token/ciphertext
while the round is open. They are not generic request-ID retries. Signed acceptance
attests durable storage, not log inclusion or protection against privileged rollback.

## Authentication and caching

Account authentication, local vault unlocking and anonymous authorization are
separate controls. Login alone cannot decrypt backups or authorize a response.
Identity mutations derive ownership from live sessions and sensitive operations
recheck recent authentication after storage locks. Anonymous APIs never accept
membership cookies. All responses are `no-store`; do not cache personalized pages
or persist plaintext keys, drafts or unlock material.

## Response-limit contract

The browser profile supports exactly one explicitly selected response per eligible
member/round. Publication freezes this signed value. Issuance atomically consumes
the allowance before signing and does not refund interrupted delivery. A token
permits one accepted ciphertext; exact retries cannot replace it. Higher limits
and distinct-participant result thresholds remain [protocol work](protocol.md#round-response-limit).

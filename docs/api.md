<!-- SPDX-FileCopyrightText: 2026 Anonce Contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# HTTP API contract

Audience: transport implementers and client authors.

Status: design only. [OpenAPI](openapi.yaml) describes proposed infrastructure and
public discovery endpoints; it is not evidence of a running service. Cryptographic
request schemas are intentionally absent until their encoding and profiles are
reviewed.

## Endpoint ownership

| Origin | Planned endpoints | Input boundary |
| --- | --- | --- |
| CA/issuer | `/healthz`, `/readyz`, `/api/v1/status`, `/api/v1/ca/certificate`, `/api/v1/ca/revocations` | Public discovery; no private material |
| CA/issuer | `/api/v1/enrollments`, `/api/v1/challenges`, `/api/v1/issuances` | Enrollment code/CSR, challenge context, authenticated blinded request |
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
reauthentication for sensitive actions. Public certificate, bulletin, checkpoint,
and asset responses may use explicit caches with freshness requirements. Secret or
identity-bearing responses use `Cache-Control: no-store`. Never share issuer session
cookies or authentication headers with the submission origin.

## Response-limit contract

Round publication requires the common, bounded positive integer `response_limit`
defined in [protocol](protocol.md#round-response-limit). The signed bulletin binds
it, and clients and the issuer must validate it without silently assuming a default.
An identity-side issuance request binds its reservation slot and bulletin context
to the authenticated challenge. Quota state and slot indices must never accompany
anonymous submission or receipt requests. Each issued token authorizes only one
accepted ciphertext, regardless of the round's limit.

Quota exhaustion is a safe `409` on the authenticated issuance interface, not a
reason to reset quota or fall back to identity-authenticated submission. The public
bulletin exposes the common limit, never a member's remaining allowance. Under the
same round ID, published limits are immutable. The administrative UI may suggest a
draft value, but omitted or invalid published values fail validation.

Form schemas and bulletin formats are part of the public API. Changes follow
[versioning](versioning.md), including wire/profile compatibility and migration range.
Replacing fixed single-response semantics with a configurable limit is a breaking
protocol/profile change, not a compatible optional field. No released runtime
exists to migrate; the reviewed wire profile must require the limit explicitly.

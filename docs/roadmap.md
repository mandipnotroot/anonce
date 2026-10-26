<!-- SPDX-FileCopyrightText: 2026 Anonce Contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Roadmap

Audience: contributors choosing work and reviewers assessing scope.

The repository contains documentation, checks, and local Go HTTP infrastructure,
not a working submission product.
Now / Next / Later express focus, not delivery promises. Use issues for individual
tasks and keep technical requirements in the linked reference documents.

## Now

- Extend the local Go services with CLI/WASM entry points and a Compose environment using
  the boundaries in [architecture](architecture.md) and [deployment](deployment.md).
- Extend the implemented build, race, lint, fuzz, and security targets with database,
  client, container, and browser checks from [testing](testing.md).
- Implement local key generation, bounded encrypted backups, CA signing, enrollment,
  and revocation under [key management](key-management.md) and [protocol](protocol.md).
- Keep any initial interface read-only, locally bound, and clearly marked as mock
  data. Unimplemented security operations must fail without accepting real secrets.

Implemented infrastructure consists of separate CA, issuer, and submission commands,
loopback-only listeners, liveness/status/source endpoints, and bounded shutdown.
Readiness remains unavailable. Protocol routes fail explicitly without reading
request bodies; no protocol or storage security property is claimed.

## Next

- Implement role-scoped multifactor administration, cohort imports, accessible forms,
  and signed round bulletins. See [architecture](architecture.md#administrative-access)
  and [UI design](ui-design.md).
- Complete administrator-set response limits, quota-bound blind issuance,
  ciphertext-only submission, atomic single-use spending, receipts, and independent
  verification under [protocol](protocol.md) and [database](database.md).
- Add reviewer-side decryption, encrypted replies, abuse controls, and audited
  retention without introducing identity into anonymous requests.
- Run the real database, browser, multi-user, and attack tests in [testing](testing.md).
- Add verifiable releases using the [release checklist](releasing.md).

## Later

The following extensions are optional, not replacements for required baseline
controls. Independent security review is required before real use, regardless of
whether an extension is implemented.

| Extension | Required safeguards if introduced |
| --- | --- |
| Independent witnesses | Review trust/key distribution and availability; test forks, rollback, stale or unknown checkpoints, and partitions |
| Network-anonymity deployment | Preserve origin separation; test direct-connection leaks and fallback; verify actual proxy/hosting logs and disclose timing/global-observer limits |
| Dual control | Distinct authorized approvers, operation-bound expiring approvals, recent reauthentication, cancellation and audit; reject self-approval, changed payloads, and replay; document recovery authority |
| Threshold decryption | Reviewed protocol/library and license, independent trustees, explicit threshold/recovery/collusion model, independent cryptographic review, and cross-client vectors |
| Post-quantum profiles | Distinguish final standards from drafts, use explicit opt-in identifiers, prevent downgrade, test native/WASM/imports/signers, and measure device costs; retain the RSA-token limitation |
| Kubernetes/Helm | Preserve separate databases/accounts/secrets/backups; validate network policy, non-root/read-only containers, resource bounds, health checks, pinned images, TLS, source links, upgrades and recovery |

## Open implementation questions

- Review interrupted-issuance recovery without storing token transcripts, re-signing
  a reserved slot, or exceeding the published allowance. Failed delivery consumes
  the reservation unless a stronger reviewed recovery mechanism is introduced.
- Fix the supported response-limit ceiling, quota/slot request encoding, and any
  stronger distinct-participant release mechanism before claiming those capabilities.
- Finalize token encoding, domain separation, key validation, envelope bounds,
  and keystore grammar before interoperable code. See [cryptography](cryptography.md).
- Define payload-bound submission retries and crash recovery for log publication.
- Define reviewer retrieval and reply-write authorization without membership cookies.
- Specify trusted checkpoint discovery, consistency checking, and split-view response.
- Bound aggregate filtering and ensure backup restoration cannot reactivate expired keys.

Resolve each question in its owning reference and tests, rather than relying on an
undocumented implementation assumption.

<!-- SPDX-FileCopyrightText: 2026 Anonce Contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Roadmap

Audience: contributors choosing work and reviewers assessing scope.

No working submission product yet. Now / Next / Later indicate focus, not delivery
promises. Track tasks in issues and requirements in the linked references.

## Now

- Extend the local Go services and client entry points with a Compose environment using
  the boundaries in [architecture](architecture.md) and [deployment](deployment.md).
- Extend the implemented build, race, lint, fuzz, and security targets with database,
  client, container, and browser checks from [testing](testing.md).
- Extend the offline key CLI and connect the shared device-backup and
  member/reviewer-key packages to reviewed browser interfaces. Implement reviewer
  round binding, CA signing, enrollment, and revocation under [key management](key-management.md) and
  [protocol](protocol.md).
- Extend the read-only local interface only with clearly marked mock data until
  the required security operations exist. Add browser, screenshot, and manual
  accessibility evidence under [UI design](ui-design.md#demonstration-and-evidence).

Available foundations:

- **HTTP services:** separate loopback CA, issuer, and submission commands with
  liveness, status, source discovery, and bounded shutdown. Readiness is unavailable;
  protocol routes reject without reading bodies. See [local deployment](deployment.md#local-development).
- **Read-only shell:** embedded pages and opt-in style guide, with markup, CSS,
  integrity, and delivery checks. Browser/accessibility evidence remains outstanding.
- **Device backups:** [profile 1](cryptography.md#device-backup-profile-1) encryption,
  bounded parsing, authenticated headers, cancellation-aware admission, tests,
  and native benchmarks. Typed wrappers generate member/reviewer keys and validate
  encrypted PKCS #8 backups.
- **Offline CLI:** [generation, public-key inspection, and password changes](key-management.md#local-key-cli)
  with bounded password input and no-replace encrypted files. Rewrapping preserves
  the key and does not revoke old backups. Optional independently trusted
  expected-key matching checks member/reviewer backups before public output.
  Password replacement can also require an independently trusted expected key
  before re-encryption or file creation.
  Local member CSR generation and bounded
  validation use an identity-free profile, with optional owner-only no-replace
  request export and password-free `verify-csr` public-key inspection with optional
  independently trusted expected-key matching; enrollment
  and certificate issuance remain unavailable.
- **Public-only WASM verifier:** [member-request validation](key-management.md#local-wasm-request-verification)
  reuses the shared parser, with matching loader/notices, hashes, a size gate, and
  native/Node compatibility tests. An opt-in expected-key method rejects request
  substitution when the expected key is independently trusted. No page integration
  or private-key access exists.

These foundations do not establish protocol or storage security. Browser custody,
enrollment, signing-service integration, reviewer round binding, expiry, submission
decryption, and independent security review remain outstanding.

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

Optional extensions do not replace baseline controls. Independent security review
is required before real use, with or without extensions.

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
- Finalize token encoding, domain separation, key validation, and envelope bounds
  before interoperable code. The device-backup grammar is fixed for profile 1;
  independent review and native/WASM evidence remain outstanding. See [cryptography](cryptography.md).
- Define payload-bound submission retries and crash recovery for log publication.
- Define reviewer retrieval and reply-write authorization without membership cookies.
- Specify trusted checkpoint discovery, consistency checking, and split-view response.
- Bound aggregate filtering and ensure backup restoration cannot reactivate expired keys.

Resolve questions in their owning references and tests before relying on assumptions.

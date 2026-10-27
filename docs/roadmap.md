<!-- SPDX-FileCopyrightText: 2026 Anonce Contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Roadmap

Audience: contributors choosing work and reviewers assessing scope.

No working submission product yet. Now / Next / Later indicate focus, not delivery
promises. Track tasks in issues and requirements in the linked references.

The required product is browser-only: **sign in, open a shared review link or an
available round, complete the form, submit**. Keys and encrypted member-key backup
are managed automatically. No app, CLI, manual CSR, or key files are required.
See the [user flow](ui-design.md#account-and-review-workflow) and
[vault research and decision](key-management.md#browser-account-vault).

## Now

- Resolve the browser account/vault design before implementation: passkey sign-in,
  PRF-assisted unlock on tested setups, explicit local-passphrase compatibility,
  new-device access, separate account/key recovery, and the anonymous handoff.
  Fix wrapping profiles and supported browser/provider evidence, not a promise of
  universal passkey decryption. Keep reviewer server backup excluded pending review.
- Build the identity-side foundation for a complete browser workflow: separate
  PostgreSQL instances and Compose, account authentication/sessions, owner-scoped
  encrypted member-key backup storage, enrollment, protected CA signing, and
  revocation. Preserve [service boundaries](architecture.md#account-and-anonymous-flow).
- Connect shared Go member-key and backup composition to reviewed browser interfaces
  with automatic key/CSR preparation and local restoration. The existing CLI stays
  optional; additional CLI conveniences must not displace browser integration.
- Add real database and browser targets and the
  [account/vault acceptance cases](testing.md#browser-account-and-vault-acceptance).
  Measure mobile costs, test negative/recovery paths, and collect actual browser,
  screenshot, and manual accessibility evidence. Keep unimplemented UI visibly
  unavailable and accept no real secrets in the current demonstration.

Available foundations:

- **HTTP services:** separate loopback CA, issuer, and submission commands with
  liveness, status, source discovery, and bounded shutdown. Readiness is unavailable;
  protocol routes reject without reading bodies. See [local deployment](deployment.md#local-development).
- **Read-only shell:** embedded pages and opt-in style guide, with markup, CSS,
  integrity, and delivery checks. Browser/accessibility evidence remains outstanding.
- **Device backups:** [profile 2](cryptography.md#device-backup-profile-2) uses
  Argon2id and ChaCha20-Poly1305 and provides
  bounded parsing, authenticated headers, cancellation-aware admission, tests,
  and native benchmarks. Typed wrappers generate member/reviewer keys and validate
  encrypted PKCS #8 backups.
- **Optional offline CLI:** [key generation, inspection, password changes, and
  member requests](key-management.md#local-key-cli), including trusted expected-key
  matching and owner-only no-replace exports. These are development foundations,
  not account onboarding, enrollment, certificate issuance, or key revocation.
- **Public-only WASM verifier:** [member-request validation](key-management.md#local-wasm-request-verification)
  reuses the shared parser, with matching loader/notices, hashes, a size gate, and
  native/Node compatibility tests. An opt-in expected-key method rejects request
  substitution when the expected key is independently trusted. No page integration
  or private-key access exists.
- **Member session composition:** [in-memory setup and restoration](key-management.md#in-memory-member-sessions)
  automatically prepare encrypted backups and public requests without exporting
  private bytes. Required expected-key matching, explicit lock, and cancellation
  are tested natively. A separate [local WASM bridge](key-management.md#local-wasm-member-sessions)
  adds bounded byte inputs, Promise-based setup/restoration, and lock/shutdown with
  native/Node backup compatibility checks. Browser page/worker integration and
  account binding remain unavailable.

These foundations do not establish protocol or storage security. Browser custody,
enrollment, signing-service integration, reviewer round binding, expiry, submission
decryption, and independent security review remain outstanding.

## Next

- Implement role-scoped multifactor administration, cohort imports, accessible forms,
  signed round bulletins, common review links, and an eligible-round dashboard.
  Keep anonymous receipts/replies out of account history. See
  [architecture](architecture.md#administrative-access) and [UI design](ui-design.md).
- Complete administrator-set response limits, quota-bound blind issuance,
  ciphertext-only submission, atomic single-use spending, receipts, and independent
  verification under [protocol](protocol.md) and [database](database.md).
- Add automatic round-scoped reviewer-key setup, local decryption, encrypted replies,
  abuse controls, and audited retention without identity in anonymous requests.
- Demonstrate the full browser journey from account/enrollment through a review
  link or dashboard to verified submission and authorized local review. Run the
  real database, browser, multi-user, and attack tests in [testing](testing.md),
  including new devices, recovery, shared devices, and credential-free submission.
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

- Fix account-to-membership binding, duplicate-account handling, authentication
  and recovery policy without granting eligibility or resetting quotas through login.
- Specify PRF wrapping and recovery profiles, per-credential access, trusted backup
  binding/rollback behavior, supported browser/provider matrix, and no-PRF browser UX.
  Profile 2 is password-based; no PRF/recovery format is selected or implemented.
- Specify the cross-origin anonymous handoff and navigation return flow, including
  message origins, replay/cancellation, secret-free URLs, and no identity fetches.
  Decide anonymous receipt/reply persistence separately from member-key backup.
- Define vault ownership/concurrent updates, deletion/snapshot retention, multi-tab
  lock/logout, and reviewer-key backup policy before enabling any such backup.
- Review interrupted-issuance recovery without storing token transcripts, re-signing
  a reserved slot, or exceeding the published allowance. Failed delivery consumes
  the reservation unless a stronger reviewed recovery mechanism is introduced.
- Fix the supported response-limit ceiling, quota/slot request encoding, and any
  stronger distinct-participant release mechanism before claiming those capabilities.
- Finalize token encoding, domain separation, key validation, and envelope bounds
  before interoperable code. The device-backup grammar is fixed for profile 2;
  independent review and native/WASM evidence remain outstanding. See [cryptography](cryptography.md).
- Define payload-bound submission retries and crash recovery for log publication.
- Define reviewer retrieval and reply-write authorization without membership cookies.
- Specify trusted checkpoint discovery, consistency checking, and split-view response.
- Bound aggregate filtering and ensure backup restoration cannot reactivate expired keys.

Resolve questions in their owning references and tests before relying on assumptions.

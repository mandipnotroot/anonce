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
  PostgreSQL application integration, account authentication over the local session
  store, owner-scoped encrypted member-key backup storage, enrollment, protected CA signing, and
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

- **Container infrastructure:** [local Compose stack](deployment.md#container-stack)
  for non-root Go services and independent PostgreSQL 18.6 instances, with separate
  volumes/credentials, owner/migration/runtime bootstrap roles, loopback publication,
  liveness checks, and opt-in real-container privilege/isolation checks. HTTP
  persistence, encrypted restoration, image scanning, and product readiness
  remain unavailable. Separate embedded Goose histories now have an explicit
  owner-scoped [local migration runner](database.md#local-migration-runner) and
  real-PostgreSQL version/grant checks. Identity version 2 also adds a local
  [account/session store](database.md#implemented-account-storage), digest-only
  sessions, expiry, revocation, and transactional disabling with real runtime-role
  race tests. Identity version 3 adds an internal
  [member-backup slot](database.md#local-member-backup-storage-contract) with bounded
  encrypted envelopes, fixed public binding, revision-checked updates/deletion,
  retained tombstones, and disable serialization. Credentials, product vault access,
  protocol tables, and HTTP persistence remain unavailable.
  Internal session-scoped backup methods now derive the owner from a live session,
  recheck expiry after lock waits, and serialize with revocation/disable. Mutations
  require authentication admission within five minutes. Caller-verified
  reauthentication can rotate one token without extending absolute expiry. Login
  ceremonies, product authentication policy, and browser/API integration remain open.
  Session starts now enforce a fixed 16-unexpired-session account limit under the
  same lock, without eviction. Expiry/revocation frees capacity, and rotation remains
  available at capacity. This internal admission bound does not replace rate limits
  or expired-reference cleanup.
  A session-scoped active-session inventory now returns bounded creation/expiry
  metadata and a current-session marker without exposing tokens/digests or tracking
  devices. Authorization is rechecked after account-lock waits; excess sessions
  fail without a partial list. Recently authenticated bearers can also remove
  sibling sessions without an owner override, preserving their own absolute expiry.
  Product session-management UI and browser logout integration remain unavailable.
  Identity version 4 adds independent non-secret session selectors to that inventory,
  backfilling existing rows without changing tokens or expiry. Rotation replaces
  the selector rather than creating a stable device-tracking handle.
  Recently authenticated bearers can remove one selected sibling without touching
  their own session. Stale selectors do not follow rotation, and foreign selectors
  do not reveal or modify another account's references.
  Recently authenticated bearers can also remove every account session, including
  their own, without an owner override. A later independently verified login remains
  possible; local keys and encrypted backups are unchanged. Browser logout remains open.
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
  native/Node backup compatibility checks. A separate
  [local worker owner](key-management.md#local-member-worker-host) keeps WASM off
  its owner's thread, bounds transport/lifetime, rejects overdue work using local
  monotonic/wall-clock checks even before delayed timeout callbacks, and terminates
  on disposal.
  Unlocked sessions can export a fresh encrypted member backup under a new local
  password, without exporting private bytes or rotating the key. Native/Node checks
  cover key preservation and cancellation. Opt-in confirmed setup/export methods
  reject mismatched local passwords in shared Go before key generation or derivation;
  native/Node checks cover bounds, snapshots, failure state, and cancellation.
  Independent user-entry prompts, server replacement, and product UI remain
  integration work.
  Opt-in worker text methods now provide bounded, exact UTF-8 passphrases for
  confirmed setup/export and expected-key restoration, clearing owned encoding
  buffers before return. Immutable strings cannot be erased. This is a development
  interface, not an input form or a configured account unlock method.
  A public, secret-free `closed` Promise observes terminal local cleanup, including
  idle peer locks, without polling; it does not acknowledge worker exit or logout.
  An optional `AbortSignal` lets a future host cancel startup or restoration through
  terminal local disposal without notifying peers or exposing the abort reason.
  Secret-free same-partition lock notifications and local pagehide/hidden-page
  termination have Node checks. An opt-in
  [synthetic browser target](testing.md#member-worker-browser-checks) exercises
  isolated test delivery, CSP, same-origin peer locking, background-tab locking,
  explicit foreground restoration, and navigation termination in pinned headless
  Chromium. Product delivery, partition/suspension coverage, and account binding/logout
  integration remain unavailable.

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
- Integrate the internal owner/revision contract with authenticated vault access;
  review product deletion/snapshot retention, multi-tab lock/logout, and reviewer-key
  backup policy before enabling browser backup storage.
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

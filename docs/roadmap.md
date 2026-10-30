<!-- SPDX-FileCopyrightText: 2026 Anonce Contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Roadmap

Audience: contributors choosing work and reviewers assessing scope.

The product has one browser-only journey: **sign in, open a review, complete the
form, submit**. Members, reviewers and administrators use the same account workspace;
anonymous responses remain on a separate origin. Now / Next / Later indicate focus,
not delivery promises. The current application is for synthetic data only.

## Now

- Browser passkey accounts, encrypted member vault, automatic enrollment requests,
  single-use invitations, common review links and eligible-round navigation.
- One free-text question, one reviewer and an explicitly selected one-response
  limit, with blind issuance, anonymous encryption, durable signed acceptance and
  reviewer-local decryption. See [profile 1](cryptography.md#browser-mvp-profile-1).
- Bounded account-session management, expiry-preserving reauthentication and local
  lock/logout cleanup. Remote revocation cannot erase previously loaded keys/text.
- `make up` connects matched workers, TLS services and independent databases with
  no-replace state and separately authorized migrations. See [startup](deployment.md#browser-mvp-local-startup).
- Shared Go backup/key/session components, parser fuzzing and native/Node checks;
  opt-in [real-browser, database and container checks](testing.md).

## Next

- Independently review the composition before real-data use. Resolve protected
  signing custody, revocation administration, retention and encrypted restoration.
- Measure and improve the existing browser journey: prompt counts, mobile resource
  costs, keyboard/assistive access, autofill, interrupted work and unsupported setups.
  Capture actual product screenshots and publish a supported-browser/provider matrix.
- Review passkey-assisted unlocking as an improvement to this same journey, not
  another onboarding path. Keep local unlocking separate from account authentication
  and never introduce server decryption. See [vault requirements](key-management.md#browser-account-vault).
- Define account and key recovery without quota resets, replacement-key fallback
  or reactivation of expired reviewer access. Reviewer server backup remains excluded
  until its retention and authorization policy is reviewed.
- Add broader forms, configurable response limits, role-scoped administration,
  independently anchored transparency/audit, encrypted replies and abuse controls
  under the [protocol requirements](protocol.md).
- Extend [acceptance evidence](testing.md#browser-account-and-vault-acceptance),
  multi-user simulations and attack tests. Never present an unavailable check as passing.
- Complete the [release checklist](releasing.md) before publication.

## Later

Extensions must preserve the same browser workflow and baseline privacy boundaries.
Independent witnesses, network-anonymity deployments, dual-control administration,
threshold decryption, post-quantum profiles and Kubernetes packaging each need a
reviewed trust model, compatible profiles, dependency/licensing review and real
failure/operational evidence. None is a substitute for the Next controls.

## Open implementation questions

- How should new credentials, duplicate accounts and recovery preserve membership
  binding and consumed quota without creating account-to-submission records?
- Which PRF wrapping, credential authorization and rollback-detection profiles can
  support simpler unlocking on tested devices? No such profile is admitted yet.
- Can interrupted issuance be made less costly without persisting linkable
  transcripts, refunding a consumed slot or authorizing another signing?
- How should anonymous receipts/replies persist without entering the account vault?
- Which public checkpoint discovery, split-view response and log-outbox recovery
  rules provide independently verifiable inclusion?
- How will reviewer retention, snapshot restoration, result thresholds and filters
  avoid overstating erasure or distinct-participant privacy guarantees?

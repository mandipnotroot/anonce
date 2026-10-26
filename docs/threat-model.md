<!-- SPDX-FileCopyrightText: 2026 Anonce Contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Threat model

Audience: security reviewers, implementers, and organizations considering adoption.

Status: design analysis, not a completed security assessment.

**Current controls:** [local infrastructure](deployment.md#local-development) rejects
non-loopback binds, reads no request bodies, and discards HTTP diagnostics that
could contain peer addresses or panic values. No protocol operations, signers, credentials,
or databases exist. Local users, browser-initiated requests, host compromise, and
externally configured proxies are not isolated by these controls.

The read-only shell serves public HTML/local CSS without forms or browser execution.
Mocks require explicit development mode. See [UI design](ui-design.md#current-local-shell)
for checks and missing browser/manual evidence. None establishes the protocol properties below.

The isolated device-backup package authenticates bounded opaque secrets and their
headers under [profile 1](cryptography.md#device-backup-profile-1). It is not used by
HTTP services. Malformed imports cannot select expensive work factors, but even
well-formed invalid imports cost one full KDF. Serialized derivation does not bound
caller queues, total RSS, repeated guessing, or hostile client execution. Encrypted
backups permit offline password guessing and do not prevent rollback or expired-key
reuse. See [custody limits](key-management.md#device-keystores).

The isolated member-key package generates fresh device-local Ed25519 keys and
validates canonical member-purpose encrypted backups. Export rejects inconsistent
private/public halves; import rejects other algorithms, noncanonical encodings,
and authenticated non-key payloads. No keys enter HTTP services. The package does
not verify identity, authorization, revocation, expiry, or backup freshness, and
does not protect returned private keys from callers or compromised devices.
The same password-guessing and runtime-erasure limits apply. No reviewed
password-entry, file/browser custody, enrollment, or integrated reviewer workflow exists.

The isolated reviewer-key package generates local X25519 keys and validates
canonical reviewer-purpose encrypted backups under the
[reviewer-key profile](cryptography.md#reviewer-key-payload-profile-1). It rejects
member-purpose backups, wrong algorithms, noncanonical DER, and authenticated
non-key payloads without returning private bytes. It neither binds keys to rounds
nor enforces reviewer authorization, expiry, or restoration policy. Raw returned
buffers are caller-owned, while library-internal key copies cannot be explicitly
erased. Offline guessing and compromised-device risks remain. No round-publication,
envelope-decryption, or reviewed device-custody workflow exists.

## Assets and principals

- **Assets:** membership identities, eligibility, keys, answers, token unlinkability,
  vote integrity, reply confidentiality, receipts, audit evidence, availability,
  and distributed-client integrity.
- **Roles:** see [architecture](architecture.md#administrative-access). Visitors and
  members supply lower-trust inputs; no role has unrestricted component access.
- **Assumptions:** secure primitives, good device randomness, reviewed clients
  validating trusted keys, and enforced service boundaries.
- **Limits:** operators can observe network/server traffic. Reviewers can retain
  any answer or key they obtain.

## STRIDE analysis

| Threat | Boundary and intended control | Residual risk |
| --- | --- | --- |
| Spoofing | Certificate proof of possession; passkeys/TOTP and protected sessions for admins | Stolen device keys, stolen sessions, coerced or fraudulent enrollment |
| Tampering | Signed bulletin, authenticated encryption, token verification, log proofs | A malicious publisher can create several valid views without independent consistency checks |
| Repudiation | Tamper-evident administrative events and public checkpoints | A hash chain controlled by one operator can be rewritten before external anchoring |
| Information disclosure | Device encryption, separate storage, minimized metadata, no third-party requests | Identifying text, traffic correlation, small cohorts, reviewer disclosure |
| Denial of service | Request bounds, throttling, database constraints, admission controls | Network saturation, storage exhaustion, and availability tradeoffs remain |
| Elevation of privilege | Scoped roles, server-side authorization, reauthentication, isolated signing | Host or maintainer compromise can subvert code, keys, and access policy |

## Collusion and compromise

| Adversary | What can be learned or changed |
| --- | --- |
| Issuer alone | Identities, cohort membership, and issuance participation; may deny or over-issue tokens if compromised |
| Submission operator alone | Ciphertexts, accepted token inputs, arrival patterns, and service-observed metadata |
| Reviewer alone | Plaintext content and reply capabilities; may infer identity from writing or context |
| Issuer plus submission operator | Blindness protects direct transcript linking under its assumptions, but timing, selective failures, and key partitioning can reduce anonymity |
| CA or enrollment manager | Can issue fraudulent credentials or exclude members; issuance transparency and separation of duties are needed |
| Admin plus reviewer | Can combine cohort and plaintext context; response thresholds do not prevent such inference |
| Compromised client distributor | Can serve code that steals answers or private keys before encryption |
| Compromised endpoint | Can access local plaintext and secrets regardless of transport encryption |
| Global observer | Can correlate flows despite database isolation; not covered by an unconditional anonymity claim |

## Browser delivery trust

- The inert shell uses escaped templates, restrictive CSP, and same-origin hashed
  CSS with SRI. No request values enter templates. Tests do not prove confidentiality.
- CSP, local assets, SRI, pinned WASM hashes, and reproducible builds aid inspection
  and reduce accidental compromise. A hostile origin can replace code and its displayed hash.
- Stronger verification requires an independent signature/checkpoint trust anchor
  and separately obtained CLI.
- WASM does not protect secrets from its loading page. No complete-erasure or
  universally constant-time guarantee in Go/browser runtimes.

## Small cohorts and content

- Thresholds govern release, not confidentiality from reviewers holding keys and
  ciphertext. Withholding ciphertext helps against honest-but-curious reviewers,
  not collusion with storage operators.
- Differencing, rare answer combinations, and repeated filters can reidentify.
  Publish a minimum cohort policy and restrict cross-filtering.
- One member can submit several responses. Never label response counts as distinct
  participants or turnout. Independent tokens do not prevent content/timing linkage.
- Use one common allowance, not individual limits that partition members.
- Stronger distinct-participant release claims require separate review, not identity
  fields or member slot indices in anonymous storage.

## Revocation, transfer, and deletion

- Fresh revocation checks block future issuance, not already-issued unlinkable tokens.
  Such tokens cannot be identified or selectively revoked.
- Tokens are shareable bearer capabilities. Honest-issuer quotas bound authorization,
  not authorship. Duplicate memberships or a compromised issuer can exceed per-person bounds.
- Submission storage cannot count a member's responses without breaking identity separation.
- Round-key destruction protects past data only if every relevant copy is gone.
  It is not ratcheting forward secrecy. Audit records show a procedure, not proof
  that devices or snapshots erased copies.

## Required security evidence

None of these protocol properties is implemented. Repository checks do not
establish protocol security.

| Intended property | Required evidence before claiming it |
| --- | --- |
| Eligibility | Certificate, challenge, cohort, schedule, and revocation rejection tests |
| Published per-member/round response quota | Real PostgreSQL slot/count concurrency, crash, recovery, and certificate-replacement tests for limits of one and greater than one |
| One accepted submission per token | Atomic canonical spending and payload-rebinding tests |
| Token unlinkability | Standards vectors, shared-key checks, transcript and storage inspection |
| Device-side confidentiality | Request capture, boundary tests, and log inspection proving no plaintext or keys cross into services |
| Ciphertext integrity | Tampering and cross-context rejection tests |
| Inclusion and append-only consistency | Independent proof verification, mutation tests, and split-view detection |
| Administrative accountability | Role tests and independently anchored audit verification |
| Retention protection | Controlled-copy inventory and restoration exercises with device limits disclosed |

Not provided: coercion resistance, receipt freeness, public-election assurance,
unconditional anonymity, guaranteed erasure, or end-to-end post-quantum protection.
Use established specialist systems where their model better fits the risk.

## Verification and updates

- Map mitigations to [tests](testing.md). Review new boundaries for identities,
  plaintext, keys, metadata, trust anchors, transport, and operator access.
- Track [open requirements](roadmap.md#open-implementation-questions); resolve them
  in their owning reference before implementation.
- Independent code/security review, transitive dependency audits, hosted protections,
  and reproducible-release evidence remain incomplete. One maintainer and repository
  files alone cannot establish independent review.

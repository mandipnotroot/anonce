<!-- SPDX-FileCopyrightText: 2026 Anonce Contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Threat model

Audience: security reviewers, implementers, and organizations considering adoption.

Status: design analysis, not a completed security assessment.

## Current controls and limits

These controls cover local development only. They do not establish the protocol
properties described below.

### HTTP services and shell

- [Local services](deployment.md#local-development) reject non-loopback binds,
  read no request bodies, and discard HTTP diagnostics that could expose peer
  addresses or panic values. No protocol operations, signers, credentials, or
  databases exist.
- The shell serves public HTML and local CSS without forms or browser execution.
  Mocks require explicit development mode. [Browser and manual checks](ui-design.md#current-local-shell)
  remain outstanding.
- These controls do not isolate local users, browser-initiated requests, host
  compromise, or externally configured proxies.

### Device keys and backups

- [Device-backup profile 1](cryptography.md#device-backup-profile-1) authenticates
  bounded secrets and headers. Imports cannot choose KDF costs, but a structurally
  valid import with an invalid password or tag still costs a full derivation.
  Serialized work does not bound caller queues, total process memory, or repeated guessing.
- The [member](cryptography.md#member-key-payload-profile-1) and
  [reviewer](cryptography.md#reviewer-key-payload-profile-1) wrappers generate local
  Ed25519/X25519 keys and validate purpose, algorithm, and canonical PKCS #8.
  They reject authenticated non-key payloads; member export also rejects inconsistent
  private/public halves. Failed imports return no key.
- Keys never enter HTTP services. These packages do not establish identity,
  authorization, revocation, expiry, backup freshness, or reviewer round binding.
  Browser custody, enrollment, round publication, and submission decryption are unavailable.
- Backups permit offline password guessing. They do not detect restored old copies
  or prevent expired-key reuse. Hostile callers and compromised devices can access returned secrets.
  Owned private buffers require caller cleanup; library/runtime copies prevent
  complete erasure. See [custody limits](key-management.md#device-keystores).

### Offline key CLI

- The [CLI](key-management.md#local-key-cli) accepts bounded passwords through a
  pipe/file, with confirmation for generation and password changes. It publishes
  owner-only encrypted files without replacement,
  and validates backups before printing public keys only. There is no plaintext
  private-key export or reviewed interactive password prompt.
- File checks require a trusted directory, ancestors, owner, and access-control
  lists. They do not isolate hostile same-user writers. Interruption after
  publication may leave a complete backup; crashes may leave encrypted temporary files.
- [Password changes](key-management.md#backup-password-changes) re-encrypt the same
  key. They do not delete or invalidate old copies, rotate a compromised key, or
  establish freshness or expiry. Retained copies remain open to password guessing.
- Passwords and private bytes enter the local process. Compromised-device risks
  remain, and independent device-workflow review is still required.
- [Member requests](cryptography.md#member-csr-profile-1) sign only a fixed,
  identity-free PKCS #10 structure. Bounded validation rejects extra claims and
  invalid signatures. Requests are public but linkable and replayable; they do not
  authenticate enrollment or belong on the anonymous submission path. HTTP
  services still perform no signing or request handling.
- Optional [request file export](key-management.md#local-member-certificate-requests)
  shares the owner-only, no-replace publication path but stores public DER, not
  encrypted data. Failed validation creates no file; interruption after publication
  can leave a complete request, and crashes can leave public temporary files.
  File permissions do not establish confidentiality from the device owner or make
  a request trusted.
- Local `verify-csr` uses the same bounded profile and signature validation before
  printing a public key, without passwords or private keys. File checks do not
  make that key trusted, prove freshness, or authorize enrollment.
  Its optional expected-key check rejects a valid request for a different key
  without public output. It prevents substitution only when the expected key was
  obtained independently and trusted. Public key arguments remain linkable and
  may be visible in local process listings or shell history.

### Public-only WASM verifier

- The [local verifier](key-management.md#local-wasm-request-verification) exposes
  only the existing member-request parser and public output. It bounds primitive
  string input before Go copies/decoding and does not inspect caller objects.
- Requests remain linkable and replayable; signature validation establishes no
  identity, certificate trust, freshness, or enrollment authority. Do not load
  membership requests on the anonymous submission origin.
- `verifyCSRForKey` rejects valid requests for another key without public output.
  Substitution protection requires an independently trusted expected key and a
  trusted host. Copying the expected key from the request provides no protection;
  neither key matching nor WASM protects against a compromised loading realm.
- Build hashes detect changed local artifacts, not a hostile distributor. The
  host realm and built-ins are trusted. Repeated calls, host allocations, and Go
  runtime memory are not bounded by the per-request size limit.
- Node compatibility tests are not browser execution, CSP, private-key custody,
  or independent security evidence. The HTTP shell still loads no executable code.

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

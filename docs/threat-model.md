<!-- SPDX-FileCopyrightText: 2026 Anonce Contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Threat model

Audience: security reviewers, implementers, and organizations considering adoption.

Status: design analysis, not a completed security assessment.

## Assets and principals

Protect membership identities, eligibility, private keys, answers, token unlinkability,
vote integrity, reply confidentiality, receipt validity, audit evidence, availability,
and the integrity of distributed clients. Roles are defined in the
[architecture](architecture.md#administrative-access). Public visitors and enrolled members are lower-trust
inputs; no role grants unrestricted access to every component.

Assume standard primitives remain secure, devices supply good randomness, reviewed
clients validate trusted keys, and services enforce the documented boundaries.
Operators control networks and servers but must not be assumed unable to observe
traffic. A malicious reviewer can retain any answer or key they have obtained.

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

CSP, self-hosted assets, SRI, pinned WASM hashes, and reproducible builds reduce
accidental compromise and support inspection. A hostile origin can replace both
code and the page describing its hash. An independent signature/checkpoint trust
anchor and the separately obtained CLI are required for stronger verification.
WASM is not a sandbox protecting secrets from the page that loads it. Do not promise
complete erasure or universally constant-time execution in Go or browser runtimes.

## Small cohorts and content

A response threshold is a release policy, not cryptographic protection against a
reviewer already holding the round key and ciphertext. Withheld ciphertext helps
against an honest-but-curious reviewer, but not collusion with storage operators.
Aggregates and exports can reidentify through differencing, rare answer combinations,
or repeated filters. Publish a minimum cohort policy and restrict cross-filtering.

With multiple responses allowed, one member may supply several accepted responses.
A response-count release threshold is not evidence of that many distinct members;
charts and exports must not label it as a participant count or turnout. Repeat
responses may also be linked through content or timing despite independent tokens.
Use one common published allowance, not individual limits that partition members.
Any stronger distinct-participant release claim needs a separately reviewed design,
not identity fields or member slot indices in anonymous storage.

## Revocation, transfer, and deletion

Membership revocation blocks future issuance once fresh revocation state is checked.
It cannot identify or selectively revoke an unlinkable token already issued. Tokens
are bearer capabilities and can be shared. A per-member issuance quota bounds
authorization by the honest issuer; it is not proof of who authored each response.
Fraudulent duplicate memberships or an over-issuing compromised issuer can violate
the intended per-person bound. Submission storage cannot independently count a
member's responses without undermining the identity-separation boundary.

Round-key destruction offers bounded retrospective protection only if every relevant
copy is gone. It is not a ratcheting forward-secrecy guarantee. Audit records attest
to a procedure, not a proof that devices or snapshots forgot their copies.

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

This is not a coercion-resistant election system and does not provide receipt
freeness or public-election assurance. There is no unconditional anonymity,
guaranteed erasure, or end-to-end post-quantum claim. Use established specialist
systems when their operational model better fits the risk.

## Verification and updates

Map each mitigation to a test in [testing](testing.md). Review this model whenever
identity, plaintext, keys, metadata, trust anchors, transport, or operator access
cross a new boundary. Track unresolved requirements in the [roadmap](roadmap.md#open-implementation-questions)
and resolve them in the owning reference before implementation.

Independent code review, external security review, transitive dependency audits,
hosted protection settings, and reproducible-release evidence remain incomplete.
The repository has one maintainer; its files alone cannot establish independent review.

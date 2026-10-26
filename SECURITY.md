<!-- SPDX-FileCopyrightText: 2026 Anonce Contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Security policy

Audience: security researchers, contributors, and operators.

## Current support

- No released or production-supported versions. Only design docs, contributor checks,
  and demo HTTP infrastructure exist; the submission protocol is unimplemented.
- Review of `main` is best effort, not cryptographic or deployment certification.
- Future security fixes cover the latest release only, unless this policy says otherwise.

## Private disclosure

Use [Report a vulnerability](https://github.com/mandipnotroot/anonce/security/advisories/new)
in the Security tab. If unavailable, request a private channel through the maintainer's
profile without disclosing details.

- Include revision, trust boundary, expected/actual behavior, dummy-data reproduction,
  and minimal impact evidence.
- Never post exploit details, personal data, tokens, private keys, or real submissions publicly.
- Do not test deployed organizations, others' accounts, or availability without explicit permission.

## Response targets

| Response | Volunteer target, not a guarantee |
| --- | --- |
| Acknowledgment | 7 calendar days |
| Initial assessment | 14 days |
| Coordinated publication | Normally within 90 days, depending on severity |

Coordinate remediation and disclosure by severity. Active exploitation may require
earlier warnings. Consult reporters on credit and timing.

## Operator obligations

Follow [deployment](docs/deployment.md) for source, separation, logging, backups,
and key retention. Do not use current development infrastructure for real submissions.

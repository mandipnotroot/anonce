<!-- SPDX-FileCopyrightText: 2026 Anonce Contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Security policy

Audience: security researchers, contributors, and operators.

## Current support

- No released or production-supported versions. The browser application connects
  passkey accounts, encrypted member backups, enrollment, anonymous encrypted
  submissions and local review for synthetic data only. See [project status](docs/README.md#project-status).
- Review of `main` is best effort, not cryptographic or deployment certification.
- Recovery, PRF unlocking, protected signer custody and reviewer server backup are
  not implemented. Do not infer that account authentication decrypts keys or that
  passkeys remove trust in browser-code delivery. See [custody limits](docs/key-management.md#browser-account-vault).
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

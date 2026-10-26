<!-- SPDX-FileCopyrightText: 2026 Anonce Contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Security policy

Audience: security researchers, contributors, and operators.

## Current support

There are no released or production-supported versions. The repository currently
contains design documents and contributor checks. Review of `main` is best effort;
no cryptographic or deployment security certification is implied.

When releases exist, the latest published release will receive security fixes.
Older releases are unsupported unless this policy explicitly says otherwise.

## Private disclosure

Use [Report a vulnerability](https://github.com/mandipnotroot/anonce/security/advisories/new)
in the repository's Security tab. Do not open a public issue with exploit details,
personal data, tokens, private keys, or real submission contents. If private reporting
is unavailable, use the maintainer's profile to request a private contact channel
without including vulnerability details.

Include the affected revision, trust boundary, expected and actual behavior, safe
reproduction using dummy data, and the smallest evidence needed to assess impact.
Do not test deployed organizations, other people's accounts, or availability
without their explicit permission.

## Response targets

The maintainer aims to acknowledge reports within seven calendar days and provide
an initial assessment within fourteen. Coordinate remediation and disclosure
according to severity, normally targeting publication within ninety days. These
are goals for a volunteer project, not guaranteed response times. Active exploitation
may require earlier warnings. Reporters will be consulted about credit and timing.

## Operator obligations

The [deployment guide](docs/deployment.md) defines source availability, operational
separation, logging, backup, and key-retention requirements. Do not deploy the current
documentation foundation to collect real submissions.

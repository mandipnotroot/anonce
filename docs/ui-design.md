<!-- SPDX-FileCopyrightText: 2026 Anonce Contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Interface design system

Audience: front-end contributors, accessibility reviewers, and product reviewers.

Status: read-only local shell implemented; product UI is design only. No browser
screenshots or accessibility results yet.

## Current local shell

- **Pages:** submission-only `/` and `/about`; `/dev/styleguide` requires
  `-dev-styleguide`. The guide has a synthetic draft, unavailable publication button,
  and empty/status examples, not administration.
- **Content:** no public mock response metrics, forms, private data, or scripts.
  Every page has a development warning, source footer, landmarks, and skip link.
- **Style:** original CSS/device fonts pending product-dependency review. Responsive
  layout, visible focus, system light/dark colors, print rules, no animation.
  See [deployment](deployment.md#transport-and-headers) for hashed CSS/SRI delivery.
- **Evidence:** `make web-lint` checks inert markup, fragments, links, hashes,
  CSS loading, headers, methods, and development gating. It does not validate full
  HTML/CSS, run browsers, measure contrast, establish WCAG conformance, or replace
  keyboard/assistive review. Actual desktop/mobile and light/dark screenshots plus
  browser/manual checks remain required; no substitute rendering images are provided.

## Visual language

Future product: Pico CSS 2.1.1, custom layout tokens, local Inter 4.1, selected
licensed SVG icons, and SVG charts. Server-render only public/mock charts;
render decrypted results on the reviewer device. Use calm surfaces, clear hierarchy,
and useful whitespace, not decorative security imagery.

| Token | Proposed value or rule |
| --- | --- |
| Primary | Indigo `#4338ca` in light mode; contrast-tested lighter variant in dark mode |
| Accent | Teal `#0f766e`; never the only indication of status |
| Surfaces | Light `#ffffff` / `#f5f7fb`; dark `#111827` / `#0b1020` |
| Text | Light `#172033`; dark `#eef2ff`; muted text needs separate contrast tests |
| Spacing | 4, 8, 12, 16, 24, 32, 48 CSS pixels |
| Typography | 1rem body with at least 1.5 line height; restrained 1.125/1.25/1.5/2rem headings |
| Shape | 8px controls, 12px cards; subtle borders rather than heavy shadows |
| Width | Readable prose at about 70 characters; responsive data panels |
| Motion | Short functional transitions; respect `prefers-reduced-motion` |

Values are candidates. Test all foreground/background, focus, disabled, chart, and
error combinations against [WCAG 2.2 AA](https://www.w3.org/TR/WCAG22/).

## Layout and navigation

- Admin: collapsible sidebar, meaningful titles, breadcrumbs, visible role/round context.
- Member: simple header and narrow content column.
- Mobile: keyboard and screen-reader navigation.
- All views: visible focus, skip links, logical headings, one main landmark.

| Area | Planned paths |
| --- | --- |
| Public | `/`, `/about`, `/source`, `/verify`, `/transparency` |
| Member | `/enroll`, `/member`, `/member/submit`, `/member/receipts`, `/member/replies` |
| Admin access/overview | `/admin/login`, `/admin` |
| CA | `/admin/ca`, `/admin/ca/certificates`, `/admin/ca/revocations` |
| Cohorts | `/admin/cohorts`, `/admin/cohorts/members`, `/admin/cohorts/import`, `/admin/cohorts/codes` |
| Forms/rounds | `/admin/forms`, `/admin/forms/builder`, `/admin/rounds`, `/admin/rounds/keys` |
| Review | `/reviewer`, `/reviewer/results`, `/reviewer/replies`, `/reviewer/flags` |
| Administration | `/admin/audit`, `/admin/users`, `/admin/settings` |
| Explicit development mode | `/dev/styleguide` |

## Component contract

- Provide consistent buttons, labelled forms, validation summaries, cards, badges,
  responsive tables, pagination, lifecycle indicators, accessible charts,
  live-region toasts, loading indicators, and useful empty states.
- Errors give safe next actions without exposing internal data.
- Destructive dialogs name the action/resource, default to cancel, trap focus,
  and restore trigger focus. Sensitive operations also require recent server-side
  reauthentication; dialogs do not replace it.
- Printed codes omit navigation/unnecessary member data and show expiry/handling
  instructions. Prevent accidental printing of entire directories.
- Every chart needs a table or accessible text equivalent.

## Round response policy

Apply [protocol rules](protocol.md#round-response-limit) for `response_limit`:
authorized manager, validated draft value, suggested `1` for ballots, supported
larger values, explicit publication confirmation, and no changes without a new round.

- Label the limit separately from the release threshold. Show it in round summaries
  and submission flows; lock after publication.
- Identity-side views may show unreserved allowance. Distinguish reserved slots,
  held tokens, and verified receipts; warn that interrupted issuance can consume allowance.
- Never fetch quota from anonymous pages or attach it to submissions.
- Count responses, not distinct respondents/turnout without separately reviewed evidence.

## Privacy and assets

Serve embedded, integrity-hashed assets with no third-party requests under the
[browser-delivery controls](deployment.md#transport-and-headers). Every page retains a visible
`/source` footer link under the [source-availability contract](deployment.md#agpl-section-13).

## Demonstration and evidence

- Initial shell: read-only, loopback by default; explicit development config for
  admin previews. Visibly label mocks, disabled authentication, and unavailable actions.
- Unimplemented security operations fail without accepting plaintext, private keys,
  or real enrollment data. No shared demo passwords or simulated cryptographic success.
- Capture actual tested desktop/mobile, light/dark screenshots in CI. Strip/verify
  empty metadata, cover images with REUSE, and publish artifacts.
- Supplement axe checks with manual keyboard, screen-reader, zoom, contrast, and
  print reviews. Automated scans alone cannot establish full WCAG conformance.

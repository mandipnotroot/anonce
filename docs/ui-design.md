<!-- SPDX-FileCopyrightText: 2026 Anonce Contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Interface design system

Audience: front-end contributors, accessibility reviewers, and product reviewers.

Status: a read-only local shell is implemented. The product interface below remains
a design specification. Browser screenshots and accessibility results are not yet
available.

## Current local shell

Only the submission process serves `/` and `/about`, plus `/dev/styleguide` when
explicitly enabled by `-dev-styleguide`. The style guide contains a synthetic draft
summary, an unavailable publication button, and empty-state/status examples. It is
not an administrative interface. Public pages contain no mock response metrics,
input forms, private data, or executable scripts. All pages have a development
warning, a source footer, semantic landmarks, and a skip link.

The minimal shell uses original CSS and device fonts rather than vendoring the
proposed product dependencies before their review. It includes responsive layout,
visible keyboard focus, system-selected light/dark colors, and print rules. It has
no animation. The stylesheet is content-addressed and SRI-linked; delivery controls
are in [deployment](deployment.md#transport-and-headers).

`make web-lint` checks rendered inert markup, fragment references, local links,
asset hashes, CSS loading restrictions, headers, methods, and the development gate.
It does not run a browser, validate full HTML/CSS grammar, measure contrast, establish
WCAG conformance, or replace keyboard and assistive-technology review. Actual
desktop/mobile, light/dark screenshots and browser/manual checks remain required;
no substitute images are supplied as evidence of rendering.

## Visual language

For the future product interface, use Pico CSS 2.1.1 with custom layout tokens, locally served Inter 4.1 fonts, a small
licensed SVG icon selection, and SVG charts. Only public or mock chart data may be
server-rendered; decrypted results must be rendered on the reviewer device. Prefer calm surfaces,
clear hierarchy, and meaningful whitespace over decorative security imagery.

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

These values are candidates, not a conformance assertion. Verify every foreground,
background, focus, disabled, chart, and error combination against WCAG 2.2 AA.

## Layout and navigation

Administrative views use a collapsible sidebar, meaningful page titles, breadcrumbs,
and a visible role/round context. Member views use a simpler header and a narrow
content column. Mobile navigation must work with keyboard and screen reader input.
Preserve visible focus, skip links, logical heading order, and a single main landmark.

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

Provide consistent buttons, labelled forms, validation summaries, cards, badges,
responsive tables, pagination, lifecycle indicators, charts with text equivalents,
toasts announced through a live region, loading indicators, and useful empty states.
Errors must identify what the person can safely do without disclosing internal data.

Destructive dialogs name the action and affected resource, default to cancellation,
trap focus correctly, and return focus to the trigger. Actual sensitive operations
also require recent server-side reauthentication. A visual confirmation is not that
security control.

Print styles for enrollment codes omit navigation, avoid unnecessary member data,
and show expiry and handling instructions. Prevent accidental printing of entire
member directories. Charts always have a table or accessible text equivalent.

## Round response policy

An authorized round manager selects the per-member `response_limit` in the draft
round. Label it separately from the minimum response threshold for releasing
results. Suggest `1` for single-response ballots, allow supported larger values for
other rounds, validate the range, and require explicit confirmation on publication.
Show the published limit in the round summary and member submission flow. Lock the
control after publication; changing it requires a new round, not a hidden override.

The identity-side member view may show remaining unreserved allowance. A local
client must distinguish reserved slots, locally held tokens, and verified accepted
receipts; an interrupted issuance can consume allowance without delivering a usable
token. Do not fetch identity-side quota state from anonymous submission pages
or attach it to submission requests. Charts and exports count responses, not
distinct respondents or turnout without separate reviewed evidence.

## Privacy and assets

Serve embedded, integrity-hashed assets with no third-party requests under the
[browser-delivery controls](deployment.md#transport-and-headers). Every page retains a visible
`/source` footer link under the [source-availability contract](deployment.md#agpl-section-13).

## Demonstration and evidence

Keep an initial shell read-only and bound to loopback by default. Require explicit
development configuration for admin previews. Label mock metrics, disabled
authentication, and unavailable actions visibly. Unimplemented security operations
must fail without accepting plaintext, private keys, or real enrollment data; never
use shared demo passwords or simulated cryptographic success.

Capture desktop/mobile, light/dark screenshots from the actual tested shell in CI.
Strip metadata, verify it is empty, cover images through REUSE, and publish artifacts.
Manual keyboard, screen-reader, zoom, contrast, and print reviews supplement automated
axe checks. Do not claim full WCAG conformance from a clean automated scan alone.

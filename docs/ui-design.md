<!-- SPDX-FileCopyrightText: 2026 Anonce Contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Interface design system

Audience: front-end contributors, accessibility reviewers, and product reviewers.

The browser application is the only product interface. Broader product screens,
product screenshots, mobile/provider measurements and manual accessibility evidence
remain outstanding. Simplicity must not hide security boundaries or missing capabilities.

## Account and review workflow

The goal is **sign in, open a review, submit**. Every role uses browser forms,
without an app, extension, console, manual key generation, certificate-request
handling or key files. The browser prepares keys, encryption and encrypted member
backups automatically.

| Situation | Experience |
| --- | --- |
| First visit | Create/sign in with a passkey, set up private access with confirmed local passphrase, verify a membership invitation |
| Shared review link | Open common round information, authorize through the identity popup, then complete and submit the anonymous form |
| Member dashboard | List eligible reviews and public schedules, not submission history |
| Return visit | Sign in and unlock private access when needed; reuse safely unlocked state within its fixed lifetime |
| Another device | Sign in and restore the same encrypted member key locally, without copying files |
| Administrator | Create invitations and a draft, assign a reviewer, confirm publication and share the common link |
| Reviewer | Prepare fresh round access automatically, unlock locally and read browser-decrypted answers |
| Loss/recovery | Explain exactly what is unavailable; account and key recovery are not implemented |

Account creation does not establish membership. Login does not decrypt a backup.
Keep those checks distinct within the same journey, with plain-language labels and
safe next actions. Do not offer alternate onboarding or server decryption.
See [custody and unlocking](key-management.md#browser-account-vault).

The identity and anonymous origins are a privacy boundary, not two ways to submit.
Common round links contain no member tracking or bearer secret. Invitations stop
at the identity origin. Account dashboards never look up receipts or mailboxes
with account credentials. Member backup restoration does not restore anonymous
receipt/reply state.

## Connected browser MVP pages

All roles share one identity workspace with private access, reviews and sessions.
The separate anonymous page owns answer entry, token state, encryption and signed
acceptance. Its account/reviews link carries no round, token or receipt back and
suppresses referrers. Decrypted reviewer text uses `textContent`, never HTML
interpolation or a plaintext server endpoint.

The current review is one free-text question, one reviewer and an explicitly
selected one-response limit. Show the signed schedule/limit, local-key retention,
issuance-loss warning and signed-storage-not-public-inclusion limitation. Replies,
charts, generalized forms, credential/recovery management and advanced
administration are unavailable and must not look operational.

### Private access and local state

Use independently labelled setup passphrase and confirmation fields with
`autocomplete="new-password"`; unlocking uses `autocomplete="current-password"`.
Allow paste and password managers. Clear fields promptly, expose live progress,
safe errors and keyboard-operable cancel/lock controls, and reject late results
after cancellation or worker closure. Wrong passphrases and corrupt backups must
never start setup or replace the enrolled key.

Explain that changing tabs or reaching the worker deadline locks private access
and requires explicit unlocking. Do not silently restart a closed worker or save
plaintext drafts on services. Warn before actions that can discard unsent text.
Reviewer encrypted access stays in this browser; clearing it can permanently lose
review access. Never imply account sign-in restores it.

An undecryptable answer gets a plain-language placeholder without hiding later
records or pages. The final status reports the number of rejected answers. Lock,
hidden-page state, round expiry, and reviewer-owner replacement stop reading
instead of being treated as bad answers; no late plaintext or success status is
displayed.

### Session controls

List own sessions with a current marker and authentication/expiry times, not device
identification claims. Other sessions have labelled sign-out buttons. Sign-out
everywhere requires explicit confirmation. Passkey verification locks local keys,
preserves absolute expiry and never automatically repeats a failed mutation.
Explain the five-minute sensitive-action window and require refresh/fresh sign-in
for uncertain outcomes. See [the session contract](api.md#browser-session-management).

Sign-out and observed invalidation clear passphrases, reviewer plaintext, pending
local work and account controls. Same-partition notices and visible-page checks
are best effort. State clearly that suspended pages and remotely copied keys/text
cannot be erased; encrypted backups are retained.

## Visual language

Use the existing first-party CSS and device fonts, calm surfaces, clear hierarchy
and readable line lengths. Keep styling consistent across roles rather than
creating another application shell. Use whitespace and restrained color, not
decorative security imagery. Every state needs text, not color alone.

Test foreground/background, focus, disabled and error combinations against
[WCAG 2.2 AA](https://www.w3.org/TR/WCAG22/). Targets are requirements, not a
conformance claim. Product desktop/mobile and light/dark screenshots must come
from the actual built application with synthetic data.

## Layout and navigation

Provide a skip link, one main landmark, logical headings, visible focus, meaningful
titles and clear role/round context. Keep the main form narrow and readable and
navigation usable on small screens and by keyboard. Use one consistent action and
error vocabulary. Do not invent separate login paths or duplicate forms for roles.

## Component contract

- Labels, validation summaries, live status, loading/empty states and progress must
  remain accessible. Controls start disabled until their dependencies are ready.
- Errors explain a safe next action without exposing keys, credentials or internals.
- Destructive confirmations name the resource/action and default to cancel. Future
  dialogs must manage/restore focus. Server authorization and recent authentication
  remain mandatory where required; confirmation is not an access control.
- Future charts need accessible text/table equivalents. Decrypted results and
  exports must remain local; never upload them for rendering.

## Round response policy

The current profile admits only an explicitly selected limit of one. Publication
freezes it. Broader [response limits](protocol.md#round-response-limit) need reviewed
forms, signed bounds, quota tests and clear distinction between unreserved allowance,
consumed issuance and accepted answers. Do not describe response counts as distinct
participants or claim key-holder-enforced release thresholds.

## Privacy and assets

No third-party requests, remote fonts, analytics, inline executable scripts or
identity-personalized anonymous assets. Go serves embedded first-party assets and
matched worker runtimes with original licenses/notices. Keep tokens and secrets
out of URLs, browser history, account vaults and diagnostics.

## Demonstration and evidence

Use synthetic data only. `make web-lint` checks embedded product assets and markup;
`make browser-test` exercises the connected journey. Component harness screenshots
are not product screenshots. Automated accessible-name/keyboard checks do not
replace manual assistive-technology, contrast, autofill, mobile or provider review.
See [acceptance evidence](testing.md#browser-account-and-vault-acceptance).

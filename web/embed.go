// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

// Package webassets contains the locally served demonstration templates and CSS.
package webassets

import "embed"

// Files contains only first-party, read-only demonstration assets.
//
//go:embed templates/*.html assets/*.css
var Files embed.FS

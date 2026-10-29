// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

// Package migrations contains the separate, immutable SQL histories.
package migrations

import (
	"embed"
	"fmt"
	"io/fs"
)

//go:embed identity/*.sql submission/*.sql
var files embed.FS

// Files returns only the requested service's history.
func Files(side string) (fs.FS, error) {
	if side != "identity" && side != "submission" {
		return nil, fmt.Errorf("invalid migration service")
	}
	return fs.Sub(files, side)
}

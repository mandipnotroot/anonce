//go:build browsermvp

// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

package browserjourney

import (
	"io/fs"
	"net/http"
	"os"
	"path/filepath"

	web "github.com/mandipnotroot/anonce/web/browser"
)

func newAssets(identity bool, peer, root string) (http.Handler, error) {
	var member fs.FS
	if identity {
		member = os.DirFS(filepath.Join(root, "bin/memberwasm"))
	}
	return web.New(identity, peer, "https://example.invalid/synthetic-source", member, os.DirFS(filepath.Join(root, "bin/reviewwasm")))
}

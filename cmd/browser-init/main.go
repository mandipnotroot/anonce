// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"fmt"
	"os"

	"github.com/mandipnotroot/anonce/internal/browserapp"
)

func main() {
	var err error
	switch {
	case len(os.Args) == 2:
		err = browserapp.Initialize(os.Args[1])
	case len(os.Args) == 3 && os.Args[1] == "-empty-directory":
		err = browserapp.InitializeEmpty(os.Args[2])
	default:
		err = os.ErrInvalid
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "Browser initialization failed. Supply a new private state directory; existing files are never replaced.")
		os.Exit(1)
	}
}

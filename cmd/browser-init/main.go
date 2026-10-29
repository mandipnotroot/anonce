// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"fmt"
	"os"

	"github.com/mandipnotroot/anonce/internal/browserapp"
)

func main() {
	if len(os.Args) != 2 || browserapp.Initialize(os.Args[1]) != nil {
		fmt.Fprintln(os.Stderr, "Browser initialization failed. Supply a new private state directory; existing files are never replaced.")
		os.Exit(1)
	}
}

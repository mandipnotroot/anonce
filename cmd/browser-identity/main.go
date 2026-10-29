// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"fmt"
	"os"

	"github.com/mandipnotroot/anonce/internal/browserapp"
	"github.com/mandipnotroot/anonce/internal/browseridentity"
)

func main() {
	if browserapp.Command("identity", os.Args[1:], browseridentity.FromState) != nil {
		fmt.Fprintln(os.Stderr, "Identity browser startup or service failed. Check explicit configuration, migrations and local files.")
		os.Exit(1)
	}
}

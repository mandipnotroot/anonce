// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"fmt"
	"os"

	"github.com/mandipnotroot/anonce/internal/browserapp"
	"github.com/mandipnotroot/anonce/internal/browsersubmission"
)

func main() {
	if browserapp.Command("submission", os.Args[1:], browsersubmission.FromState) != nil {
		fmt.Fprintln(os.Stderr, "Anonymous browser startup or service failed. Check explicit configuration, migrations and local files.")
		os.Exit(1)
	}
}

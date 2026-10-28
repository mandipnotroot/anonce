// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

// Command probe checks fixed container-local liveness without shell utilities.
package main

import (
	"context"
	"os"

	"github.com/mandipnotroot/anonce/internal/healthprobe"
)

func main() {
	if len(os.Args) != 2 || healthprobe.Check(context.Background(), os.Args[1]) != nil {
		os.Exit(1)
	}
}

// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"os"

	"github.com/mandipnotroot/anonce/internal/clientcli"
)

func main() {
	os.Exit(clientcli.Main())
}

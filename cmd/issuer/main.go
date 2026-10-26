// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"os"

	"github.com/mandipnotroot/anonce/internal/app"
	"github.com/mandipnotroot/anonce/internal/service"
)

func main() {
	os.Exit(app.Main(service.Issuer))
}

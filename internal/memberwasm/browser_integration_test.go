//go:build browserintegration && !js

// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

package memberwasm

import (
	"io"
	"log"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestMemberNativeBrowserCompatibility(t *testing.T) {
	assets, err := browserAssets(os.DirFS("../../bin/memberwasm"))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(nil)
	server.Config.Handler = browserHandler(assets, server.Listener.Addr().String())
	server.Config.ReadHeaderTimeout = 5 * time.Second
	server.Config.ReadTimeout = 10 * time.Second
	server.Config.WriteTimeout = 10 * time.Second
	server.Config.IdleTimeout = 30 * time.Second
	server.Config.MaxHeaderBytes = 8 << 10
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.Start()
	defer server.Close()
	testMemberCompatibility(t, "member_browser_test.mjs", server.URL)
}

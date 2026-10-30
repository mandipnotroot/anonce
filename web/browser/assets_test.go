// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

package browser

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io/fs"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

func runtimeFixture(member bool) fstest.MapFS {
	names := []string{"LICENSE", "LICENSE.anonce", "LICENSE.circl", "LICENSE.x-crypto", "LICENSE.x-sys", "PATENTS", "PATENTS.x-crypto", "PATENTS.x-sys", "client.wasm", "wasm_exec.js"}
	if member {
		names = append(names, "member-client.mjs", "member-worker.mjs", "protocol.mjs")
	}
	files := make(fstest.MapFS)
	var manifest strings.Builder
	for _, name := range names {
		data := []byte("synthetic runtime material: " + name)
		files[name] = &fstest.MapFile{Data: data}
		fmt.Fprintf(&manifest, "%x  %s\n", sha256.Sum256(data), name)
	}
	files["SHA256SUMS"] = &fstest.MapFile{Data: []byte(manifest.String())}
	return files
}

func TestRuntimeManifestAdmission(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(fstest.MapFS) fs.FS
	}{
		{"missing-runtime", func(fstest.MapFS) fs.FS { return nil }},
		{"missing-material", func(f fstest.MapFS) fs.FS { delete(f, "client.wasm"); return f }},
		{"changed-material", func(f fstest.MapFS) fs.FS { f["client.wasm"].Data = []byte("changed"); return f }},
		{"duplicate", func(f fstest.MapFS) fs.FS {
			f["SHA256SUMS"].Data = append(f["SHA256SUMS"].Data, f["SHA256SUMS"].Data...)
			return f
		}},
		{"traversal", func(f fstest.MapFS) fs.FS {
			f["SHA256SUMS"].Data = []byte(strings.Repeat("0", 64) + "  ../client.wasm\n")
			return f
		}},
		{"oversized", func(f fstest.MapFS) fs.FS { f["SHA256SUMS"].Data = make([]byte, 8193); return f }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if handler, err := New(false, "https://identity.localhost:8443", "https://example.invalid/source", nil, tc.mutate(runtimeFixture(false))); err == nil || handler != nil {
				t.Fatal("invalid runtime admitted")
			}
		})
	}
}

func TestEmbeddedPagesAndPolicy(t *testing.T) {
	for _, identity := range []bool{false, true} {
		t.Run(fmt.Sprint(identity), func(t *testing.T) {
			handler, err := New(identity, "https://identity.localhost:8443", "https://example.invalid/source", runtimeFixture(true), runtimeFixture(false))
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, httptest.NewRequest("GET", "https://local.invalid/", nil))
			if w.Code != 200 || !strings.Contains(w.Header().Get("Content-Type"), "text/html") {
				t.Fatal("embedded page unavailable")
			}
			csp := w.Header().Get("Content-Security-Policy")
			if strings.Contains(csp, "https://identity.localhost:8443") != identity || strings.Contains(csp, "wasm-unsafe-eval") {
				t.Fatal("incorrect page connection or execution policy")
			}
			for _, name := range []string{"screen.css", "identity.mjs", "anonymous.mjs"} {
				data, err := files.ReadFile(name)
				if err != nil {
					t.Fatal(err)
				}
				digest := sha256.Sum256(data)
				pageEntry := name == "screen.css" || identity && name == "identity.mjs" || !identity && name == "anonymous.mjs"
				if pageEntry && !strings.Contains(w.Body.String(), `integrity="sha256-`+base64.StdEncoding.EncodeToString(digest[:])+`"`) {
					t.Fatal("entry asset integrity missing")
				}
			}
			for _, path := range []string{"/assets/identity.html", "/assets/screen.css", "/assets/missing"} {
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, httptest.NewRequest("GET", "https://local.invalid"+path, nil))
				if w.Code != 404 {
					t.Fatal("unexpected unversioned resource delivery")
				}
			}
		})
	}
}

func TestBrowserLiveness(t *testing.T) {
	handler, err := New(true, "https://submit.localhost:8444", "https://example.invalid/source", runtimeFixture(true), runtimeFixture(false))
	if err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{"GET", "HEAD", "POST"} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(method, "https://local.invalid/healthz", nil))
		want := "ok"
		if method == "HEAD" {
			want = ""
		}
		if method == "POST" {
			if w.Code != 405 {
				t.Fatal("liveness write admitted")
			}
		} else if w.Code != 200 || w.Body.String() != want {
			t.Fatal("incorrect browser liveness")
		}
	}
}

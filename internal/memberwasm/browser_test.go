// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

package memberwasm

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
)

// This delivery harness exists only in test binaries. Product services never
// import it or serve executable assets on the anonymous submission origin.
//
//go:embed testdata/browser.html testdata/browser.mjs
var browserFiles embed.FS

const browserPageCSP = "default-src 'none'; script-src 'self'; worker-src 'self'; connect-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"

const browserWorkerCSP = "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; connect-src 'self'; worker-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"

var browserAssetNames = []string{
	"LICENSE", "LICENSE.anonce", "LICENSE.x-crypto", "LICENSE.x-sys",
	"PATENTS", "PATENTS.x-crypto", "PATENTS.x-sys", "client.wasm",
	"member-client.mjs", "member-worker.mjs", "protocol.mjs", "wasm_exec.js",
}

// Read bounded assets once, then verify the complete manifest before listening.
// The manifest detects build corruption, not a malicious local distributor.
func browserAssets(files fs.FS) (map[string][]byte, error) {
	read := func(name string, maximum int64) ([]byte, error) {
		info, err := fs.Stat(files, name)
		if err != nil || !info.Mode().IsRegular() || info.Size() > maximum {
			return nil, errors.New("unavailable or oversized browser test asset")
		}
		file, err := files.Open(name)
		if err != nil {
			return nil, errors.New("cannot open browser test asset")
		}
		data, err := io.ReadAll(io.LimitReader(file, maximum+1))
		closeErr := file.Close()
		if err != nil || closeErr != nil || int64(len(data)) > maximum {
			return nil, errors.New("cannot read browser test asset")
		}
		return data, nil
	}
	manifest, err := read("SHA256SUMS", 4096)
	if err != nil {
		return nil, err
	}
	assets := map[string][]byte{"/SHA256SUMS": manifest}
	for line := range strings.SplitSeq(strings.TrimSuffix(string(manifest), "\n"), "\n") {
		if len(line) < 67 || line[64:66] != "  " {
			return nil, errors.New("invalid browser test manifest")
		}
		name := line[66:]
		if !slices.Contains(browserAssetNames, name) || assets["/"+name] != nil {
			return nil, errors.New("unexpected browser test manifest entry")
		}
		maximum := int64(256 << 10)
		if name == "client.wasm" {
			maximum = 8 << 20
		}
		data, err := read(name, maximum)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != line[:64] {
			return nil, errors.New("browser test asset digest mismatch")
		}
		assets["/"+name] = data
	}
	if len(assets) != len(browserAssetNames)+1 {
		return nil, errors.New("incomplete browser test manifest")
	}
	for path, name := range map[string]string{"/": "browser.html", "/browser.mjs": "browser.mjs"} {
		data, err := browserFiles.ReadFile("testdata/" + name)
		if err != nil {
			return nil, errors.New("missing browser test page")
		}
		assets[path] = data
	}
	return assets, nil
}

func FuzzMemberBrowserManifest(f *testing.F) {
	f.Add(syntheticBrowserFiles()["SHA256SUMS"].Data)
	f.Add([]byte("invalid"))
	f.Fuzz(func(t *testing.T, manifest []byte) {
		if len(manifest) > 4097 {
			return
		}
		files := syntheticBrowserFiles()
		files["SHA256SUMS"].Data = manifest
		assets, err := browserAssets(files)
		if err != nil && assets != nil {
			t.Fatal("partial asset set returned")
		}
	})
}

func browserHandler(assets map[string][]byte, host string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", browserPageCSP)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		// Never read or drain bodies, including rejected methods and unknown paths.
		if r.Body != nil && r.Body != http.NoBody {
			r.Close = true
			w.Header().Set("Connection", "close")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if r.Host != host {
			w.WriteHeader(http.StatusMisdirectedRequest)
			return
		}
		if origin := r.Header.Get("Origin"); (origin != "" && origin != "http://"+host) || r.Header.Get("Sec-Fetch-Site") == "cross-site" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		data, ok := assets[r.URL.Path]
		if !ok || r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.RawPath != "" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		contentType := "text/plain; charset=utf-8"
		switch {
		case r.URL.Path == "/":
			contentType = "text/html; charset=utf-8"
		case strings.HasSuffix(r.URL.Path, ".mjs"), strings.HasSuffix(r.URL.Path, ".js"):
			contentType = "text/javascript; charset=utf-8"
		case r.URL.Path == "/client.wasm":
			contentType = "application/wasm"
		}
		if r.URL.Path == "/member-worker.mjs" {
			w.Header().Set("Content-Security-Policy", browserWorkerCSP)
		}
		w.Header().Set("Content-Type", contentType)
		w.WriteHeader(http.StatusOK)
		if r.Method != http.MethodHead {
			_, _ = w.Write(data)
		}
	})
}

func syntheticBrowserFiles() fstest.MapFS {
	files := fstest.MapFS{}
	var manifest strings.Builder
	for _, name := range browserAssetNames {
		data := []byte("synthetic " + name)
		files[name] = &fstest.MapFile{Data: data}
		sum := sha256.Sum256(data)
		manifest.WriteString(hex.EncodeToString(sum[:]) + "  " + name + "\n")
	}
	files["SHA256SUMS"] = &fstest.MapFile{Data: []byte(manifest.String())}
	return files
}

func TestMemberBrowserAssets(t *testing.T) {
	for _, name := range []string{"valid", "missing", "changed", "duplicate", "traversal", "incomplete", "oversized", "directory"} {
		t.Run(name, func(t *testing.T) {
			files := syntheticBrowserFiles()
			switch name {
			case "missing":
				delete(files, "client.wasm")
			case "changed":
				files["client.wasm"].Data[0] ^= 1
			case "duplicate":
				files["SHA256SUMS"].Data = append(files["SHA256SUMS"].Data, files["SHA256SUMS"].Data...)
			case "traversal":
				files["SHA256SUMS"].Data = []byte(strings.Repeat("0", 64) + "  ../client.wasm\n")
			case "incomplete":
				files["SHA256SUMS"].Data = nil
			case "oversized":
				files["client.wasm"].Data = make([]byte, (8<<20)+1)
			case "directory":
				files["client.wasm"].Mode = fs.ModeDir
			}
			assets, err := browserAssets(files)
			if name == "valid" {
				if err != nil || len(assets) != len(browserAssetNames)+3 {
					t.Fatalf("valid assets: %v", err)
				}
			} else if err == nil || assets != nil {
				t.Fatal("invalid assets admitted")
			}
		})
	}
}

type unreadBrowserBody struct{ t *testing.T }

func (b unreadBrowserBody) Read([]byte) (int, error) { b.t.Fatal("read request body"); return 0, nil }
func (unreadBrowserBody) Close() error               { return nil }

func TestMemberBrowserDelivery(t *testing.T) {
	assets, err := browserAssets(syntheticBrowserFiles())
	if err != nil {
		t.Fatal(err)
	}
	handler := browserHandler(assets, "127.0.0.1:12345")
	for _, tc := range []struct {
		name, method, path, host, origin, site string
		body                                   bool
		status                                 int
	}{
		{name: "page", path: "/", status: 200},
		{name: "worker", path: "/member-worker.mjs", status: 200},
		{name: "wasm", path: "/client.wasm", status: 200},
		{name: "head", method: "HEAD", path: "/", status: 200},
		{name: "head-wasm", method: "HEAD", path: "/client.wasm", status: 200},
		{name: "method", method: "POST", path: "/", status: 405},
		{name: "body", path: "/", body: true, status: 400},
		{name: "unknown-body", method: "POST", path: "/unknown", body: true, status: 400},
		{name: "host", path: "/", host: "untrusted.invalid", status: 421},
		{name: "origin", path: "/", origin: "https://untrusted.invalid", status: 403},
		{name: "cross-site", path: "/", site: "cross-site", status: 403},
		{name: "same-origin", path: "/", origin: "http://127.0.0.1:12345", site: "same-origin", status: 200},
		{name: "listing", path: "/assets/", status: 404},
		{name: "query", path: "/?synthetic=ignored", status: 404},
		{name: "empty-query", path: "/?", status: 404},
		{name: "encoded", path: "/%62rowser.mjs", status: 404},
		{name: "traversal", path: "/../client.wasm", status: 404},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, "http://127.0.0.1:12345"+tc.path, nil)
			if tc.host != "" {
				r.Host = tc.host
			}
			r.Header.Set("Origin", tc.origin)
			r.Header.Set("Sec-Fetch-Site", tc.site)
			if tc.body {
				r.Body = unreadBrowserBody{t}
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code != tc.status {
				t.Fatalf("status %d, want %d", w.Code, tc.status)
			}
			csp := browserPageCSP
			if tc.path == "/member-worker.mjs" && tc.status == 200 {
				csp = browserWorkerCSP
			}
			if w.Header().Get("Content-Security-Policy") != csp || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Content-Type-Options") != "nosniff" {
				t.Fatal("missing delivery policy")
			}
			if (tc.method == "HEAD" || tc.status != 200) && w.Body.Len() != 0 {
				t.Fatal("unexpected response body")
			}
			if w.Header().Get("Set-Cookie") != "" || w.Header().Get("Access-Control-Allow-Origin") != "" {
				t.Fatal("credentials or cross-origin access enabled")
			}
			if tc.status == 405 && w.Header().Get("Allow") != "GET, HEAD" {
				t.Fatal("missing method restriction")
			}
			if tc.body && (w.Header().Get("Connection") != "close" || !r.Close) {
				t.Fatal("unread body connection reused")
			}
			if tc.status == 200 {
				contentType := "text/html; charset=utf-8"
				switch tc.path {
				case "/client.wasm":
					contentType = "application/wasm"
				case "/member-worker.mjs":
					contentType = "text/javascript; charset=utf-8"
				}
				if w.Header().Get("Content-Type") != contentType {
					t.Fatal("incorrect asset media type")
				}
			}
		})
	}
}

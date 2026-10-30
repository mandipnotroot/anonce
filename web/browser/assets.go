// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

// Package browser supplies embedded pages for the identity and anonymous origins.
package browser

import (
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"

	"github.com/mandipnotroot/anonce/internal/browserhttp"
)

//go:embed *.html *.mjs *.css
var files embed.FS

type asset struct {
	data []byte
	kind string
}
type site struct {
	identity      bool
	cross, source string
	assets        map[string]asset
}

// New verifies every generated runtime file against its bounded local manifest.
// These hashes detect accidental build changes, not a malicious distributor.
func New(identity bool, cross, source string, member, review fs.FS) (http.Handler, error) {
	if !browserhttp.IsOrigin(cross) {
		return nil, errors.New("invalid browser peer origin")
	}
	s := &site{identity, cross, source, make(map[string]asset)}
	entries, err := files.ReadDir(".")
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if e.IsDir() || strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		data, err := files.ReadFile(e.Name())
		if err != nil {
			return nil, err
		}
		kind := mime.TypeByExtension(path.Ext(e.Name()))
		s.assets["/assets/"+e.Name()] = asset{data, kind}
	}
	load := func(prefix string, source fs.FS) error {
		if source == nil {
			return errors.New("runtime unavailable")
		}
		names := []string{"LICENSE", "LICENSE.anonce", "LICENSE.circl", "LICENSE.x-crypto", "LICENSE.x-sys", "PATENTS", "PATENTS.x-crypto", "PATENTS.x-sys", "client.wasm", "wasm_exec.js"}
		if prefix == "/runtime/member/" {
			names = append(names, "member-client.mjs", "member-worker.mjs", "protocol.mjs")
		}
		allowed := make(map[string]bool, len(names))
		for _, name := range names {
			allowed[name] = true
		}
		seen := make(map[string]bool, len(names))
		manifest, err := fs.ReadFile(source, "SHA256SUMS")
		if err != nil || len(manifest) > 8192 {
			return errors.New("runtime manifest unavailable")
		}
		count := 0
		for line := range strings.SplitSeq(string(manifest), "\n") {
			if line == "" {
				continue
			}
			parts := strings.Split(line, "  ")
			if len(parts) != 2 || len(parts[0]) != 64 || path.Base(parts[1]) != parts[1] || parts[1] == "." {
				return errors.New("invalid runtime manifest")
			}
			if !allowed[parts[1]] || seen[parts[1]] {
				return errors.New("unexpected runtime material")
			}
			seen[parts[1]] = true
			data, err := fs.ReadFile(source, parts[1])
			if err != nil || len(data) > 8<<20 {
				return errors.New("runtime unavailable")
			}
			digest := sha256.Sum256(data)
			if hex.EncodeToString(digest[:]) != parts[0] {
				return errors.New("runtime digest mismatch")
			}
			kind := mime.TypeByExtension(path.Ext(parts[1]))
			if path.Ext(parts[1]) == ".wasm" {
				kind = "application/wasm"
			}
			s.assets[prefix+parts[1]] = asset{data, kind}
			count++
		}
		if count != len(names) {
			return errors.New("incomplete runtime")
		}
		return nil
	}
	if err := load("/runtime/review/", review); err != nil {
		return nil, err
	}
	if identity {
		if member == nil {
			return nil, errors.New("member runtime unavailable")
		}
		if err := load("/runtime/member/", member); err != nil {
			return nil, err
		}
	}
	// Only startup-owned embedded bytes are rewritten. No request value enters
	// markup. Entry modules and CSS have full digest names and matching SRI.
	for _, name := range []string{"screen.css", "identity.mjs", "anonymous.mjs"} {
		original := "/assets/" + name
		a := s.assets[original]
		digest := sha256.Sum256(a.data)
		ext := path.Ext(name)
		hashed := "/assets/" + strings.TrimSuffix(name, ext) + "." + hex.EncodeToString(digest[:]) + ext
		s.assets[hashed] = a
		delete(s.assets, original)
		integrity := "sha256-" + base64.StdEncoding.EncodeToString(digest[:])
		for _, page := range []string{"/assets/identity.html", "/assets/anonymous.html"} {
			html := s.assets[page]
			html.data = bytesReplace(html.data, original, hashed, integrity)
			s.assets[page] = html
		}
	}
	return s, nil
}

func bytesReplace(raw []byte, original, hashed, integrity string) []byte {
	return []byte(strings.ReplaceAll(string(raw), `"`+original+`"`, `"`+hashed+`" integrity="`+integrity+`"`))
}

func (s *site) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" && r.Method != "HEAD" {
		browserhttp.Error(w, 405)
		return
	}
	if r.URL.Path == "/healthz" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if r.Method != "HEAD" {
			_, _ = w.Write([]byte("ok"))
		}
		return
	}
	if r.URL.Path == "/source" {
		w.Header().Set("Location", s.source)
		w.WriteHeader(302)
		return
	}
	name := r.URL.Path
	if name == "/" {
		if s.identity {
			name = "/assets/identity.html"
		} else {
			name = "/assets/anonymous.html"
		}
	}
	a, ok := s.assets[name]
	if !ok || strings.HasSuffix(name, ".html") && r.URL.Path != "/" {
		browserhttp.Error(w, 404)
		return
	}
	connect := "'self'"
	if s.identity {
		connect += " " + s.cross
	}
	csp := fmt.Sprintf("default-src 'none'; script-src 'self'; style-src 'self'; connect-src %s; worker-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'", connect)
	if strings.HasSuffix(name, "member-worker.mjs") || strings.HasSuffix(name, "review-worker.mjs") {
		csp = "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; connect-src 'self'; base-uri 'none'"
	}
	w.Header().Set("Content-Security-Policy", csp)
	w.Header().Set("Content-Type", a.kind)
	if r.Method != "HEAD" {
		_, _ = w.Write(a.data)
	}
}

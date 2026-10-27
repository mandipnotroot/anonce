// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

package web

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"testing/fstest"
)

func TestSite(t *testing.T) {
	t.Parallel()
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprint(enabled), func(t *testing.T) {
			t.Parallel()
			site, err := New(enabled)
			if err != nil {
				t.Fatal(err)
			}
			for _, path := range []string{"/", "/about", "/dev/styleguide"} {
				response, ok := site.Lookup(path)
				if ok != (path != "/dev/styleguide" || enabled) {
					t.Fatalf("incorrect availability for %s", path)
				}
				if !ok {
					continue
				}
				if response.ContentType != "text/html; charset=utf-8" {
					t.Fatal("incorrect page content type")
				}
				for _, required := range []string{"<!doctype html>", "Development only", `href="/source"`, `id="main"`, `<html lang="en">`} {
					if !strings.Contains(response.Body, required) {
						t.Errorf("%s missing %q", path, required)
					}
				}
				if strings.Contains(response.Body, `href="/dev/styleguide"`) != enabled {
					t.Fatal("style-guide navigation does not match configuration")
				}
				if !enabled && strings.Contains(response.Body, "Example feedback round") {
					t.Fatal("mock content leaked into public pages")
				}
			}
			for _, path := range []string{"/about/", "/dev/styleguide/", "/dev", "/admin", "/assets/shell.css", "/assets/../templates/shell.html", "/templates/shell.html", "/unknown"} {
				if _, ok := site.Lookup(path); ok {
					t.Errorf("unexpected route: %s", path)
				}
			}
		})
	}
}

func TestStylesheetIntegrity(t *testing.T) {
	t.Parallel()
	site, err := New(true)
	if err != nil {
		t.Fatal(err)
	}
	assets := 0
	for path, response := range site.responses {
		if response.ContentType != "text/css; charset=utf-8" {
			continue
		}
		assets++
		sum := sha256.Sum256([]byte(response.Body))
		if path != fmt.Sprintf("/assets/shell.%x.css", sum) {
			t.Fatal("asset path is not content-addressed")
		}
		integrity := "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
		for _, page := range []string{"/", "/about", "/dev/styleguide"} {
			html, _ := site.Lookup(page)
			if !strings.Contains(html.Body, `href="`+path+`"`) || !strings.Contains(html.Body, `integrity="`+integrity+`"`) {
				t.Fatal("stylesheet path or SRI does not match embedded bytes")
			}
		}
		if _, ok := site.Lookup(path + "/"); ok {
			t.Fatal("accepted a noncanonical asset route")
		}
	}
	if assets != 1 {
		t.Fatalf("stylesheet count = %d, want 1", assets)
	}
}

func TestSiteRejectsBrokenAssets(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name      string
		files     fstest.MapFS
		operation string
	}{
		{"missing CSS", fstest.MapFS{}, "read embedded stylesheet"},
		{"missing template", fstest.MapFS{"assets/shell.css": {Data: []byte("body {}")}}, "parse embedded shell"},
		{"invalid template", fstest.MapFS{"assets/shell.css": {Data: []byte("body {}")}, "templates/shell.html": {Data: []byte("{{")}}, "parse embedded shell"},
		{"missing shell", fstest.MapFS{"assets/shell.css": {Data: []byte("body {}")}, "templates/shell.html": {Data: []byte("no shell defined")}}, "render embedded shell"},
		{"incomplete template", fstest.MapFS{"assets/shell.css": {Data: []byte("body {}")}, "templates/shell.html": {Data: []byte(`{{define "shell"}}{{template "missing" .}}{{end}}`)}}, "render embedded shell"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			site, err := newSite(tc.files, true)
			if site != nil || err == nil || !strings.Contains(err.Error(), tc.operation) {
				t.Fatalf("expected contextual failure with no partial site, got %v", err)
			}
		})
	}
}

func FuzzLookup(f *testing.F) {
	sites := make(map[bool]*Site)
	for _, enabled := range []bool{false, true} {
		site, err := New(enabled)
		if err != nil {
			f.Fatal(err)
		}
		sites[enabled] = site
	}
	for _, path := range []string{"/", "/about", "/dev/styleguide", "/assets/../templates/shell.html", "/%2e%2e/", ""} {
		f.Add(path, false)
		f.Add(path, true)
	}
	f.Fuzz(func(t *testing.T, path string, enabled bool) {
		if len(path) > 8192 {
			return
		}
		response, ok := sites[enabled].Lookup(path)
		if !ok {
			if response != (Response{}) {
				t.Fatal("unknown route returned content")
			}
			return
		}
		known := path == "/" || path == "/about" || (enabled && path == "/dev/styleguide") || strings.HasPrefix(path, "/assets/shell.")
		if !known {
			t.Fatal("served an unexpected route")
		}
		if len(response.Body) == 0 || len(response.Body) > 32768 {
			t.Fatal("unbounded or empty shell response")
		}
	})
}

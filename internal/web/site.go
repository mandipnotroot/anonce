// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

// Package web pre-renders a read-only demonstration shell. It has no input forms,
// protocol operations, credentials, database access, or client-side execution.
package web

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"html/template"
	"io/fs"

	webassets "github.com/mandipnotroot/anonce/web"
)

// ContentSecurityPolicy allows only local styles in addition to inert HTML.
const ContentSecurityPolicy = "default-src 'none'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"

// Response is an immutable, pre-rendered public page or stylesheet.
type Response struct {
	Body        string
	ContentType string
}

// Site holds fixed public responses that are safe for concurrent reads.
type Site struct {
	responses map[string]Response
}

type pageData struct {
	Title        string
	Page         string
	StyleGuide   bool
	CSSPath      string
	CSSIntegrity string
}

// New renders all available pages at startup, failing rather than serving a
// partial page. Style-guide content is absent unless explicitly enabled.
func New(styleGuide bool) (*Site, error) {
	return newSite(webassets.Files, styleGuide)
}

func newSite(files fs.FS, styleGuide bool) (*Site, error) {
	css, err := fs.ReadFile(files, "assets/shell.css")
	if err != nil {
		return nil, fmt.Errorf("read embedded stylesheet: %w", err)
	}
	sum := sha256.Sum256(css)
	cssPath := fmt.Sprintf("/assets/shell.%x.css", sum)
	integrity := "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
	tmpl, err := template.ParseFS(files, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("parse embedded shell: %w", err)
	}
	site := &Site{responses: map[string]Response{
		cssPath: {Body: string(css), ContentType: "text/css; charset=utf-8"},
	}}
	pages := []struct{ path, name, title string }{
		{"/", "home", "Local demonstration"},
		{"/about", "about", "About anonce"},
	}
	if styleGuide {
		pages = append(pages, struct{ path, name, title string }{"/dev/styleguide", "styleguide", "Development style guide"})
	}
	for _, page := range pages {
		var body bytes.Buffer
		data := pageData{page.title, page.name, styleGuide, cssPath, integrity}
		if err := tmpl.ExecuteTemplate(&body, "shell", data); err != nil {
			return nil, fmt.Errorf("render embedded shell: %w", err)
		}
		site.responses[page.path] = Response{Body: body.String(), ContentType: "text/html; charset=utf-8"}
	}
	return site, nil
}

// Lookup matches exact paths only. It never reads directories or user-supplied files.
func (s *Site) Lookup(path string) (Response, bool) {
	response, ok := s.responses[path]
	return response, ok
}

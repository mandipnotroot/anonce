// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

package service

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/mandipnotroot/anonce/internal/web"
)

// NewHandler returns infrastructure, a submission-only read-only shell, and unavailable protocol routes.
// No handler reads request bodies, authenticates users, or accepts protocol data.
func NewHandler(cfg Config) (http.Handler, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	var site *web.Site
	if cfg.Role == Submission {
		var err error
		site, err = web.New(cfg.DevStyleGuide)
		if err != nil {
			return nil, fmt.Errorf("initialize web shell: %w", err)
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")

		// Prevent net/http from draining an unread body for connection reuse. Bytes
		// may already be buffered by the network stack; never parse or retain them.
		if r.Body != nil && r.Body != http.NoBody {
			w.Header().Set("Connection", "close")
			r.Close = true
		}
		if site != nil {
			if response, ok := site.Lookup(r.URL.Path); ok {
				if r.Method != http.MethodGet && r.Method != http.MethodHead {
					w.Header().Set("Allow", "GET, HEAD")
					writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "Use GET or HEAD.")
					return
				}
				w.Header().Set("Content-Security-Policy", web.ContentSecurityPolicy)
				w.Header().Set("Content-Type", response.ContentType)
				w.WriteHeader(http.StatusOK)
				if r.Method != http.MethodHead {
					_, _ = w.Write([]byte(response.Body))
				}
				return
			}
		}

		switch r.URL.Path {
		case "/healthz", "/readyz", "/api/v1/status", "/source":
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				w.Header().Set("Allow", "GET, HEAD")
				writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "Use GET or HEAD.")
				return
			}
		default:
			if unavailable(cfg.Role, r.URL.Path) {
				writeError(w, r, http.StatusNotImplemented, "not_implemented", "This protocol operation is not implemented. Do not send real data.")
			} else {
				writeError(w, r, http.StatusNotFound, "not_found", "No such endpoint.")
			}
			return
		}

		switch r.URL.Path {
		case "/healthz":
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			if r.Method != http.MethodHead {
				_, _ = w.Write([]byte("ok"))
			}
		case "/readyz":
			writeError(w, r, http.StatusServiceUnavailable, "not_ready", "Required storage, migrations, and protocol controls are not implemented.")
		case "/api/v1/status":
			writeJSON(w, r, http.StatusOK, struct {
				Version       string   `json:"version"`
				Capabilities  []string `json:"capabilities"`
				Demonstration bool     `json:"demonstration"`
			}{"development", []string{"liveness", "status", "source-discovery"}, true})
		case "/source":
			w.Header().Set("Location", cfg.SourceURL)
			w.WriteHeader(http.StatusFound)
		}
	}), nil
}

func unavailable(role Role, path string) bool {
	var prefixes []string
	switch role {
	case CA:
		prefixes = []string{"/api/v1/ca/certificate", "/api/v1/ca/revocations", "/api/v1/enrollments", "/admin"}
	case Issuer:
		prefixes = []string{"/api/v1/ca/certificate", "/api/v1/ca/revocations", "/api/v1/challenges", "/api/v1/issuances", "/admin"}
	case Submission:
		prefixes = []string{"/api/v1/rounds", "/api/v1/submissions", "/api/v1/receipts", "/api/v1/log", "/api/v1/reply-mailboxes"}
	}
	for _, prefix := range prefixes {
		if path == prefix || strings.HasPrefix(path, prefix+"/") {
			return true
		}
	}
	return false
}

func writeError(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	writeJSON(w, r, status, struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}{code, message})
}

func writeJSON(w http.ResponseWriter, r *http.Request, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if r.Method != http.MethodHead {
		// Only fixed, non-secret infrastructure values reach this encoder. A client
		// disconnect needs no request/error log and cannot change protocol state.
		_ = json.NewEncoder(w).Encode(value)
	}
}

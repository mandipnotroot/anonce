// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

package service

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/mandipnotroot/anonce/internal/web"
)

func TestWebServiceBoundary(t *testing.T) {
	t.Parallel()
	for _, role := range []Role{CA, Issuer, Submission} {
		for _, enabled := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/styleguide=%t", role, enabled), func(t *testing.T) {
				t.Parallel()
				cfg := testConfig(role)
				cfg.DevStyleGuide = enabled
				handler, err := NewHandler(cfg)
				if enabled && role != Submission {
					if err == nil {
						t.Fatal("identity service accepted development UI configuration")
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				for _, path := range []string{"/", "/about", "/dev/styleguide"} {
					want := http.StatusNotFound
					if role == Submission && (path != "/dev/styleguide" || enabled) {
						want = http.StatusOK
					}
					response := httptest.NewRecorder()
					handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
					if response.Code != want {
						t.Fatalf("%s status = %d, want %d", path, response.Code, want)
					}
				}
			})
		}
	}
}

func TestWebDelivery(t *testing.T) {
	t.Parallel()
	cfg := testConfig(Submission)
	cfg.DevStyleGuide = true
	handler, err := NewHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	home := httptest.NewRecorder()
	handler.ServeHTTP(home, httptest.NewRequest(http.MethodGet, "/", nil))
	match := regexp.MustCompile(`href="(/assets/shell\.[a-f0-9]{64}\.css)"`).FindStringSubmatch(home.Body.String())
	if len(match) != 2 {
		t.Fatal("home did not link an integrity-addressed stylesheet")
	}
	for _, path := range []string{"/", "/about", "/dev/styleguide", match[1]} {
		for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodOptions} {
			t.Run(method+path, func(t *testing.T) {
				t.Parallel()
				body := &unreadBody{}
				request := httptest.NewRequest(method, path+"?ignored=synthetic-sensitive-input", body)
				request.Header.Set("Cookie", "test=synthetic-sensitive-input")
				request.Header.Set("Authorization", "synthetic-sensitive-input")
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, request)
				if body.reads != 0 || !request.Close || response.Header().Get("Connection") != "close" {
					t.Fatal("web route read or allowed draining a request body")
				}
				if strings.Contains(response.Body.String(), "synthetic-sensitive-input") {
					t.Fatal("web route reflected request data")
				}
				if method == http.MethodGet || method == http.MethodHead {
					if response.Code != http.StatusOK || response.Header().Get("Content-Security-Policy") != web.ContentSecurityPolicy {
						t.Fatal("invalid shell delivery or CSP")
					}
					assertHeadersWithCSP(t, response.Header(), web.ContentSecurityPolicy)
					if method == http.MethodHead && response.Body.Len() != 0 {
						t.Fatal("HEAD returned content")
					}
					if method == http.MethodGet && response.Body.Len() == 0 {
						t.Fatal("GET returned no content")
					}
				} else {
					if response.Code != http.StatusMethodNotAllowed || response.Header().Get("Allow") != "GET, HEAD" {
						t.Fatal("web route accepted a write or omitted Allow")
					}
					assertHeaders(t, response.Header())
					assertErrorCode(t, response.Body.Bytes(), "method_not_allowed")
				}
			})
		}
	}
	for _, path := range []string{"/about/", "/dev/styleguide/", "/assets/shell.css", "/assets/../templates/shell.html", "/templates/shell.html", "/assets/shell." + strings.Repeat("0", 64) + ".css"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusNotFound {
			t.Fatalf("served noncanonical or private path %s", path)
		}
	}
}

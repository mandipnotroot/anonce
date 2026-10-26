// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

package service

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func handlerFor(t *testing.T, role Role) http.Handler {
	t.Helper()
	handler, err := NewHandler(testConfig(role))
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func TestInfrastructureRoutes(t *testing.T) {
	t.Parallel()
	for _, role := range []Role{CA, Issuer, Submission} {
		t.Run(string(role), func(t *testing.T) {
			t.Parallel()
			handler := handlerFor(t, role)
			for _, tc := range []struct {
				path   string
				status int
				code   string
			}{
				{"/healthz", http.StatusOK, ""},
				{"/readyz", http.StatusServiceUnavailable, "not_ready"},
				{"/api/v1/status", http.StatusOK, ""},
				{"/source", http.StatusFound, ""},
				{"/", http.StatusNotFound, "not_found"},
				{"/unknown", http.StatusNotFound, "not_found"},
				{"/healthz/", http.StatusNotFound, "not_found"},
			} {
				t.Run(tc.path, func(t *testing.T) {
					t.Parallel()
					response := httptest.NewRecorder()
					handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, tc.path, nil))
					if role == Submission && tc.path == "/" {
						if response.Code != http.StatusOK || !strings.HasPrefix(response.Header().Get("Content-Type"), "text/html;") {
							t.Fatal("submission process did not serve the read-only shell")
						}
						return
					}
					if response.Code != tc.status {
						t.Fatalf("status = %d, want %d", response.Code, tc.status)
					}
					assertHeaders(t, response.Header())
					if tc.code != "" {
						assertErrorCode(t, response.Body.Bytes(), tc.code)
					}
					switch tc.path {
					case "/healthz":
						if response.Body.String() != "ok" || response.Header().Get("Content-Type") != "text/plain; charset=utf-8" {
							t.Fatal("invalid liveness response")
						}
					case "/api/v1/status":
						var status struct {
							Version       string   `json:"version"`
							Capabilities  []string `json:"capabilities"`
							Demonstration bool     `json:"demonstration"`
						}
						decoder := json.NewDecoder(response.Body)
						decoder.DisallowUnknownFields()
						if err := decoder.Decode(&status); err != nil {
							t.Fatal(err)
						}
						if status.Version != "development" || !status.Demonstration || strings.Join(status.Capabilities, ",") != "liveness,status,source-discovery" {
							t.Fatalf("incorrect capability inventory: %+v", status)
						}
					case "/source":
						if response.Header().Get("Location") != testSource || response.Body.Len() != 0 {
							t.Fatal("source redirect did not preserve configured source URL")
						}
					}
				})
			}
		})
	}
}

func TestInfrastructureMethods(t *testing.T) {
	t.Parallel()
	handler := handlerFor(t, Submission)
	for _, path := range []string{"/healthz", "/readyz", "/api/v1/status", "/source"} {
		for _, method := range []string{http.MethodHead, http.MethodPost, http.MethodOptions, http.MethodDelete} {
			t.Run(method+path, func(t *testing.T) {
				t.Parallel()
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, httptest.NewRequest(method, path, nil))
				if method == http.MethodHead {
					if response.Body.Len() != 0 {
						t.Fatal("HEAD returned a body")
					}
				} else if response.Code != http.StatusMethodNotAllowed || response.Header().Get("Allow") != "GET, HEAD" {
					t.Fatal("unsupported method did not return 405 with Allow")
				}
			})
		}
	}
}

func TestUnavailableRoutesRespectServiceBoundary(t *testing.T) {
	t.Parallel()
	cases := []struct {
		path  string
		roles []Role
	}{
		{"/api/v1/ca/certificate", []Role{CA, Issuer}},
		{"/api/v1/ca/revocations", []Role{CA, Issuer}},
		{"/api/v1/enrollments", []Role{CA}},
		{"/api/v1/challenges", []Role{Issuer}},
		{"/api/v1/issuances", []Role{Issuer}},
		{"/admin/login", []Role{CA, Issuer}},
		{"/api/v1/rounds/test-round/bulletin", []Role{Submission}},
		{"/api/v1/submissions", []Role{Submission}},
		{"/api/v1/receipts/test-record", []Role{Submission}},
		{"/api/v1/log/checkpoint", []Role{Submission}},
		{"/api/v1/reply-mailboxes/test-mailbox", []Role{Submission}},
	}
	for _, role := range []Role{CA, Issuer, Submission} {
		for _, tc := range cases {
			t.Run(string(role)+tc.path, func(t *testing.T) {
				t.Parallel()
				owned := false
				for _, owner := range tc.roles {
					owned = owned || owner == role
				}
				for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodPut} {
					response := httptest.NewRecorder()
					handlerFor(t, role).ServeHTTP(response, httptest.NewRequest(method, tc.path, nil))
					status, code := http.StatusNotFound, "not_found"
					if owned {
						status, code = http.StatusNotImplemented, "not_implemented"
					}
					if response.Code != status {
						t.Fatalf("%s: status = %d, want %d", method, response.Code, status)
					}
					assertErrorCode(t, response.Body.Bytes(), code)
				}
			})
		}
	}
	response := httptest.NewRecorder()
	handlerFor(t, Submission).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/v1/submissions-extra", nil))
	if response.Code != http.StatusNotFound {
		t.Fatal("route matching crossed a path segment boundary")
	}
}

type unreadBody struct{ reads int }

func (b *unreadBody) Read([]byte) (int, error) {
	b.reads++
	return 0, io.EOF
}

func (*unreadBody) Close() error { return nil }

func TestInfrastructureDoesNotReadOrReflectRequestData(t *testing.T) {
	t.Parallel()
	for _, path := range []string{"/api/v1/submissions", "/api/v1/status", "/unknown"} {
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			body := &unreadBody{}
			request := httptest.NewRequest(http.MethodPost, path+"?value=synthetic-sensitive-input", body)
			request.Header.Set("Authorization", "synthetic-sensitive-input")
			request.Header.Set("Cookie", "test=synthetic-sensitive-input")
			request.Header.Set("X-Forwarded-For", "192.0.2.1")
			response := httptest.NewRecorder()
			handlerFor(t, Submission).ServeHTTP(response, request)
			if body.reads != 0 {
				t.Fatal("handler read request body")
			}
			if !request.Close || response.Header().Get("Connection") != "close" {
				t.Fatal("unread request body could be drained for connection reuse")
			}
			if strings.Contains(response.Body.String(), "synthetic-sensitive-input") || strings.Contains(response.Body.String(), "192.0.2.1") {
				t.Fatal("response reflected request data")
			}
			assertHeaders(t, response.Header())
		})
	}
}

func TestHandlerRejectsInvalidConfig(t *testing.T) {
	t.Parallel()
	if _, err := NewHandler(Config{}); err == nil {
		t.Fatal("accepted invalid configuration")
	}
}

func assertHeaders(t *testing.T, headers http.Header) {
	t.Helper()
	assertHeadersWithCSP(t, headers, "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
}

func assertHeadersWithCSP(t *testing.T, headers http.Header, csp string) {
	t.Helper()
	for key, want := range map[string]string{
		"Cache-Control":           "no-store",
		"Content-Security-Policy": csp,
		"X-Content-Type-Options":  "nosniff",
		"X-Frame-Options":         "DENY",
		"Referrer-Policy":         "no-referrer",
		"Permissions-Policy":      "camera=(), microphone=(), geolocation=()",
	} {
		if got := headers.Get(key); got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
	for _, key := range []string{"Set-Cookie", "Access-Control-Allow-Origin", "Strict-Transport-Security"} {
		if headers.Get(key) != "" {
			t.Errorf("unexpected %s header", key)
		}
	}
}

func assertErrorCode(t *testing.T, data []byte, code string) {
	t.Helper()
	var response struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&response); err != nil {
		t.Fatal(err)
	}
	if response.Code != code || response.Message == "" {
		t.Fatalf("incorrect error: %+v", response)
	}
}

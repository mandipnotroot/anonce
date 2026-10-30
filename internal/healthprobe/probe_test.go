// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

package healthprobe

import (
	"context"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func probeTrust(server *httptest.Server) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
}

func TestProbe(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, body string
		status     int
		valid      bool
	}{
		{"liveness", "ok", 200, true},
		{"empty", "", 200, false},
		{"truncated", "o", 200, false},
		{"extra", "ok\nx", 200, false},
		{"oversized", strings.Repeat("x", 4096), 200, false},
		{"unavailable", "ok\n", 503, false},
		{"redirect", "ok\n", 302, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.TLS == nil || r.Method != http.MethodGet || r.URL.Path != "/healthz" || r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" {
					t.Error("unexpected probe request")
				}
				w.Header().Set("Location", "/must-not-follow")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			if err := checkTLS(t.Context(), server.URL+"/healthz", server.Listener.Addr().String(), probeTrust(server)); (err == nil) != tc.valid {
				t.Fatalf("probe outcome: %v", err)
			}
		})
	}
}

func TestBrowserProbeTLS(t *testing.T) {
	t.Parallel()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()
	trust, address := probeTrust(server), server.Listener.Addr().String()
	if err := checkTLS(t.Context(), server.URL+"/healthz", address, trust); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, target string
		trust        []byte
	}{
		{"wrong hostname", "https://wrong.invalid/healthz", trust},
		{"invalid trust", server.URL + "/healthz", []byte("invalid trust")},
		{"malformed target", "://invalid", trust},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if checkTLS(t.Context(), tc.target, address, tc.trust) == nil {
				t.Fatal("invalid TLS probe admitted")
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := checkTLS(ctx, server.URL+"/healthz", address, trust); !errors.Is(err, context.Canceled) {
		t.Fatal("probe did not propagate cancellation")
	}
}

func TestProbeCancellationAndFailures(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for _, role := range []string{"identity", "submission"} {
		if err := Check(ctx, role); !errors.Is(err, context.Canceled) {
			t.Fatalf("fixed-role cancellation: %v", err)
		}
	}
	for _, role := range []string{"", "unknown", "https://identity.localhost:8443", "identity/healthz"} {
		if Check(t.Context(), role) == nil {
			t.Fatal("accepted unsupported probe target")
		}
	}
	for _, tc := range []struct {
		name    string
		handler http.HandlerFunc
	}{
		{"oversized headers", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Oversized", strings.Repeat("x", 2048))
			_, _ = w.Write([]byte("ok"))
		}},
		{"truncated body", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Length", "3")
			_, _ = w.Write([]byte("ok"))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewTLSServer(tc.handler)
			trust, address := probeTrust(server), server.Listener.Addr().String()
			if checkTLS(t.Context(), server.URL, address, trust) == nil {
				t.Error("invalid response admitted")
			}
			server.Close()
			if checkTLS(t.Context(), server.URL, address, trust) == nil {
				t.Fatal("unavailable server admitted")
			}
		})
	}
}

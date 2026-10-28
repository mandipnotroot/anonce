// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

package healthprobe

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

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
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != "/healthz" || r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" {
					t.Error("unexpected probe request")
				}
				w.Header().Set("Location", "/must-not-follow")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			if err := check(t.Context(), server.URL+"/healthz"); (err == nil) != tc.valid {
				t.Fatalf("probe outcome: %v", err)
			}
		})
	}
}

func TestProbeCancellationAndFailures(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for _, role := range []string{"server", "issuer", "ca"} {
		if err := Check(ctx, role); !errors.Is(err, context.Canceled) {
			t.Fatalf("fixed-role cancellation: %v", err)
		}
	}
	if err := check(ctx, "http://127.0.0.1:1/healthz"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation not propagated: %v", err)
	}
	for _, role := range []string{"", "unknown", "http://127.0.0.1:8080", "server/healthz"} {
		if Check(t.Context(), role) == nil {
			t.Fatal("accepted unsupported probe target")
		}
	}
	if check(t.Context(), "://invalid") == nil {
		t.Fatal("accepted malformed target")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Oversized", strings.Repeat("x", 2048))
		_, _ = w.Write([]byte("ok\n"))
	}))
	if check(t.Context(), server.URL) == nil {
		t.Error("accepted oversized headers")
	}
	server.Close()
	if check(t.Context(), server.URL) == nil {
		t.Fatal("accepted unavailable server")
	}
	truncated := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "3")
		_, _ = w.Write([]byte("ok"))
	}))
	defer truncated.Close()
	if check(t.Context(), truncated.URL) == nil {
		t.Fatal("accepted failed body read")
	}
}

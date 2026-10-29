// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

package service

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestBoundedTLSMetadata(t *testing.T) {
	seed := httptest.NewTLSServer(http.NotFoundHandler())
	certificate := seed.TLS.Certificates[0]
	roots := seed.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	seed.Close()
	listener := listenForTest(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		result <- serveTransport(ctx, listener, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.TLS == nil || !r.TLS.HandshakeComplete || r.TLS.Version < tls.VersionTLS13 {
				w.WriteHeader(403)
				return
			}
			w.WriteHeader(204)
		}), &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}})
	}()
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	response, err := client.Get("https://" + listener.Addr().String())
	if err != nil {
		t.Fatal("bounded TLS request failed")
	}
	_ = response.Body.Close()
	if response.StatusCode != 204 {
		t.Fatal("TLS metadata was hidden by connection limiting")
	}
	cancel()
	if awaitResult(t, result) != nil {
		t.Fatal("TLS service shutdown failed")
	}
}

// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

// Package healthprobe checks fixed browser-service TLS liveness, never readiness.
package healthprobe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"syscall"
	"time"
)

// Check accepts only fixed local service names. It uses no proxy or credentials.
func Check(ctx context.Context, role string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if role != "identity" && role != "submission" {
		return errors.New("unknown liveness probe service")
	}
	f, err := os.OpenFile("/state/local-root.crt", os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return errors.New("browser probe trust unavailable")
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 4096 {
		return errors.New("invalid browser probe trust file")
	}
	data, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(data) > 4096 {
		return errors.New("invalid browser probe trust")
	}
	name, port := "identity.localhost", "8443"
	if role == "submission" {
		name, port = "submit.localhost", "8444"
	}
	return checkTLS(ctx, "https://"+name+":"+port+"/healthz", "127.0.0.1:"+port, data)
}

func checkTLS(ctx context.Context, target, address string, trust []byte) error {
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(trust) {
		return errors.New("invalid browser probe trust")
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13},
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp", address)
		},
		DisableKeepAlives: true, ResponseHeaderTimeout: time.Second, MaxResponseHeaderBytes: 1024,
	}
	return checkTransport(ctx, target, transport)
}

func checkTransport(ctx context.Context, target string, transport *http.Transport) (err error) {
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		Timeout:   2 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return fmt.Errorf("prepare liveness probe: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("probe local liveness: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close liveness probe: %w", closeErr))
		}
	}()
	if resp.StatusCode != http.StatusOK {
		return errors.New("local liveness unavailable")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 3))
	if err != nil {
		return fmt.Errorf("read liveness probe: %w", err)
	}
	if string(body) != "ok" {
		return errors.New("invalid local liveness response")
	}
	return nil
}

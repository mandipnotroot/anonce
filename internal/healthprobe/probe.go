// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

// Package healthprobe checks local demonstration liveness, never readiness.
package healthprobe

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// Check accepts only fixed local service names. It uses no proxy or credentials.
func Check(ctx context.Context, role string) error {
	port := map[string]string{"server": "8080", "issuer": "8081", "ca": "8082"}[role]
	if port == "" {
		return errors.New("unknown liveness probe service")
	}
	return check(ctx, "http://127.0.0.1:"+port+"/healthz")
}

func check(ctx context.Context, target string) (err error) {
	transport := &http.Transport{
		DialContext:            (&net.Dialer{Timeout: time.Second}).DialContext,
		DisableKeepAlives:      true,
		ResponseHeaderTimeout:  time.Second,
		MaxResponseHeaderBytes: 1024,
	}
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

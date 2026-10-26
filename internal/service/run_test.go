// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

package service

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

func listenForTest(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return listener
}

func awaitResult(t *testing.T, result <-chan error) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("service did not stop within test deadline")
		return nil
	}
}

func TestServeLifecycle(t *testing.T) {
	t.Parallel()
	listener := listenForTest(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	result := make(chan error, 1)
	handler := handlerFor(t, Submission)
	go func() { result <- serve(ctx, listener, handler) }()
	transport := &http.Transport{}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	response, err := client.Get("http://" + listener.Addr().String() + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 1024))
	_ = response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK || string(body) != "ok" {
		t.Fatalf("liveness response: status = %d, body = %q, err = %v", response.StatusCode, body, err)
	}
	cancel()
	if err := awaitResult(t, result); err != nil {
		t.Fatal(err)
	}
	conn, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err == nil {
		_ = conn.Close()
		t.Fatal("listener still accepts connections after cancellation")
	}
}

func TestServePropagatesCancellationToRequests(t *testing.T) {
	t.Parallel()
	listener := listenForTest(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	started := make(chan struct{})
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	result := make(chan error, 1)
	go func() { result <- serve(ctx, listener, handler) }()
	conn, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not start")
	}
	cancel()
	if err := awaitResult(t, result); err != nil {
		t.Fatal(err)
	}
}

func TestServeRejectsBodyBeforeContinue(t *testing.T) {
	t.Parallel()
	listener := listenForTest(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	result := make(chan error, 1)
	handler := handlerFor(t, Submission)
	go func() { result <- serve(ctx, listener, handler) }()
	conn, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	// Do not send a body. The service must reject based on headers alone, without
	// soliciting the body with 100 Continue or waiting for the declared bytes.
	if _, err := io.WriteString(conn, "POST /api/v1/submissions HTTP/1.1\r\nHost: localhost\r\nExpect: 100-continue\r\nContent-Length: 1048576\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNotImplemented || !response.Close {
		t.Fatalf("status = %d, connection close = %v", response.StatusCode, response.Close)
	}
	cancel()
	if err := awaitResult(t, result); err != nil {
		t.Fatal(err)
	}
}

func TestServeListenerFailureClosesRequests(t *testing.T) {
	t.Parallel()
	listener := listenForTest(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	started, stopped := make(chan struct{}), make(chan struct{})
	handler := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
		close(stopped)
	})
	result := make(chan error, 1)
	go func() { result <- serve(ctx, listener, handler) }()
	conn, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not start")
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if err := awaitResult(t, result); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("listener failure returned %v", err)
	}
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("listener failure left a request running")
	}
	if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("listener failure left a connection open: %v", err)
	}
}

func TestServeClosesUnresponsiveRequests(t *testing.T) {
	t.Parallel()
	listener := listenForTest(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	started, release, stopped := make(chan struct{}), make(chan struct{}), make(chan struct{})
	defer close(release)
	handler := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		close(started)
		<-release // Deliberately ignore cancellation to exercise the forced close.
		close(stopped)
	})
	result := make(chan error, 1)
	go func() { result <- serve(ctx, listener, handler) }()
	conn, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(8 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not start")
	}
	cancel()
	if err := awaitResult(t, result); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("unresponsive request returned %v", err)
	}
	if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("connection was not force-closed: %v", err)
	}
	select {
	case <-stopped:
		t.Fatal("forced connection close unexpectedly terminated application code")
	default:
		// The test releases its handler on return. Shutdown cannot terminate an
		// arbitrary Go goroutine; future handlers must honor request cancellation.
	}
}

func TestRunFailures(t *testing.T) {
	t.Parallel()
	if err := Run(context.Background(), Config{}); err == nil {
		t.Fatal("accepted invalid configuration")
	}
	listener := listenForTest(t)
	cfg := testConfig(Submission)
	cfg.Listen = listener.Addr().String()
	if err := Run(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "listen for HTTP service") {
		t.Fatalf("occupied listener returned %v", err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if err := serve(context.Background(), listener, handlerFor(t, Submission)); err == nil {
		t.Fatal("closed listener did not fail")
	}
}

func TestServerBounds(t *testing.T) {
	t.Parallel()
	server := newServer(context.Background(), handlerFor(t, Submission))
	if server.ReadHeaderTimeout != 5*time.Second || server.ReadTimeout != 10*time.Second ||
		server.WriteTimeout != 10*time.Second || server.IdleTimeout != 30*time.Second ||
		server.MaxHeaderBytes != 8<<10 || !server.DisableGeneralOptionsHandler ||
		maxConnections != 64 || shutdownTimeout != 5*time.Second {
		t.Fatal("unexpected HTTP resource limits")
	}
	if server.ErrorLog == nil || server.ErrorLog.Writer() != io.Discard {
		t.Fatal("HTTP diagnostics could retain identifying request data")
	}
}

// pipeListener permits deterministic connection-limit tests without scheduler sleeps.
type pipeListener struct {
	net.Listener
	connections chan net.Conn
	done        chan struct{}
	once        sync.Once
}

func (l *pipeListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.connections:
		return conn, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *pipeListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func TestConnectionLimitAndClose(t *testing.T) {
	t.Parallel()
	underlying := &pipeListener{connections: make(chan net.Conn, 1), done: make(chan struct{})}
	listener := &limitedListener{Listener: underlying, slots: make(chan struct{}, 1), done: make(chan struct{})}
	t.Cleanup(func() { _ = listener.Close() })
	server, client := net.Pipe()
	defer func() { _ = client.Close() }()
	underlying.connections <- server
	conn, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	if len(listener.slots) != 1 {
		t.Fatal("accepted connection did not occupy its slot")
	}
	// Concurrent repeated closes must release the slot exactly once.
	var group sync.WaitGroup
	for range 8 {
		group.Go(func() {
			if err := conn.Close(); err != nil {
				t.Error(err)
			}
		})
	}
	group.Wait()
	if len(listener.slots) != 0 {
		t.Fatal("connection close did not release its slot")
	}

	server, client2 := net.Pipe()
	defer func() { _ = client2.Close() }()
	underlying.connections <- server
	conn, err = listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	result := make(chan error, 1)
	go func() {
		accepted, err := listener.Accept()
		if err == nil {
			_ = accepted.Close()
			err = fmt.Errorf("accepted connection beyond limit")
		}
		result <- err
	}()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if err := awaitResult(t, result); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("blocked Accept returned %v", err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := listener.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Accept after Close returned %v", err)
	}
}

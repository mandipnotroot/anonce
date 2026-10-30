// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

package service

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"
)

const (
	maxConnections  = 64
	shutdownTimeout = 5 * time.Second
)

// RunTLS serves a browser handler with a bounded, silent TLS lifecycle.
func RunTLS(ctx context.Context, cfg Config, handler http.Handler, certificate tls.Certificate) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	if handler == nil {
		return errors.New("browser handler unavailable")
	}
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", cfg.Listen)
	if err != nil {
		return errors.New("browser listener unavailable")
	}
	return serveTransport(ctx, listener, handler, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}})
}

func newServer(ctx context.Context, handler http.Handler) *http.Server {
	return &http.Server{
		Handler:                      handler,
		DisableGeneralOptionsHandler: true,
		ReadHeaderTimeout:            5 * time.Second,
		ReadTimeout:                  10 * time.Second,
		WriteTimeout:                 10 * time.Second,
		IdleTimeout:                  30 * time.Second,
		MaxHeaderBytes:               8 << 10,
		BaseContext:                  func(net.Listener) context.Context { return ctx },
		// net/http diagnostics can include peer addresses or panic values. Do not
		// retain those values, even on the submission service's error path.
		ErrorLog: log.New(io.Discard, "", 0),
	}
}

func serveTransport(ctx context.Context, listener net.Listener, handler http.Handler, tlsConfig *tls.Config) error {
	ctx, cancelRequests := context.WithCancel(ctx)
	defer cancelRequests()
	var bounded net.Listener = newLimitedListener(listener, maxConnections)
	if tlsConfig != nil {
		// TLS must be the outer listener. net/http recognizes the concrete
		// *tls.Conn to populate Request.TLS before the browser gate runs.
		bounded = tls.NewListener(bounded, tlsConfig)
	}
	server := newServer(ctx, handler)
	result := make(chan error, 1)
	go func() { result <- server.Serve(bounded) }()
	select {
	case err := <-result:
		return errors.Join(fmt.Errorf("serve HTTP: %w", err), server.Close())
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := server.Shutdown(shutdown); err != nil {
			closeErr := server.Close()
			serveErr := <-result
			if errors.Is(serveErr, http.ErrServerClosed) {
				serveErr = nil
			}
			return errors.Join(fmt.Errorf("shut down HTTP: %w", err), closeErr, serveErr)
		}
		if err := <-result; !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("stop HTTP listener: %w", err)
		}
		return nil
	}
}

// limitedListener bounds accepted connections, including slow header senders.
// Closing it wakes Accept even when every connection slot is occupied.
type limitedListener struct {
	net.Listener
	slots chan struct{}
	done  chan struct{}
	close func() error
}

func newLimitedListener(listener net.Listener, limit int) *limitedListener {
	l := &limitedListener{Listener: listener, slots: make(chan struct{}, limit), done: make(chan struct{})}
	l.close = sync.OnceValue(func() error {
		close(l.done)
		return listener.Close()
	})
	return l
}

func (l *limitedListener) Accept() (net.Conn, error) {
	select {
	case <-l.done:
		return nil, net.ErrClosed
	case l.slots <- struct{}{}:
	}
	conn, err := l.Listener.Accept()
	if err != nil {
		<-l.slots
		return nil, err
	}
	return &limitedConn{Conn: conn, close: sync.OnceValue(func() error {
		err := conn.Close()
		<-l.slots
		return err
	})}, nil
}

func (l *limitedListener) Close() error {
	return l.close()
}

type limitedConn struct {
	net.Conn
	close func() error
}

func (c *limitedConn) Close() error {
	return c.close()
}

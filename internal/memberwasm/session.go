// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

// Package memberwasm adapts shared member sessions to a separate development-only
// WASM interface. It provides no transport, persistence, or account binding.
package memberwasm

import (
	"context"
	"sync"

	"github.com/mandipnotroot/anonce/internal/client/keystore"
	"github.com/mandipnotroot/anonce/internal/client/membersession"
)

const memberBackupSize = 108

// host admits work before copying JS inputs or starting a goroutine. Cancellation
// covers the interval before the shared session begins its own operation too.
type host struct {
	mu      sync.Mutex
	session membersession.Session
	pending *operation
	closed  bool
	done    chan struct{}
}

type operation struct {
	ctx    context.Context
	cancel context.CancelFunc
}

func newHost() *host {
	return &host{done: make(chan struct{})}
}

func (h *host) begin() *operation {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed || h.pending != nil {
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	op := &operation{ctx: ctx, cancel: cancel}
	h.pending = op
	return op
}

func (h *host) accepted(op *operation) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return !h.closed && op.ctx.Err() == nil
}

// finish retains admission until input cleanup and promise settlement finish.
func (h *host) finish(op *operation) {
	h.mu.Lock()
	defer h.mu.Unlock()
	op.cancel()
	h.pending = nil
	if h.closed {
		close(h.done)
	}
}

func (h *host) lock() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.pending != nil {
		h.pending.cancel()
	}
	h.session.Lock()
}

func (h *host) close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return
	}
	h.closed = true
	if h.pending != nil {
		h.pending.cancel()
	} else {
		close(h.done)
	}
	h.session.Lock()
}

func validSizes(password, backup, expected int, unlock bool) bool {
	if password < 1 || password > keystore.MaxPasswordSize {
		return false
	}
	if unlock {
		return backup == memberBackupSize && expected == 32
	}
	return backup == 0 && expected == 0
}

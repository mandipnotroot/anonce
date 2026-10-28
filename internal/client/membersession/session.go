// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

// Package membersession owns a local member key for setup, restoration, encrypted
// backups, and fixed-profile certificate requests. It provides no browser bridge, persistence,
// account authentication, enrollment transport, or general-purpose signing.
package membersession

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"errors"
	"fmt"
	"sync"

	"github.com/mandipnotroot/anonce/internal/client/keystore"
	"github.com/mandipnotroot/anonce/internal/client/membercsr"
	"github.com/mandipnotroot/anonce/internal/client/memberkey"
)

var (
	// ErrState reports a locked request/export or an unavailable operation target.
	ErrState = errors.New("member session unavailable")
	// ErrKeyMismatch reports a validated backup for a different expected key.
	ErrKeyMismatch = errors.New("member session key mismatch")
	// ErrPasswordMismatch reports different bounded password and confirmation bytes.
	ErrPasswordMismatch = errors.New("member session password confirmation mismatch")
)

// Enrollment contains independently owned public, linkable enrollment material.
// It is not a certificate, identity claim, or enrollment authorization.
type Enrollment struct {
	PublicKey ed25519.PublicKey
	CSR       []byte
}

// Setup adds an encrypted member-key backup to the public enrollment material.
// Its buffers belong to the caller. Returning it does not establish persistence.
type Setup struct {
	Enrollment
	Backup []byte
}

// Session retains at most one private member key without exporting its bytes.
// Its zero value is locked and ready to use. Methods are safe for concurrent use;
// a Session must not be copied after first use. Call Lock when it is no longer
// needed. Callers must enforce lifetime, account binding, and cross-context lock.
type Session struct {
	mu      sync.Mutex
	key     ed25519.PrivateKey
	pending *operation
}

type operation struct {
	ctx    context.Context
	cancel context.CancelFunc
}

// Create prepares a fresh member key, profile-2 backup, and profile-1 request.
// It requires a locked, idle session and installs the key only after all work
// succeeds. The password remains caller-owned and must not change during the
// call; clear it afterwards. No password or backup is retained by the session.
func (s *Session) Create(ctx context.Context, password []byte) (*Setup, error) {
	if err := validatePassword(ctx, password); err != nil {
		return nil, fmt.Errorf("create member session: %w", err)
	}
	op, err := s.begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("create member session: %w", err)
	}
	defer s.end(op)
	key, err := memberkey.Generate(op.ctx)
	if err != nil {
		return nil, fmt.Errorf("create member session: %w", err)
	}
	backup, err := memberkey.Seal(op.ctx, password, key)
	if err != nil {
		clear(key)
		return nil, fmt.Errorf("create member session: %w", err)
	}
	enrollment, err := s.install(op, key)
	if err != nil {
		clear(backup)
		return nil, fmt.Errorf("create member session: %w", err)
	}
	return &Setup{Enrollment: *enrollment, Backup: backup}, nil
}

// CreateConfirmed requires two matching passwords before creating a session.
// Both inputs are caller-owned opaque bytes, subject to Create's bounds and
// ownership rules. Confirmation does not establish password strength or storage.
func (s *Session) CreateConfirmed(ctx context.Context, password, confirmation []byte) (*Setup, error) {
	if err := confirmPassword(ctx, password, confirmation); err != nil {
		return nil, fmt.Errorf("confirm member setup: %w", err)
	}
	return s.Create(ctx, password)
}

// Unlock restores a member backup only if its validated public key matches the
// required, independently trusted 32-byte expected key. All inputs remain owned
// by the caller and must not change during the call. Failed restoration leaves
// a locked, idle session locked, with no public output or fallback to creation.
// An already unlocked/busy session rejects restoration without replacing its key.
func (s *Session) Unlock(ctx context.Context, password, backup []byte, expected ed25519.PublicKey) (*Enrollment, error) {
	if err := validatePassword(ctx, password); err != nil {
		return nil, fmt.Errorf("unlock member session: %w", err)
	}
	if len(expected) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("unlock member session: %w", keystore.ErrInvalidInput)
	}
	op, err := s.begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("unlock member session: %w", err)
	}
	defer s.end(op)
	key, err := memberkey.Open(op.ctx, password, backup)
	if err != nil {
		return nil, fmt.Errorf("unlock member session: %w", err)
	}
	if subtle.ConstantTimeCompare(key[ed25519.SeedSize:], expected) != 1 {
		clear(key)
		return nil, fmt.Errorf("unlock member session: %w", ErrKeyMismatch)
	}
	enrollment, err := s.install(op, key)
	if err != nil {
		return nil, fmt.Errorf("unlock member session: %w", err)
	}
	return enrollment, nil
}

// Request prepares only the fixed identity-free CSR for the unlocked key. Lock
// and Request are serialized, so Lock waits for an active bounded signing call.
// Public results already returned to callers are not revoked or cleared by Lock.
func (s *Session) Request(ctx context.Context) (*Enrollment, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("request member session: %w", err)
	}
	if len(s.key) == 0 {
		return nil, fmt.Errorf("request member session: %w", ErrState)
	}
	enrollment, err := prepare(ctx, s.key)
	if err != nil {
		return nil, fmt.Errorf("request member session: %w", err)
	}
	return enrollment, nil
}

// Backup encrypts the unlocked member key under password using the unchanged
// backup profile. It does not rotate the key, retain the password, persist output,
// or invalidate old backups. The password remains caller-owned and must not change
// during the call. Only one setup, restoration, or export may be pending.
// Lock cancels export without waiting for derivation and clears the retained key;
// the bounded temporary key copy is cleared before this call releases admission.
func (s *Session) Backup(ctx context.Context, password []byte) ([]byte, error) {
	if err := validatePassword(ctx, password); err != nil {
		return nil, fmt.Errorf("backup member session: %w", err)
	}
	op, key, err := s.beginBackup(ctx)
	if err != nil {
		return nil, fmt.Errorf("backup member session: %w", err)
	}
	defer s.end(op)
	defer clear(key)
	backup, err := memberkey.Seal(op.ctx, password, key)
	if err != nil {
		return nil, fmt.Errorf("backup member session: %w", err)
	}
	backup, err = s.publishBackup(op, backup)
	if err != nil {
		return nil, fmt.Errorf("backup member session: %w", err)
	}
	return backup, nil
}

// BackupConfirmed requires matching replacement passwords before snapshotting
// the unlocked key or deriving a backup key. Backup's other rules are unchanged;
// a failed confirmation leaves the retained member key and old backups unchanged.
func (s *Session) BackupConfirmed(ctx context.Context, password, confirmation []byte) ([]byte, error) {
	if err := confirmPassword(ctx, password, confirmation); err != nil {
		return nil, fmt.Errorf("confirm member backup: %w", err)
	}
	return s.Backup(ctx, password)
}

func confirmPassword(ctx context.Context, password, confirmation []byte) error {
	if err := validatePassword(ctx, password); err != nil {
		return err
	}
	if err := validatePassword(ctx, confirmation); err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(password, confirmation) != 1 {
		return ErrPasswordMismatch
	}
	return nil
}

func (s *Session) publishBackup(op *operation, backup []byte) ([]byte, error) {
	// Serialize publication with Lock, just like final key installation. Lock
	// after this boundary cannot retract ciphertext already returned to a caller.
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := op.ctx.Err(); err != nil {
		clear(backup)
		return nil, err
	}
	return backup, nil
}

func (s *Session) beginBackup(ctx context.Context) (*operation, ed25519.PrivateKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if s.pending != nil || len(s.key) == 0 {
		return nil, nil, ErrState
	}
	ctx, cancel := context.WithCancel(ctx)
	op := &operation{ctx: ctx, cancel: cancel}
	s.pending = op
	return op, bytes.Clone(s.key), nil
}

// Lock clears the session's private buffer and cancels pending work. It is
// idempotent and does not wait for Argon2id to finish. Until the cancelled call
// returns, new setup/restoration/export attempts still fail with ErrState. Runtime and
// library copies prevent a complete-erasure guarantee.
func (s *Session) Lock() {
	s.mu.Lock()
	defer s.mu.Unlock()
	clear(s.key)
	s.key = nil
	if s.pending != nil {
		s.pending.cancel()
	}
}

func validatePassword(ctx context.Context, password []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(password) == 0 || len(password) > keystore.MaxPasswordSize {
		return keystore.ErrInvalidInput
	}
	return nil
}

func (s *Session) begin(ctx context.Context) (*operation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s.pending != nil || len(s.key) != 0 {
		return nil, ErrState
	}
	ctx, cancel := context.WithCancel(ctx)
	op := &operation{ctx: ctx, cancel: cancel}
	s.pending = op
	return op, nil
}

func (s *Session) end(op *operation) {
	s.mu.Lock()
	defer s.mu.Unlock()
	op.cancel()
	s.pending = nil
}

// install takes ownership of key, clearing it unless installation succeeds. The
// pending operation remains admitted until its caller has finished all cleanup.
func (s *Session) install(op *operation, key ed25519.PrivateKey) (*Enrollment, error) {
	defer func() { clear(key) }()
	enrollment, err := prepare(op.ctx, key)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := op.ctx.Err(); err != nil {
		clear(enrollment.PublicKey)
		clear(enrollment.CSR)
		return nil, err
	}
	s.key = key
	key = nil // Ownership moves to the session under the same lock as cancellation.
	return enrollment, nil
}

func prepare(ctx context.Context, key ed25519.PrivateKey) (*Enrollment, error) {
	csr, err := membercsr.Create(ctx, key)
	if err != nil {
		return nil, err
	}
	public := ed25519.PublicKey(bytes.Clone(key[ed25519.SeedSize:]))
	return &Enrollment{PublicKey: public, CSR: csr}, nil
}

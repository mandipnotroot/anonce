// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

// Package memberbackup provides development-only identity-side encrypted member
// backup persistence with trusted-owner or existing-session access. It performs no
// authentication ceremony, decryption, enrollment, or key recovery. See
// docs/database.md for the internal storage and retention contract.
package memberbackup

import (
	"context"
	"crypto/ed25519"
	"errors"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/mandipnotroot/anonce/internal/client/keystore"
	"github.com/mandipnotroot/anonce/internal/identity/accounts"
)

const (
	BackupSize       = 108
	operationTimeout = 5 * time.Second
)

var (
	ErrInvalidInput = errors.New("invalid member backup input")
	ErrUnavailable  = errors.New("member backup unavailable")
	ErrConflict     = errors.New("member backup revision or binding conflict")
)

// Record holds caller-owned encrypted/public material. A nil Backup denotes a
// deleted slot, not an absent slot. PublicKey and Revision survive deletion.
type Record struct {
	PublicKey [ed25519.PublicKeySize]byte
	Revision  int64
	Backup    []byte
}

// Store borrows an identity runtime pool without query/parameter tracing. Callers
// must preserve the checked role/database on every connection. It is concurrency
// safe; its zero value fails closed. Owner-ID methods require a trusted
// authenticated owner, not an unchecked request parameter. ForSession methods
// derive the owner from a live session. Recent authentication and rate limits
// are host responsibilities. There is no HTTP integration.
type Store struct{ pool *pgxpool.Pool }

func New(ctx context.Context, pool *pgxpool.Pool) (*Store, error) {
	if pool == nil {
		return nil, ErrInvalidInput
	}
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	if _, err := accounts.New(ctx, pool); err != nil {
		return nil, failure(ctx, "check member backup storage boundary")
	}
	var exists bool
	if err := pool.QueryRow(ctx, "SELECT to_regclass('anonce.member_key_backups') IS NOT NULL").Scan(&exists); err != nil || !exists {
		return nil, failure(ctx, "check member backup table")
	}
	return &Store{pool: pool}, nil
}

// Get returns one active owner's current slot, including a deletion tombstone.
// Missing slots and missing/disabled accounts share ErrUnavailable. Returned
// metadata is not an independent trust anchor or proof of backup freshness.
func (s *Store) Get(ctx context.Context, owner accounts.ID) (Record, error) {
	if owner == (accounts.ID{}) {
		return Record{}, ErrInvalidInput
	}
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	if err := s.ready(ctx); err != nil {
		return Record{}, err
	}
	return read(ctx, s.pool, owner)
}

type rowQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func read(ctx context.Context, query rowQuerier, owner accounts.ID) (Record, error) {
	var record Record
	var public []byte
	err := query.QueryRow(ctx, `SELECT b.public_key, b.revision, b.backup
        FROM anonce.member_key_backups b JOIN anonce.accounts a ON a.id = b.account_id
        WHERE b.account_id = $1 AND a.state = 'active'`, owner[:]).Scan(&public, &record.Revision, &record.Backup)
	if errors.Is(err, pgx.ErrNoRows) {
		return Record{}, ErrUnavailable
	}
	if err != nil || len(public) != len(record.PublicKey) || record.Revision < 1 ||
		record.Backup != nil && !validBackup(record.Backup) {
		return Record{}, failure(ctx, "read member backup")
	}
	copy(record.PublicKey[:], public)
	return record, nil
}

// Put creates at expected revision zero, or replaces/restores at the current
// positive revision with the same public key. It admits only the public envelope,
// never authenticates the ciphertext/key binding. Inputs remain caller-owned and
// must not change until return. A commit error returns no revision; do not blindly
// retry because the write may have committed. Read current state first.
func (s *Store) Put(ctx context.Context, owner accounts.ID, expected int64, public, backup []byte) (int64, error) {
	if owner == (accounts.ID{}) || !validRevision(expected) || len(public) != ed25519.PublicKeySize || !validBackup(backup) {
		return 0, ErrInvalidInput
	}
	return s.write(ctx, owner, expected, public, backup, false)
}

// Delete clears ciphertext at the matching live revision and returns the new
// tombstone revision. It is not secure erasure, account deletion, or key revocation.
// A stale revision or an already deleted/absent slot returns ErrConflict.
func (s *Store) Delete(ctx context.Context, owner accounts.ID, expected int64) (int64, error) {
	if owner == (accounts.ID{}) || expected == 0 || !validRevision(expected) {
		return 0, ErrInvalidInput
	}
	return s.write(ctx, owner, expected, nil, nil, true)
}

func (s *Store) write(ctx context.Context, owner accounts.ID, expected int64, public, backup []byte, deleting bool) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	if err := s.ready(ctx); err != nil {
		return 0, err
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return 0, failure(ctx, "begin member backup write")
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := lockOwner(ctx, tx, owner); err != nil {
		return 0, err
	}
	revision, err := writeSlot(ctx, tx, owner, expected, public, backup, deleting)
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, failure(ctx, "commit member backup write")
	}
	return revision, nil
}

func lockOwner(ctx context.Context, tx pgx.Tx, owner accounts.ID) error {
	// Match account/session lock ordering. Recheck state after any lock wait,
	// before executing a separate statement with a fresh Read Committed snapshot.
	var state string
	err := tx.QueryRow(ctx, "SELECT state FROM anonce.accounts WHERE id = $1 FOR UPDATE", owner[:]).Scan(&state)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && state != "active" {
		return ErrUnavailable
	}
	if err != nil {
		return failure(ctx, "lock member backup account")
	}
	return nil
}

func writeSlot(ctx context.Context, tx pgx.Tx, owner accounts.ID, expected int64, public, backup []byte, deleting bool) (int64, error) {
	var revision int64
	var err error
	switch {
	case deleting:
		err = tx.QueryRow(ctx, `UPDATE anonce.member_key_backups SET backup = NULL, revision = revision + 1
            WHERE account_id = $1 AND revision = $2 AND backup IS NOT NULL RETURNING revision`, owner[:], expected).Scan(&revision)
	case expected == 0:
		err = tx.QueryRow(ctx, `INSERT INTO anonce.member_key_backups(account_id, public_key, revision, backup)
            VALUES ($1, $2, 1, $3) ON CONFLICT (account_id) DO NOTHING RETURNING revision`, owner[:], public, backup).Scan(&revision)
	default:
		err = tx.QueryRow(ctx, `UPDATE anonce.member_key_backups SET backup = $4, revision = revision + 1
            WHERE account_id = $1 AND revision = $2 AND public_key = $3 RETURNING revision`, owner[:], expected, public, backup).Scan(&revision)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrConflict
	}
	if err != nil {
		return 0, failure(ctx, "write member backup")
	}
	return revision, nil
}

func validRevision(revision int64) bool { return revision >= 0 && revision < math.MaxInt64 }

func validBackup(backup []byte) bool {
	return len(backup) == BackupSize && keystore.ValidateEnvelope(keystore.MemberKey, backup) == nil
}

func (s *Store) ready(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s == nil || s.pool == nil {
		return ErrUnavailable
	}
	return nil
}

// Database diagnostics can contain row data or credentials. Preserve only local
// operation context and cancellation, without reflecting driver-controlled text.
func failure(ctx context.Context, operation string) error {
	return errors.Join(errors.New(operation), ctx.Err())
}

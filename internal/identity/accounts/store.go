// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

// Package accounts provides identity-side account and session persistence, not
// authentication, enrollment, membership authorization, or browser vault access.
package accounts

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	TokenSize        = 32
	MaxLifetime      = 12 * time.Hour
	operationTimeout = 5 * time.Second
)

var (
	ErrInvalidInput = errors.New("invalid account input")
	ErrUnavailable  = errors.New("account or session unavailable")
)

// ID is a random, identity-side account reference, never a membership or spend ID.
type ID [16]byte

type Session struct {
	AccountID ID
	CreatedAt time.Time
	ExpiresAt time.Time
}

// Store borrows its pool. The caller must keep its connections on the checked
// database/role and must not install query/parameter logging. A Store is safe for
// concurrent use. Its zero value fails closed.
type Store struct{ pool *pgxpool.Pool }

// New admits only the identity boundary and unprivileged anonce_runtime login.
// It neither opens nor owns connections. HTTP services do not yet use this API.
func New(ctx context.Context, pool *pgxpool.Pool) (*Store, error) {
	if pool == nil {
		return nil, ErrInvalidInput
	}
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	var valid bool
	err := pool.QueryRow(ctx, `SELECT current_database() = 'identity'
        AND current_user = 'anonce_runtime' AND session_user = 'anonce_runtime'
        AND NOT (rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls)
        AND NOT pg_has_role(current_user, 'anonce_owner', 'MEMBER')
        AND to_regclass('anonce.accounts') IS NOT NULL
        AND to_regclass('anonce.account_sessions') IS NOT NULL
        AND (SELECT count(*) = 1 AND bool_and(singleton AND service = 'identity')
             FROM anonce.storage_boundary)
        FROM pg_roles WHERE rolname = current_user`).Scan(&valid)
	if err != nil || !valid {
		return nil, failure(ctx, "check account storage boundary")
	}
	return &Store{pool: pool}, nil
}

// Create creates an unbound account. Only a future trusted registration flow may
// call it; creation grants no membership, credential, role, or eligibility.
func (s *Store) Create(ctx context.Context) (ID, error) {
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	if err := s.ready(ctx); err != nil {
		return ID{}, err
	}
	var id ID
	rand.Read(id[:])
	_, err := s.pool.Exec(ctx, "INSERT INTO anonce.accounts(id) VALUES ($1)", id[:])
	if err != nil {
		return ID{}, failure(ctx, "create account")
	}
	return id, nil
}

// StartSession must be called only after independently verified authentication.
// It returns a newly allocated opaque bearer secret exactly once; callers must
// clear it after protected delivery. Only its SHA-256 digest reaches PostgreSQL.
// No caller-selected token, idle refresh, or privilege assertion is accepted.
func (s *Store) StartSession(ctx context.Context, id ID, lifetime time.Duration) ([]byte, Session, error) {
	if id == (ID{}) || lifetime < time.Second || lifetime > MaxLifetime || lifetime%time.Second != 0 {
		return nil, Session{}, ErrInvalidInput
	}
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	if err := s.ready(ctx); err != nil {
		return nil, Session{}, err
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, Session{}, failure(ctx, "begin account session")
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := lockAccount(ctx, tx, id, true); err != nil {
		return nil, Session{}, err
	}
	token := make([]byte, TokenSize)
	rand.Read(token)
	digest, _ := tokenDigest(token)
	session := Session{AccountID: id}
	err = tx.QueryRow(ctx, `INSERT INTO anonce.account_sessions(token_digest, account_id, expires_at)
        VALUES ($1, $2, statement_timestamp() + $3 * interval '1 second')
        RETURNING created_at, expires_at`, digest[:], id[:], int64(lifetime/time.Second)).Scan(&session.CreatedAt, &session.ExpiresAt)
	if err == nil {
		err = tx.Commit(ctx)
	}
	if err != nil {
		clear(token)
		return nil, Session{}, failure(ctx, "create account session")
	}
	return token, session, nil
}

// Resolve checks current account status and absolute expiry on every lookup.
// A successful lookup is not authorization for membership or sensitive actions.
func (s *Store) Resolve(ctx context.Context, token []byte) (Session, error) {
	digest, ok := tokenDigest(token)
	if !ok {
		return Session{}, ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	if err := s.ready(ctx); err != nil {
		return Session{}, err
	}
	var session Session
	var id []byte
	err := s.pool.QueryRow(ctx, `SELECT s.account_id, s.created_at, s.expires_at
        FROM anonce.account_sessions s JOIN anonce.accounts a ON a.id = s.account_id
        WHERE s.token_digest = $1 AND a.state = 'active' AND s.expires_at > statement_timestamp()`, digest[:]).Scan(&id, &session.CreatedAt, &session.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Session{}, ErrUnavailable
	}
	if err != nil || len(id) != len(session.AccountID) {
		return Session{}, failure(ctx, "resolve account session")
	}
	copy(session.AccountID[:], id)
	return session, nil
}

// Revoke is idempotent for a well-sized unknown, expired, or already revoked token.
func (s *Store) Revoke(ctx context.Context, token []byte) error {
	digest, ok := tokenDigest(token)
	if !ok {
		return ErrInvalidInput
	}
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	if err := s.ready(ctx); err != nil {
		return err
	}
	if _, err := s.pool.Exec(ctx, "DELETE FROM anonce.account_sessions WHERE token_digest = $1", digest[:]); err != nil {
		return failure(ctx, "revoke account session")
	}
	return nil
}

// RevokeAll removes sessions serialized before this operation. A separately
// authenticated StartSession ordered after it may create a new session.
func (s *Store) RevokeAll(ctx context.Context, id ID) error { return s.invalidate(ctx, id, false) }

// Disable atomically disables the account and removes its sessions. There is no
// re-enable API. It is idempotent, does not delete the account, and changes no
// membership, quotas, device keys, or anonymous state. Caller authorization is
// required; this persistence layer is not an administrative endpoint.
func (s *Store) Disable(ctx context.Context, id ID) error { return s.invalidate(ctx, id, true) }

func (s *Store) invalidate(ctx context.Context, id ID, disable bool) error {
	if id == (ID{}) {
		return ErrInvalidInput
	}
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	if err := s.ready(ctx); err != nil {
		return err
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return failure(ctx, "begin session invalidation")
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := lockAccount(ctx, tx, id, false); err != nil {
		return err
	}
	if disable {
		if _, err := tx.Exec(ctx, `UPDATE anonce.accounts SET state = 'disabled',
            disabled_at = COALESCE(disabled_at, statement_timestamp()) WHERE id = $1`, id[:]); err != nil {
			return failure(ctx, "disable account")
		}
	}
	if _, err := tx.Exec(ctx, "DELETE FROM anonce.account_sessions WHERE account_id = $1", id[:]); err != nil {
		return failure(ctx, "invalidate account sessions")
	}
	if err := tx.Commit(ctx); err != nil {
		return failure(ctx, "commit session invalidation")
	}
	return nil
}

// PurgeExpired deletes at most limit expired references, with no authentication
// effect on still-live sessions. Hosts must schedule cleanup and set retention.
func (s *Store) PurgeExpired(ctx context.Context, limit int) (int64, error) {
	if limit < 1 || limit > 1000 {
		return 0, ErrInvalidInput
	}
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	if err := s.ready(ctx); err != nil {
		return 0, err
	}
	result, err := s.pool.Exec(ctx, `DELETE FROM anonce.account_sessions WHERE token_digest IN
        (SELECT token_digest FROM anonce.account_sessions WHERE expires_at <= statement_timestamp()
         ORDER BY expires_at, token_digest LIMIT $1)`, limit)
	if err != nil {
		return 0, failure(ctx, "purge expired account sessions")
	}
	return result.RowsAffected(), nil
}

func lockAccount(ctx context.Context, tx pgx.Tx, id ID, active bool) error {
	var state string
	err := tx.QueryRow(ctx, "SELECT state FROM anonce.accounts WHERE id = $1 FOR UPDATE", id[:]).Scan(&state)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && active && state != "active" {
		return ErrUnavailable
	}
	if err != nil {
		return failure(ctx, "lock account")
	}
	return nil
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

func tokenDigest(token []byte) ([sha256.Size]byte, bool) {
	if len(token) != TokenSize {
		return [sha256.Size]byte{}, false
	}
	return sha256.Sum256(token), true
}

// SQL errors may contain row data or connection credentials. Preserve operation
// context and cancellation, never driver diagnostics or caller-controlled text.
func failure(ctx context.Context, operation string) error {
	return errors.Join(errors.New(operation), ctx.Err())
}

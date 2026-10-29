// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

package memberbackup

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/mandipnotroot/anonce/internal/identity/accounts"
)

// RecentAuthenticationWindow is the fixed development admission window for
// session-scoped backup mutations, not a product authentication assurance claim.
const RecentAuthenticationWindow = accounts.RecentAuthenticationWindow

// ErrReauthenticationRequired denotes a live session too old for backup mutation.
var ErrReauthenticationRequired = errors.New("member backup requires recent authentication")

// GetForSession reads only the live session owner's slot. It accepts no owner
// override. Invalid, missing, expired, revoked, or disabled sessions and missing
// slots share ErrUnavailable. Tokens remain caller-owned; clear after use.
func (s *Store) GetForSession(ctx context.Context, token []byte) (Record, error) {
	var record Record
	err := s.withSession(ctx, token, false, func(ctx context.Context, tx pgx.Tx, owner accounts.ID) error {
		var err error
		record, err = read(ctx, tx, owner)
		return err
	})
	if err != nil {
		return Record{}, err
	}
	return record, nil
}

// PutForSession applies Put's revision/binding rules to the live session owner.
// The session must have been created by verified authentication or rotated after
// verified reauthentication within RecentAuthenticationWindow.
// Inputs remain caller-owned and must not change until return. Commit errors
// return no revision and must not be retried without reading current state.
func (s *Store) PutForSession(ctx context.Context, token []byte, expected int64, public, backup []byte) (int64, error) {
	if !validRevision(expected) || len(public) != ed25519.PublicKeySize || !validBackup(backup) {
		return 0, ErrInvalidInput
	}
	var revision int64
	err := s.withSession(ctx, token, true, func(ctx context.Context, tx pgx.Tx, owner accounts.ID) error {
		var err error
		revision, err = writeSlot(ctx, tx, owner, expected, public, backup, false)
		return err
	})
	if err != nil {
		return 0, err
	}
	return revision, nil
}

// DeleteForSession applies Delete's tombstone rules to the live session owner.
// The same recent-authentication and uncertain-commit rules apply.
func (s *Store) DeleteForSession(ctx context.Context, token []byte, expected int64) (int64, error) {
	if expected == 0 || !validRevision(expected) {
		return 0, ErrInvalidInput
	}
	var revision int64
	err := s.withSession(ctx, token, true, func(ctx context.Context, tx pgx.Tx, owner accounts.ID) error {
		var err error
		revision, err = writeSlot(ctx, tx, owner, expected, nil, nil, true)
		return err
	})
	if err != nil {
		return 0, err
	}
	return revision, nil
}

func (s *Store) withSession(ctx context.Context, token []byte, requireRecent bool, apply func(context.Context, pgx.Tx, accounts.ID) error) error {
	if len(token) != accounts.TokenSize {
		return ErrUnavailable
	}
	digest := sha256.Sum256(token)
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	if err := s.ready(ctx); err != nil {
		return err
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return failure(ctx, "begin session member backup access")
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// Discover the owner without trusting it as authorization. Lock the account
	// first, like StartSession, RotateSession, revocation, disable, and owner-ID writes.
	var id []byte
	err = tx.QueryRow(ctx, "SELECT account_id FROM anonce.account_sessions WHERE token_digest = $1", digest[:]).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrUnavailable
	}
	var owner accounts.ID
	if err != nil || len(id) != len(owner) {
		return failure(ctx, "find member backup session owner")
	}
	copy(owner[:], id)
	if err := lockOwner(ctx, tx, owner); err != nil {
		return err
	}
	// A fresh statement after the lock wait observes committed revocations and
	// uses the database clock, not transaction-start time, to check expiry/age.
	var recent bool
	err = tx.QueryRow(ctx, `SELECT created_at > statement_timestamp() - $3 * interval '1 second'
        FROM anonce.account_sessions WHERE token_digest = $1 AND account_id = $2
        AND created_at <= statement_timestamp() AND expires_at > statement_timestamp()`,
		digest[:], owner[:], int64(RecentAuthenticationWindow/time.Second)).Scan(&recent)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrUnavailable
	}
	if err != nil {
		return failure(ctx, "check member backup session")
	}
	if requireRecent && !recent {
		return ErrReauthenticationRequired
	}
	if err := apply(ctx, tx, owner); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return failure(ctx, "commit session member backup access")
	}
	return nil
}

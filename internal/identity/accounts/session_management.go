// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

package accounts

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// RecentAuthenticationWindow is the fixed development admission window for
// sensitive session operations, not proof of a verified authentication ceremony.
const RecentAuthenticationWindow = 5 * time.Minute

// ErrReauthenticationRequired denotes a live bearer too old for a sensitive operation.
var ErrReauthenticationRequired = errors.New("account session requires recent authentication")

// SessionID is a non-secret, random row selector, never a bearer credential,
// token digest, device identifier, or authorization to access an account.
// Rotation replaces it; it is not a stable browser or device tracking handle.
type SessionID [16]byte

// SessionInfo is identity-side session metadata, not a device identifier or an
// anonymous activity record. It contains no bearer secret or stored digest.
type SessionInfo struct {
	ID        SessionID
	CreatedAt time.Time
	ExpiresAt time.Time
	Current   bool
}

// ListSessions returns at most MaxSessionsPerAccount live, nonfuture sessions for
// the bearer owner's active account, newest first. Excess rows fail closed with
// ErrSessionLimit, never a partial list. No owner override or session selector is
// accepted. Inputs remain caller-owned and must not change until return.
// Authorization/expiry is checked after the account lock; returned metadata can
// immediately become stale. This is not browser authentication or device tracking.
func (s *Store) ListSessions(ctx context.Context, token []byte) ([]SessionInfo, error) {
	var result []SessionInfo
	err := s.withSession(ctx, token, false, func(ctx context.Context, tx pgx.Tx, owner ID, admittedAt time.Time) error {
		digest, _ := tokenDigest(token)
		rows, err := tx.Query(ctx, `SELECT session_id, created_at, expires_at, token_digest = $2
            FROM anonce.account_sessions WHERE account_id = $1
            AND created_at <= $3 AND expires_at > $3
            ORDER BY created_at DESC, expires_at DESC, session_id
            LIMIT $4`, owner[:], digest[:], admittedAt, MaxSessionsPerAccount+1)
		if err != nil {
			return failure(ctx, "list account sessions")
		}
		defer rows.Close()
		result, err = pgx.CollectRows(rows, sessionInfoRow)
		if err != nil {
			return failure(ctx, "read account session list")
		}
		if len(result) > MaxSessionsPerAccount {
			return ErrSessionLimit
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func sessionInfoRow(row pgx.CollectableRow) (SessionInfo, error) {
	var info SessionInfo
	var id pgtype.UUID
	if err := row.Scan(&id, &info.CreatedAt, &info.ExpiresAt, &info.Current); err != nil {
		return SessionInfo{}, err
	}
	if !id.Valid || id.Bytes == ([16]byte{}) {
		return SessionInfo{}, ErrUnavailable
	}
	info.ID = SessionID(id.Bytes)
	return info, nil
}

// RevokeOtherSessions removes every sibling reference, including expired or
// future-dated rows, for the live bearer's owner. The current session is unchanged.
// Creation/rotation must follow independently verified authentication within
// RecentAuthenticationWindow. No owner override, target selector, or freshness
// assertion is accepted. The returned count is published only after commit.
// The token remains caller-owned and must not change until return; clear after use.
// An uncertain commit may have removed siblings; do not retry blindly. New,
// independently authenticated starts ordered after this operation remain possible.
func (s *Store) RevokeOtherSessions(ctx context.Context, token []byte) (int64, error) {
	var removed int64
	err := s.withSession(ctx, token, true, func(ctx context.Context, tx pgx.Tx, owner ID, _ time.Time) error {
		digest, _ := tokenDigest(token)
		result, err := tx.Exec(ctx, `DELETE FROM anonce.account_sessions
            WHERE account_id = $1 AND token_digest <> $2`, owner[:], digest[:])
		if err != nil {
			return failure(ctx, "revoke other account sessions")
		}
		removed = result.RowsAffected()
		return nil
	})
	if err != nil {
		return 0, err
	}
	return removed, nil
}

func (s *Store) withSession(ctx context.Context, token []byte, requireRecent bool, apply func(context.Context, pgx.Tx, ID, time.Time) error) error {
	digest, ok := tokenDigest(token)
	if !ok {
		return ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	if err := s.ready(ctx); err != nil {
		return err
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return failure(ctx, "begin account session management")
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// Discovery is not authorization. All package session writers and backup
	// access lock the account first; a fresh statement must recheck the bearer.
	var rawID []byte
	err = tx.QueryRow(ctx, "SELECT account_id FROM anonce.account_sessions WHERE token_digest = $1", digest[:]).Scan(&rawID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrUnavailable
	}
	var owner ID
	if err != nil || len(rawID) != len(owner) {
		return failure(ctx, "find managed session account")
	}
	copy(owner[:], rawID)
	if err := lockAccount(ctx, tx, owner, true); err != nil {
		return err
	}
	var admittedAt time.Time
	var recent bool
	err = tx.QueryRow(ctx, `SELECT statement_timestamp(), created_at > statement_timestamp() - $3 * interval '1 second'
        FROM anonce.account_sessions
        WHERE token_digest = $1 AND account_id = $2
        AND created_at <= statement_timestamp() AND expires_at > statement_timestamp()`,
		digest[:], owner[:], int64(RecentAuthenticationWindow/time.Second)).Scan(&admittedAt, &recent)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrUnavailable
	}
	if err != nil {
		return failure(ctx, "authorize account session management")
	}
	if requireRecent && !recent {
		return ErrReauthenticationRequired
	}
	if err := apply(ctx, tx, owner, admittedAt); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return failure(ctx, "commit account session management")
	}
	return nil
}

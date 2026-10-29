// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

package accounts

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// RevokeAllForSession removes every session reference for the live bearer's owner,
// including the current session and expired or future-dated rows. Authentication
// admission must be within RecentAuthenticationWindow after account-lock waits.
// No owner override is accepted. The count is published only after commit; errors
// return zero, but an uncertain commit may have removed all sessions. Do not retry
// blindly. A separately authenticated start ordered afterward remains possible.
// The token remains caller-owned and must not change until return; clear after use.
// This does not lock local keys, revoke membership, or recall already admitted work.
func (s *Store) RevokeAllForSession(ctx context.Context, token []byte) (int64, error) {
	var removed int64
	err := s.withSession(ctx, token, true, func(ctx context.Context, tx pgx.Tx, owner ID, _ time.Time) error {
		result, err := tx.Exec(ctx, "DELETE FROM anonce.account_sessions WHERE account_id = $1", owner[:])
		if err != nil {
			return failure(ctx, "revoke all sessions for bearer account")
		}
		removed = result.RowsAffected()
		return nil
	})
	if err != nil {
		return 0, err
	}
	return removed, nil
}

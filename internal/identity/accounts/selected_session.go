// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

package accounts

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// RevokeSession removes one sibling reference selected by inventory's non-secret
// ID. The bearer must have authentication admission within
// RecentAuthenticationWindow, rechecked after account-lock waits. No owner override
// is accepted. Current, missing, rotated, and other-account selectors are unchanged
// and return false; expired or future-dated siblings may be removed.
// Inputs remain caller-owned and must not change until return; clear tokens after
// use. The result is published only after commit. Failure returns false, but an
// uncertain commit may have removed the target. Reread inventory, never retry
// blindly. Removal does not recall admitted work, lock keys, or revoke membership.
func (s *Store) RevokeSession(ctx context.Context, token []byte, target SessionID) (bool, error) {
	if target == (SessionID{}) {
		return false, ErrInvalidInput
	}
	var removed bool
	err := s.withSession(ctx, token, true, func(ctx context.Context, tx pgx.Tx, owner ID, _ time.Time) error {
		digest, _ := tokenDigest(token)
		result, err := tx.Exec(ctx, `DELETE FROM anonce.account_sessions
            WHERE account_id = $1 AND session_id = $2 AND token_digest <> $3`,
			owner[:], pgtype.UUID{Bytes: target, Valid: true}, digest[:])
		if err != nil {
			return failure(ctx, "revoke selected account session")
		}
		removed = result.RowsAffected() == 1
		return nil
	})
	if err != nil {
		return false, err
	}
	return removed, nil
}

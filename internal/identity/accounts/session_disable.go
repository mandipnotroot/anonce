// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

package accounts

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// DisableForSession disables the live bearer's account and removes all its session
// references atomically, including the current session. Authentication admission
// must be within RecentAuthenticationWindow after account-lock waits; no owner
// override or caller freshness assertion is accepted. An already invalidated
// bearer returns ErrUnavailable, unlike trusted-owner Disable's idempotent API.
// Inputs remain caller-owned and must not change until return; clear after use.
// An uncertain commit may have disabled the account even when an error is returned.
// There is no re-enable API. Encrypted backups are retained; this does not lock
// local keys, revoke membership, reset quotas, or recall already admitted work.
func (s *Store) DisableForSession(ctx context.Context, token []byte) error {
	return s.withSession(ctx, token, true, func(ctx context.Context, tx pgx.Tx, owner ID, _ time.Time) error {
		if _, err := tx.Exec(ctx, `UPDATE anonce.accounts SET state = 'disabled',
            disabled_at = statement_timestamp() WHERE id = $1`, owner[:]); err != nil {
			return failure(ctx, "disable bearer account")
		}
		if _, err := tx.Exec(ctx, "DELETE FROM anonce.account_sessions WHERE account_id = $1", owner[:]); err != nil {
			return failure(ctx, "invalidate disabled bearer account sessions")
		}
		return nil
	})
}

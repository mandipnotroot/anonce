// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

//go:build databaseintegration

package accounts

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type accountSnapshot struct {
	state      string
	disabledAt bool
	sessions   int
}

func snapshotAccount(t *testing.T, pool *pgxpool.Pool, id ID) accountSnapshot {
	t.Helper()
	var snapshot accountSnapshot
	if err := pool.QueryRow(t.Context(), `SELECT state, disabled_at IS NOT NULL,
        (SELECT count(*) FROM anonce.account_sessions WHERE account_id=$1)
        FROM anonce.accounts WHERE id=$1`, id[:]).Scan(&snapshot.state, &snapshot.disabledAt, &snapshot.sessions); err != nil {
		t.Fatal("read account state and reference count")
	}
	return snapshot
}

func testPostgresSessionDisable(t *testing.T) {
	store, pool := testStore(t)
	owner, other := newAccount(t, store), newAccount(t, store)
	token, _ := startSession(t, store, owner)
	foreign, original := startSession(t, store, other)
	before := bytes.Clone(token)
	defer clear(before)
	for range MaxSessionsPerAccount - 1 {
		startSession(t, store, owner)
	}
	for _, offset := range []time.Duration{-2 * time.Hour, time.Hour, -time.Minute} {
		syntheticSession(t, pool, owner, offset, time.Hour)
	}
	if err := store.DisableForSession(t.Context(), token); err != nil || !bytes.Equal(before, token) {
		t.Fatal("session-scoped disable failed or changed input")
	}
	if snapshotAccount(t, pool, owner) != (accountSnapshot{state: "disabled", disabledAt: true}) {
		t.Fatal("session-scoped disable retained references or left account active")
	}
	if err := store.DisableForSession(t.Context(), token); !errors.Is(err, ErrUnavailable) {
		t.Fatal("invalidated bearer disabled again")
	}
	if _, err := store.Resolve(t.Context(), token); !errors.Is(err, ErrUnavailable) {
		t.Fatal("disabled bearer remained usable")
	}
	if fresh, session, err := store.StartSession(t.Context(), owner, time.Hour); fresh != nil || session != (Session{}) || !errors.Is(err, ErrUnavailable) {
		clear(fresh)
		t.Fatal("disabled account admitted a new session")
	}
	if current, err := store.Resolve(t.Context(), foreign); err != nil || current != original {
		t.Fatal("session-scoped disable changed another account")
	}
	for _, state := range []string{"malformed", "unknown", "expired", "future", "revoked", "rotated", "disabled", "old", "boundary", "recent-boundary"} {
		t.Run(state, func(t *testing.T) {
			id := newAccount(t, store)
			bearer, _ := startSession(t, store, id)
			startSession(t, store, id)
			want := ErrUnavailable
			switch state {
			case "malformed":
				bearer = bearer[:TokenSize-1]
			case "unknown":
				bearer = make([]byte, TokenSize)
			case "expired":
				bearer, _ = syntheticSession(t, pool, id, -2*time.Hour, time.Hour)
			case "future":
				bearer, _ = syntheticSession(t, pool, id, time.Hour, time.Hour)
			case "revoked":
				if err := store.Revoke(t.Context(), bearer); err != nil {
					t.Fatal("revoke account-disable bearer")
				}
			case "rotated":
				fresh, _, err := store.RotateSession(t.Context(), id, bearer)
				clear(fresh)
				if err != nil {
					t.Fatal("rotate account-disable bearer")
				}
			case "disabled":
				if _, err := pool.Exec(t.Context(), "UPDATE anonce.accounts SET state='disabled',disabled_at=statement_timestamp() WHERE id=$1", id[:]); err != nil {
					t.Fatal("disable account while preserving references")
				}
			case "old", "boundary", "recent-boundary":
				offset := -RecentAuthenticationWindow
				if state == "old" {
					offset -= time.Second
				} else if state == "recent-boundary" {
					offset += 30 * time.Second
				}
				bearer, _ = syntheticSession(t, pool, id, offset, time.Hour)
				want = ErrReauthenticationRequired
			}
			before := snapshotAccount(t, pool, id)
			if state == "recent-boundary" {
				if err := store.DisableForSession(t.Context(), bearer); err != nil {
					t.Fatal("recent boundary bearer could not disable")
				}
			} else {
				if err := store.DisableForSession(t.Context(), bearer); !errors.Is(err, want) {
					t.Fatal("invalid or old bearer disabled an account")
				}
				if snapshotAccount(t, pool, id) != before {
					t.Fatal("denied disable changed account or references")
				}
				if state != "old" && state != "boundary" {
					return
				}
				fresh, _, err := store.RotateSession(t.Context(), id, bearer)
				if err != nil {
					t.Fatal("reauthenticate account-disable bearer")
				}
				defer clear(fresh)
				if err := store.DisableForSession(t.Context(), fresh); err != nil {
					t.Fatal("reauthenticated bearer could not disable")
				}
			}
			if snapshotAccount(t, pool, id) != (accountSnapshot{state: "disabled", disabledAt: true}) {
				t.Fatal("admitted disable left an active account or references")
			}
		})
	}
	pool.Close()
	if err := store.DisableForSession(t.Context(), foreign); err == nil || bytes.Contains([]byte(err.Error()), []byte("postgres")) {
		t.Fatal("closed disable pool reported success or driver diagnostics")
	}
}

func testPostgresConcurrentSessionDisable(t *testing.T) {
	store, pool := testStore(t)
	peer, _ := testStore(t)
	for _, operation := range []string{"same-bearer", "competing-bearers", "rotation", "start", "sign-out", "disable"} {
		t.Run(operation, func(t *testing.T) {
			owner := newAccount(t, store)
			token, _ := startSession(t, store, owner)
			sibling, _ := startSession(t, store, owner)
			gate := make(chan struct{})
			var wg sync.WaitGroup
			var disabled, peerDisabled bool
			wg.Go(func() {
				<-gate
				err := store.DisableForSession(t.Context(), token)
				if err != nil && !errors.Is(err, ErrUnavailable) {
					t.Error("unexpected concurrent session-disable failure")
				}
				disabled = err == nil
			})
			wg.Go(func() {
				<-gate
				var err error
				switch operation {
				case "same-bearer", "competing-bearers":
					bearer := token
					if operation == "competing-bearers" {
						bearer = sibling
					}
					err = peer.DisableForSession(t.Context(), bearer)
					peerDisabled = err == nil
				case "rotation":
					var fresh []byte
					fresh, _, err = peer.RotateSession(t.Context(), owner, sibling)
					clear(fresh)
				case "start":
					var fresh []byte
					fresh, _, err = peer.StartSession(t.Context(), owner, time.Hour)
					clear(fresh)
				case "sign-out":
					_, err = peer.RevokeAllForSession(t.Context(), sibling)
				case "disable":
					err = peer.Disable(t.Context(), owner)
				}
				if err != nil && (!errors.Is(err, ErrUnavailable) || operation == "disable") {
					t.Error("unexpected competing session-disable operation failure")
				}
			})
			close(gate)
			wg.Wait()
			snapshot := snapshotAccount(t, pool, owner)
			if operation == "same-bearer" || operation == "competing-bearers" {
				if disabled == peerDisabled {
					t.Fatal("competing session disables did not have exactly one winner")
				}
			} else if operation != "disable" && operation != "sign-out" && !disabled {
				t.Fatal("start or sibling rotation prevented account disabling")
			}
			if !disabled && operation == "sign-out" {
				if snapshot != (accountSnapshot{state: "active"}) {
					t.Fatal("sign-out ordered first left unexpected state")
				}
			} else if snapshot != (accountSnapshot{state: "disabled", disabledAt: true}) {
				t.Fatal("disable race left active account or usable references")
			}
		})
	}
}

func testPostgresSessionDisableWait(t *testing.T) {
	testPostgresInvalidationWait(t, true)
}

func testPostgresSessionDisableRollback(t *testing.T) {
	store, pool := testStore(t)
	owner := newAccount(t, store)
	token, original := startSession(t, store, owner)
	sibling, _ := startSession(t, store, owner)
	before := snapshotAccount(t, pool, owner)
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal("begin disable session-row lock")
	}
	defer func() { _ = tx.Rollback(t.Context()) }()
	digest, _ := tokenDigest(sibling)
	if _, err := tx.Exec(t.Context(), "DELETE FROM anonce.account_sessions WHERE token_digest=$1", digest[:]); err != nil {
		t.Fatal("hold disable session-row lock")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	if err := store.DisableForSession(ctx, token); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("blocked account disable reported success or lost cancellation")
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal("release disable session-row lock")
	}
	if snapshotAccount(t, pool, owner) != before {
		t.Fatal("cancelled disable retained state update or removed sessions")
	}
	if current, err := store.Resolve(t.Context(), token); err != nil || current != original {
		t.Fatal("cancelled disable changed current authorization")
	}
	if _, err := store.Resolve(t.Context(), sibling); err != nil {
		t.Fatal("cancelled disable removed sibling authorization")
	}
	if err := store.DisableForSession(t.Context(), token); err != nil {
		t.Fatal("cancelled disable retained locks")
	}
}

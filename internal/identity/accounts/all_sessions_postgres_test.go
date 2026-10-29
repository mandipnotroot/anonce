// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

//go:build databaseintegration

package accounts

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"sync"
	"testing"
	"time"
)

func testPostgresAllSessions(t *testing.T) {
	store, pool := testStore(t)
	owner, other := newAccount(t, store), newAccount(t, store)
	token, _ := startSession(t, store, owner)
	foreign, foreignSession := startSession(t, store, other)
	before := bytes.Clone(token)
	defer clear(before)
	for range MaxSessionsPerAccount - 1 {
		startSession(t, store, owner)
	}
	for _, offset := range []time.Duration{-2 * time.Hour, time.Hour, -time.Minute} {
		syntheticSession(t, pool, owner, offset, time.Hour)
	}
	if count, err := store.RevokeAllForSession(t.Context(), token); count != MaxSessionsPerAccount+3 || err != nil || !bytes.Equal(before, token) {
		t.Fatal("session-scoped sign-out returned wrong count or changed input")
	}
	var count int
	if err := pool.QueryRow(t.Context(), "SELECT count(*) FROM anonce.account_sessions WHERE account_id=$1", owner[:]).Scan(&count); err != nil || count != 0 {
		t.Fatal("session-scoped sign-out retained references")
	}
	if count, err := store.RevokeAllForSession(t.Context(), token); count != 0 || !errors.Is(err, ErrUnavailable) {
		t.Fatal("removed bearer could sign out again")
	}
	if _, err := store.Resolve(t.Context(), token); !errors.Is(err, ErrUnavailable) {
		t.Fatal("current bearer survived sign-out")
	}
	if current, err := store.Resolve(t.Context(), foreign); err != nil || current != foreignSession {
		t.Fatal("session-scoped sign-out changed another account")
	}
	// Signing out does not disable an account or forbid a later verified login.
	later, _ := startSession(t, store, owner)
	if _, err := store.Resolve(t.Context(), later); err != nil {
		t.Fatal("sign-out prevented a later authenticated start")
	}
	for _, state := range []string{"malformed", "unknown", "expired", "future", "revoked", "rotated", "disabled", "old", "boundary", "recent-boundary"} {
		t.Run(state, func(t *testing.T) {
			id := newAccount(t, store)
			bearer, _ := startSession(t, store, id)
			sibling, original := startSession(t, store, id)
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
					t.Fatal("revoke sign-out bearer")
				}
			case "rotated":
				fresh, _, err := store.RotateSession(t.Context(), id, bearer)
				clear(fresh)
				if err != nil {
					t.Fatal("rotate sign-out bearer")
				}
			case "disabled":
				if _, err := pool.Exec(t.Context(), "UPDATE anonce.accounts SET state='disabled',disabled_at=statement_timestamp() WHERE id=$1", id[:]); err != nil {
					t.Fatal("disable sign-out account without removing references")
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
			var beforeCount int64
			if err := pool.QueryRow(t.Context(), "SELECT count(*) FROM anonce.account_sessions WHERE account_id=$1", id[:]).Scan(&beforeCount); err != nil {
				t.Fatal("count sign-out references")
			}
			if state == "recent-boundary" {
				if count, err := store.RevokeAllForSession(t.Context(), bearer); err != nil || count != beforeCount {
					t.Fatal("recent boundary bearer could not sign out")
				}
				return
			}
			if count, err := store.RevokeAllForSession(t.Context(), bearer); count != 0 || !errors.Is(err, want) {
				t.Fatal("invalid or old bearer signed out or exposed a count")
			}
			var afterCount int64
			if err := pool.QueryRow(t.Context(), "SELECT count(*) FROM anonce.account_sessions WHERE account_id=$1", id[:]).Scan(&afterCount); err != nil || afterCount != beforeCount {
				t.Fatal("denied sign-out changed references")
			}
			if state != "disabled" {
				if current, err := store.Resolve(t.Context(), sibling); err != nil || current != original {
					t.Fatal("denied sign-out changed sibling authorization")
				}
			}
			if state == "old" || state == "boundary" {
				fresh, _, err := store.RotateSession(t.Context(), id, bearer)
				if err != nil {
					t.Fatal("reauthenticate sign-out bearer")
				}
				defer clear(fresh)
				if count, err := store.RevokeAllForSession(t.Context(), fresh); err != nil || count != beforeCount {
					t.Fatal("reauthenticated bearer could not sign out")
				}
			}
		})
	}
	pool.Close()
	if count, err := store.RevokeAllForSession(t.Context(), later); count != 0 || err == nil || bytes.Contains([]byte(err.Error()), []byte("postgres")) {
		t.Fatal("closed sign-out pool returned success or driver diagnostics")
	}
}

func testPostgresConcurrentAllSessions(t *testing.T) {
	store, pool := testStore(t)
	peer, _ := testStore(t)
	for _, operation := range []string{"same-bearer", "competing-bearers", "rotation", "start", "disable"} {
		t.Run(operation, func(t *testing.T) {
			owner := newAccount(t, store)
			token, _ := startSession(t, store, owner)
			sibling, _ := startSession(t, store, owner)
			gate := make(chan struct{})
			counts := make(chan int64, 2)
			var wg sync.WaitGroup
			wg.Go(func() {
				<-gate
				count, err := store.RevokeAllForSession(t.Context(), token)
				if err != nil && !errors.Is(err, ErrUnavailable) {
					t.Error("unexpected concurrent sign-out failure")
				}
				counts <- count
			})
			wg.Go(func() {
				<-gate
				switch operation {
				case "same-bearer", "competing-bearers":
					bearer := token
					if operation == "competing-bearers" {
						bearer = sibling
					}
					count, err := peer.RevokeAllForSession(t.Context(), bearer)
					if err != nil && !errors.Is(err, ErrUnavailable) {
						t.Error("unexpected competing sign-out failure")
					}
					counts <- count
				case "rotation":
					fresh, _, err := peer.RotateSession(t.Context(), owner, sibling)
					clear(fresh)
					if err != nil && !errors.Is(err, ErrUnavailable) {
						t.Error("unexpected rotation racing sign-out failure")
					}
				case "start":
					fresh, _, err := peer.StartSession(t.Context(), owner, time.Hour)
					clear(fresh)
					if err != nil {
						t.Error("start racing sign-out failed")
					}
				case "disable":
					if err := peer.Disable(t.Context(), owner); err != nil {
						t.Error("disable racing sign-out failed")
					}
				}
			})
			close(gate)
			wg.Wait()
			close(counts)
			var removed int64
			for count := range counts {
				removed += count
			}
			var remaining int64
			if err := pool.QueryRow(t.Context(), "SELECT count(*) FROM anonce.account_sessions WHERE account_id=$1", owner[:]).Scan(&remaining); err != nil {
				t.Fatal("count concurrent sign-out references")
			}
			if operation == "disable" {
				if remaining != 0 || removed != 0 && removed != 2 {
					t.Fatal("disable race retained sessions or returned unexpected count")
				}
			} else {
				want := int64(2)
				if operation == "start" {
					want++
				}
				if removed+remaining != want || remaining > 1 || operation != "start" && remaining != 0 {
					t.Fatal("sign-out race lost serialization")
				}
			}
		})
	}
}

func testPostgresAllSessionsWait(t *testing.T) {
	store, pool := testStore(t)
	for _, operation := range []string{"expiry", "age", "revocation", "rotation", "disable", "cancellation"} {
		t.Run(operation, func(t *testing.T) {
			owner := newAccount(t, store)
			token, session := startSession(t, store, owner)
			if operation == "expiry" {
				token, session = syntheticSession(t, pool, owner, -time.Hour+time.Second, time.Hour)
			} else if operation == "age" {
				token, session = syntheticSession(t, pool, owner, -RecentAuthenticationWindow+time.Second, time.Hour)
			}
			startSession(t, store, owner)
			tx, err := pool.Begin(t.Context())
			if err != nil {
				t.Fatal("begin sign-out account lock")
			}
			defer func() { _ = tx.Rollback(t.Context()) }()
			if err := lockAccount(t.Context(), tx, owner, true); err != nil {
				t.Fatal("hold sign-out account lock")
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				count, err := store.RevokeAllForSession(ctx, token)
				if count != 0 {
					t.Error("queued sign-out returned a count after invalidation")
				}
				done <- err
			}()
			waitForBlockedStart(t, pool, tx.Conn().PgConn().PID())
			want := ErrUnavailable
			switch operation {
			case "expiry", "age":
				deadline := session.ExpiresAt
				if operation == "age" {
					deadline, want = session.CreatedAt.Add(RecentAuthenticationWindow), ErrReauthenticationRequired
				}
				_, err = pool.Exec(t.Context(), "SELECT pg_sleep(GREATEST(0, EXTRACT(EPOCH FROM ($1::timestamptz-clock_timestamp())))+0.05)", deadline)
			case "revocation", "rotation":
				digest, _ := tokenDigest(token)
				if operation == "revocation" {
					_, err = tx.Exec(t.Context(), "DELETE FROM anonce.account_sessions WHERE token_digest=$1", digest[:])
				} else {
					fresh := make([]byte, TokenSize)
					rand.Read(fresh)
					next, _ := tokenDigest(fresh)
					clear(fresh)
					_, err = tx.Exec(t.Context(), `WITH previous AS (
                    DELETE FROM anonce.account_sessions WHERE token_digest=$1 RETURNING account_id,expires_at)
                    INSERT INTO anonce.account_sessions(token_digest,account_id,expires_at)
                    SELECT $2,account_id,expires_at FROM previous`, digest[:], next[:])
				}
			case "disable":
				_, err = tx.Exec(t.Context(), "UPDATE anonce.accounts SET state='disabled',disabled_at=statement_timestamp() WHERE id=$1", owner[:])
			case "cancellation":
				cancel()
				if err := <-done; !errors.Is(err, context.Canceled) {
					t.Fatal("queued sign-out lost cancellation")
				}
			}
			if err != nil {
				t.Fatal("prepare post-lock sign-out state")
			}
			var beforeCount int
			if err := tx.QueryRow(t.Context(), "SELECT count(*) FROM anonce.account_sessions WHERE account_id=$1", owner[:]).Scan(&beforeCount); err != nil {
				t.Fatal("count queued sign-out references")
			}
			if err := tx.Commit(t.Context()); err != nil {
				t.Fatal("release sign-out account lock")
			}
			if operation != "cancellation" {
				if err := <-done; !errors.Is(err, want) {
					t.Fatal("sign-out ignored post-lock authorization")
				}
			}
			var afterCount int
			if err := pool.QueryRow(t.Context(), "SELECT count(*) FROM anonce.account_sessions WHERE account_id=$1", owner[:]).Scan(&afterCount); err != nil || afterCount != beforeCount {
				t.Fatal("denied queued sign-out changed references")
			}
		})
	}
}

func testPostgresAllSessionsRollback(t *testing.T) {
	store, pool := testStore(t)
	owner := newAccount(t, store)
	token, original := startSession(t, store, owner)
	sibling, _ := startSession(t, store, owner)
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal("begin sign-out row lock")
	}
	defer func() { _ = tx.Rollback(t.Context()) }()
	digest, _ := tokenDigest(sibling)
	if _, err := tx.Exec(t.Context(), "DELETE FROM anonce.account_sessions WHERE token_digest=$1", digest[:]); err != nil {
		t.Fatal("hold sign-out row lock")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	if count, err := store.RevokeAllForSession(ctx, token); count != 0 || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("blocked sign-out returned a count or lost cancellation")
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal("release sign-out row lock")
	}
	if entries, err := store.ListSessions(t.Context(), token); err != nil || len(entries) != 2 {
		t.Fatal("cancelled sign-out changed references")
	}
	if current, err := store.Resolve(t.Context(), token); err != nil || current != original {
		t.Fatal("cancelled sign-out changed current session")
	}
}

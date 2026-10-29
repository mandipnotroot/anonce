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

func testPostgresSelectedSession(t *testing.T) {
	store, pool := testStore(t)
	owner, other := newAccount(t, store), newAccount(t, store)
	token, original := startSession(t, store, owner)
	sibling, siblingSession := startSession(t, store, owner)
	foreign, foreignSession := startSession(t, store, other)
	currentID, target := sessionSelector(t, pool, token), sessionSelector(t, pool, sibling)
	before := bytes.Clone(token)
	defer clear(before)
	for _, id := range []SessionID{{1}, currentID, sessionSelector(t, pool, foreign)} {
		if removed, err := store.RevokeSession(t.Context(), token, id); removed || err != nil {
			t.Fatal("missing, current, or foreign selector changed a session")
		}
	}
	if removed, err := store.RevokeSession(t.Context(), token, SessionID{}); removed || !errors.Is(err, ErrInvalidInput) {
		t.Fatal("zero selector admitted")
	}
	if current, err := store.Resolve(t.Context(), sibling); err != nil || current != siblingSession {
		t.Fatal("no-op selected revocation changed a sibling")
	}
	if removed, err := store.RevokeSession(t.Context(), token, target); !removed || err != nil || !bytes.Equal(before, token) {
		t.Fatal("selected revocation failed or changed bearer input")
	}
	if _, err := store.Resolve(t.Context(), sibling); !errors.Is(err, ErrUnavailable) {
		t.Fatal("selected sibling remained usable")
	}
	if removed, err := store.RevokeSession(t.Context(), token, target); removed || err != nil {
		t.Fatal("repeated selected revocation was not a no-op")
	}
	if current, err := store.Resolve(t.Context(), token); err != nil || current != original {
		t.Fatal("selected revocation changed current session")
	}
	if current, err := store.Resolve(t.Context(), foreign); err != nil || current != foreignSession {
		t.Fatal("selected revocation changed another account")
	}
	for _, offset := range []time.Duration{-2 * time.Hour, time.Hour} {
		candidate, _ := syntheticSession(t, pool, owner, offset, time.Hour)
		if removed, err := store.RevokeSession(t.Context(), token, sessionSelector(t, pool, candidate)); !removed || err != nil {
			t.Fatal("selected expired or future sibling could not be removed")
		}
	}
	for _, state := range []string{"malformed", "unknown", "expired", "future", "revoked", "rotated", "disabled", "old", "boundary"} {
		t.Run(state, func(t *testing.T) {
			id := newAccount(t, store)
			bearer, _ := startSession(t, store, id)
			victim, victimSession := startSession(t, store, id)
			selector := sessionSelector(t, pool, victim)
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
					t.Fatal("revoke selected-management bearer")
				}
			case "rotated":
				fresh, _, err := store.RotateSession(t.Context(), id, bearer)
				clear(fresh)
				if err != nil {
					t.Fatal("rotate selected-management bearer")
				}
			case "disabled":
				// Preserve references to prove denial happens before target deletion.
				if _, err := pool.Exec(t.Context(), "UPDATE anonce.accounts SET state='disabled',disabled_at=statement_timestamp() WHERE id=$1", id[:]); err != nil {
					t.Fatal("disable selected-management account")
				}
			case "old", "boundary":
				offset := -RecentAuthenticationWindow
				if state == "old" {
					offset -= time.Second
				}
				bearer, _ = syntheticSession(t, pool, id, offset, time.Hour)
				want = ErrReauthenticationRequired
			}
			if removed, err := store.RevokeSession(t.Context(), bearer, selector); removed || !errors.Is(err, want) {
				t.Fatal("invalid or old bearer revoked a selected session")
			}
			if sessionSelector(t, pool, victim) != selector {
				t.Fatal("denied operation changed the selected row")
			}
			if state != "disabled" {
				if current, err := store.Resolve(t.Context(), victim); err != nil || current != victimSession {
					t.Fatal("denied operation changed sibling authorization")
				}
			}
			if state == "old" || state == "boundary" {
				fresh, _, err := store.RotateSession(t.Context(), id, bearer)
				if err != nil {
					t.Fatal("reauthenticate selected-management bearer")
				}
				defer clear(fresh)
				if removed, err := store.RevokeSession(t.Context(), fresh, selector); !removed || err != nil {
					t.Fatal("reauthenticated bearer could not revoke selected sibling")
				}
			}
		})
	}
	// Target rotation invalidates an inventory selector, not its successor.
	sibling, _ = startSession(t, store, owner)
	target = sessionSelector(t, pool, sibling)
	fresh, rotated, err := store.RotateSession(t.Context(), owner, sibling)
	if err != nil {
		t.Fatal("rotate selected target")
	}
	defer clear(fresh)
	if removed, err := store.RevokeSession(t.Context(), token, target); removed || err != nil {
		t.Fatal("stale selector revoked a successor")
	}
	if current, err := store.Resolve(t.Context(), fresh); err != nil || current != rotated {
		t.Fatal("stale selector changed successor authorization")
	}
	// Selection needs no inventory and still works above admission capacity.
	for range MaxSessionsPerAccount {
		syntheticSession(t, pool, owner, -time.Minute, time.Hour)
	}
	if removed, err := store.RevokeSession(t.Context(), token, sessionSelector(t, pool, fresh)); !removed || err != nil {
		t.Fatal("excess rows prevented selected revocation")
	}
	pool.Close()
	if removed, err := store.RevokeSession(t.Context(), token, target); removed || err == nil || bytes.Contains([]byte(err.Error()), []byte("postgres")) {
		t.Fatal("closed pool reported success or driver details")
	}
}

func testPostgresConcurrentSelectedSession(t *testing.T) {
	store, pool := testStore(t)
	peer, _ := testStore(t)
	for _, operation := range []string{"same-target", "competing-bearers", "rotation", "disable"} {
		t.Run(operation, func(t *testing.T) {
			owner := newAccount(t, store)
			token, _ := startSession(t, store, owner)
			sibling, _ := startSession(t, store, owner)
			currentID, target := sessionSelector(t, pool, token), sessionSelector(t, pool, sibling)
			gate := make(chan struct{})
			removed := make(chan bool, 2)
			var rotated bool
			var wg sync.WaitGroup
			wg.Go(func() {
				<-gate
				didRemove, err := store.RevokeSession(t.Context(), token, target)
				if err != nil && (!errors.Is(err, ErrUnavailable) || operation == "same-target" || operation == "rotation") {
					t.Error("unexpected selected revocation race failure")
				}
				removed <- didRemove
			})
			wg.Go(func() {
				<-gate
				switch operation {
				case "same-target", "competing-bearers":
					bearer, selector := token, target
					if operation == "competing-bearers" {
						bearer, selector = sibling, currentID
					}
					didRemove, err := peer.RevokeSession(t.Context(), bearer, selector)
					if err != nil && (!errors.Is(err, ErrUnavailable) || operation == "same-target") {
						t.Error("unexpected competing selected revocation failure")
					}
					removed <- didRemove
				case "rotation":
					fresh, _, err := peer.RotateSession(t.Context(), owner, sibling)
					clear(fresh)
					if err != nil && !errors.Is(err, ErrUnavailable) {
						t.Error("unexpected selected target rotation failure")
					}
					removed <- err == nil
					rotated = err == nil
				case "disable":
					if err := peer.Disable(t.Context(), owner); err != nil {
						t.Error("disable racing selected revocation failed")
					}
				}
			})
			close(gate)
			wg.Wait()
			close(removed)
			winners := 0
			for success := range removed {
				if success {
					winners++
				}
			}
			if operation != "disable" && winners != 1 {
				t.Fatal("selected revocation race had the wrong winner count")
			}
			var count int
			want := 1
			if rotated {
				want = 2
			}
			if operation == "disable" {
				want = 0
			}
			if err := pool.QueryRow(t.Context(), "SELECT count(*) FROM anonce.account_sessions WHERE account_id=$1", owner[:]).Scan(&count); err != nil || count != want {
				t.Fatal("selected revocation race left unexpected rows")
			}
		})
	}
}

func testPostgresSelectedSessionWait(t *testing.T) {
	store, pool := testStore(t)
	for _, operation := range []string{"expiry", "age", "revocation", "rotation", "target-rotation", "disable", "cancellation"} {
		t.Run(operation, func(t *testing.T) {
			owner := newAccount(t, store)
			var token []byte
			var session Session
			if operation == "age" {
				token, session = syntheticSession(t, pool, owner, -RecentAuthenticationWindow+time.Second, time.Hour)
			} else {
				lifetime := MaxLifetime
				if operation == "expiry" {
					lifetime = time.Second
				}
				var err error
				token, session, err = store.StartSession(t.Context(), owner, lifetime)
				if err != nil {
					t.Fatal("prepare selected revocation bearer")
				}
				defer clear(token)
			}
			sibling, _ := startSession(t, store, owner)
			target := sessionSelector(t, pool, sibling)
			tx, err := pool.Begin(t.Context())
			if err != nil {
				t.Fatal("begin selected revocation lock")
			}
			defer func() { _ = tx.Rollback(t.Context()) }()
			if err := lockAccount(t.Context(), tx, owner, true); err != nil {
				t.Fatal("hold selected revocation account lock")
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				removed, err := store.RevokeSession(ctx, token, target)
				if removed {
					t.Error("queued selected revocation reported removal after invalidation")
				}
				done <- err
			}()
			waitForBlockedStart(t, pool, tx.Conn().PgConn().PID())
			want := ErrUnavailable
			remaining := 2
			switch operation {
			case "expiry", "age":
				deadline := session.ExpiresAt
				if operation == "age" {
					deadline = session.CreatedAt.Add(RecentAuthenticationWindow)
					want = ErrReauthenticationRequired
				}
				_, err = pool.Exec(t.Context(), "SELECT pg_sleep(GREATEST(0, EXTRACT(EPOCH FROM ($1::timestamptz-clock_timestamp())))+0.05)", deadline)
			case "revocation":
				digest, _ := tokenDigest(token)
				_, err = tx.Exec(t.Context(), "DELETE FROM anonce.account_sessions WHERE token_digest=$1", digest[:])
				remaining = 1
			case "rotation", "target-rotation":
				previous := token
				if operation == "target-rotation" {
					previous, want = sibling, nil
				}
				digest, _ := tokenDigest(previous)
				fresh := make([]byte, TokenSize)
				rand.Read(fresh)
				next, _ := tokenDigest(fresh)
				clear(fresh)
				// Simulate a trusted rotation under the already-held account lock.
				// StartSession/RotateSession normally generate the replacement token.
				_, err = tx.Exec(t.Context(), `WITH previous AS (
                    DELETE FROM anonce.account_sessions WHERE token_digest=$1 RETURNING account_id,expires_at)
                    INSERT INTO anonce.account_sessions(token_digest,account_id,expires_at)
                    SELECT $2,account_id,expires_at FROM previous`, digest[:], next[:])
			case "disable":
				_, err = tx.Exec(t.Context(), "UPDATE anonce.accounts SET state='disabled',disabled_at=statement_timestamp() WHERE id=$1", owner[:])
			case "cancellation":
				cancel()
				if err := <-done; !errors.Is(err, context.Canceled) {
					t.Fatal("selected revocation lost cancellation")
				}
			}
			if err != nil {
				t.Fatal("prepare post-lock selected revocation state")
			}
			if err := tx.Commit(t.Context()); err != nil {
				t.Fatal("release selected revocation account lock")
			}
			if operation != "cancellation" {
				if err := <-done; !errors.Is(err, want) {
					t.Fatal("selected revocation ignored post-lock authorization or target replacement")
				}
			}
			var count int
			if err := pool.QueryRow(t.Context(), "SELECT count(*) FROM anonce.account_sessions WHERE account_id=$1", owner[:]).Scan(&count); err != nil || count != remaining {
				t.Fatal("queued selected revocation changed unexpected references")
			}
		})
	}
}

func testPostgresSelectedSessionRollback(t *testing.T) {
	store, pool := testStore(t)
	owner := newAccount(t, store)
	token, original := startSession(t, store, owner)
	sibling, _ := startSession(t, store, owner)
	target := sessionSelector(t, pool, sibling)
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal("begin selected row lock")
	}
	defer func() { _ = tx.Rollback(t.Context()) }()
	digest, _ := tokenDigest(sibling)
	if _, err := tx.Exec(t.Context(), "DELETE FROM anonce.account_sessions WHERE token_digest=$1", digest[:]); err != nil {
		t.Fatal("hold selected row lock")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	if removed, err := store.RevokeSession(ctx, token, target); removed || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("blocked selected revocation reported removal or lost cancellation")
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal("release selected row lock")
	}
	if entries, err := store.ListSessions(t.Context(), token); err != nil || len(entries) != 2 {
		t.Fatal("cancelled selected revocation changed rows")
	}
	if current, err := store.Resolve(t.Context(), token); err != nil || current != original {
		t.Fatal("cancelled selected revocation changed current session")
	}
	if _, err := store.Resolve(t.Context(), sibling); err != nil {
		t.Fatal("cancelled selected revocation removed the target")
	}
}

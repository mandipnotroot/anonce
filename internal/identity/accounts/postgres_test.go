// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

//go:build databaseintegration

package accounts

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The harness provisions a disposable database and mounts only this side's
// runtime credential. Missing configuration fails, never skips this target.
func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	side := os.Getenv("ANONCE_TEST_SIDE")
	if side != "identity" && side != "submission" {
		t.Fatal("invalid database test side")
	}
	password, err := os.ReadFile("/run/secrets/runtime_password")
	if err != nil {
		t.Fatal("read database test credential")
	}
	defer clear(password)
	config, err := pgxpool.ParseConfig("postgres://anonce_runtime@" + side + "-db:5432/" + side + "?sslmode=disable&connect_timeout=5")
	if err != nil {
		t.Fatal("configure database test pool")
	}
	config.ConnConfig.Password = string(password)
	config.ConnConfig.RuntimeParams = map[string]string{"search_path": "pg_catalog,anonce"}
	config.MaxConns = 8
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal("open database test pool")
	}
	t.Cleanup(pool.Close)
	return pool
}

func testStore(t *testing.T) (*Store, *pgxpool.Pool) {
	t.Helper()
	pool := testPool(t)
	store, err := New(t.Context(), pool)
	if err != nil {
		t.Fatal("admit identity account store")
	}
	return store, pool
}

func TestPostgresAccounts(t *testing.T) {
	if os.Getenv("ANONCE_TEST_SIDE") == "submission" {
		if store, err := New(t.Context(), testPool(t)); err == nil || store != nil {
			t.Fatal("submission database admitted")
		}
		return
	}
	t.Run("lifecycle", testPostgresLifecycle)
	t.Run("constraints-and-grants", testPostgresConstraints)
	t.Run("expiry-and-retention", testPostgresExpiry)
	t.Run("concurrent-disable", testPostgresConcurrentDisable)
	t.Run("blocked-cancellation", testPostgresCancellation)
	t.Run("disable-rollback", testPostgresDisableRollback)
	t.Run("session-rotation", testPostgresRotation)
	t.Run("concurrent-session-rotation", testPostgresConcurrentRotation)
	t.Run("rotation-cancellation-and-rollback", testPostgresRotationCancellation)
}

func testPostgresRotation(t *testing.T) {
	store, pool := testStore(t)
	id, other := newAccount(t, store), newAccount(t, store)
	token, original := startSession(t, store, id)
	sibling, siblingSession := startSession(t, store, id)
	before := bytes.Clone(token)
	defer clear(before)
	if fresh, session, err := store.RotateSession(t.Context(), other, token); fresh != nil || session != (Session{}) || !errors.Is(err, ErrUnavailable) {
		t.Fatal("rotation accepted another authenticated account")
	}
	fresh, session, err := store.RotateSession(t.Context(), id, token)
	if err != nil || len(fresh) != TokenSize || bytes.Equal(fresh, token) || !bytes.Equal(token, before) ||
		session.AccountID != id || session.ExpiresAt != original.ExpiresAt || !session.CreatedAt.After(original.CreatedAt) {
		t.Fatal("rotation changed owner/expiry or token ownership")
	}
	defer clear(fresh)
	if resolved, err := store.Resolve(t.Context(), fresh); err != nil || resolved != session {
		t.Fatal("rotated session unavailable")
	}
	if resolved, err := store.Resolve(t.Context(), sibling); err != nil || resolved != siblingSession {
		t.Fatal("rotation changed sibling session")
	}
	digest, _ := tokenDigest(fresh)
	var count int
	if err := pool.QueryRow(t.Context(), "SELECT count(*) FROM anonce.account_sessions WHERE token_digest=$1", digest[:]).Scan(&count); err != nil || count != 1 {
		t.Fatal("rotated digest missing")
	}
	for _, state := range []string{"replaced", "unknown", "expired", "future", "revoked", "disabled"} {
		t.Run(state, func(t *testing.T) {
			owner := id
			candidate := token
			if state == "unknown" || state == "expired" || state == "future" {
				candidate = make([]byte, TokenSize)
				rand.Read(candidate)
				defer clear(candidate)
				if state != "unknown" {
					digest, _ := tokenDigest(candidate)
					age := int64(-3600)
					if state == "future" {
						age = 3600
					}
					_, err := pool.Exec(t.Context(), `INSERT INTO anonce.account_sessions(token_digest,account_id,created_at,expires_at)
                        VALUES ($1,$2,statement_timestamp()+$3*interval '1 second',statement_timestamp()+($3+60)*interval '1 second')`, digest[:], id[:], age)
					if err != nil {
						t.Fatal("insert synthetic rotation session")
					}
				}
			} else if state == "revoked" || state == "disabled" {
				owner = newAccount(t, store)
				candidate, _ = startSession(t, store, owner)
				var err error
				if state == "revoked" {
					err = store.Revoke(t.Context(), candidate)
				} else {
					err = store.Disable(t.Context(), owner)
				}
				if err != nil {
					t.Fatal("invalidate rotation candidate")
				}
			}
			if result, session, err := store.RotateSession(t.Context(), owner, candidate); result != nil || session != (Session{}) || !errors.Is(err, ErrUnavailable) {
				t.Fatal("unavailable session rotated")
			}
		})
	}
	if _, err := store.Resolve(t.Context(), token); !errors.Is(err, ErrUnavailable) {
		t.Fatal("old token survived rotation")
	}
}

func testPostgresConcurrentRotation(t *testing.T) {
	store, pool := testStore(t)
	for _, invalidation := range []string{"none", "revoke-all", "disable"} {
		t.Run(invalidation, func(t *testing.T) {
			id := newAccount(t, store)
			token, original := startSession(t, store, id)
			gate := make(chan struct{})
			results := make(chan []byte, 8)
			var wg sync.WaitGroup
			for range 8 {
				wg.Go(func() {
					<-gate
					fresh, session, err := store.RotateSession(t.Context(), id, token)
					if err == nil {
						if session.ExpiresAt != original.ExpiresAt {
							t.Error("concurrent rotation extended expiry")
						}
						results <- fresh
					} else if !errors.Is(err, ErrUnavailable) || fresh != nil || session != (Session{}) {
						t.Error("concurrent rotation failed unexpectedly")
					}
				})
			}
			if invalidation != "none" {
				wg.Go(func() {
					<-gate
					var err error
					if invalidation == "disable" {
						err = store.Disable(t.Context(), id)
					} else {
						err = store.RevokeAll(t.Context(), id)
					}
					if err != nil {
						t.Error("rotation invalidation failed")
					}
				})
			}
			close(gate)
			wg.Wait()
			close(results)
			successes := 0
			for fresh := range results {
				if invalidation != "none" {
					if _, err := store.Resolve(t.Context(), fresh); !errors.Is(err, ErrUnavailable) {
						t.Error("rotated session survived invalidation")
					}
				}
				clear(fresh)
				successes++
			}
			want := 0
			if invalidation == "none" {
				want = 1
				if successes != 1 {
					t.Fatal("competing rotations did not have one winner")
				}
			}
			var count int
			if err := pool.QueryRow(t.Context(), "SELECT count(*) FROM anonce.account_sessions WHERE account_id=$1", id[:]).Scan(&count); err != nil || count != want || successes > 1 {
				t.Fatal("rotation persisted unexpected sessions")
			}
		})
	}
}

func testPostgresRotationCancellation(t *testing.T) {
	store, pool := testStore(t)
	id := newAccount(t, store)
	token, original := startSession(t, store, id)
	digest, _ := tokenDigest(token)
	for _, query := range []string{
		"SELECT state FROM anonce.accounts WHERE id=$1 FOR UPDATE",
		"DELETE FROM anonce.account_sessions WHERE token_digest=$1",
	} {
		tx, err := pool.Begin(t.Context())
		if err != nil {
			t.Fatal("begin rotation test lock")
		}
		defer func() { _ = tx.Rollback(t.Context()) }()
		argument := id[:]
		if query == "DELETE FROM anonce.account_sessions WHERE token_digest=$1" {
			argument = digest[:]
		}
		if _, err := tx.Exec(t.Context(), query, argument); err != nil {
			t.Fatal("hold rotation test lock")
		}
		ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
		fresh, session, err := store.RotateSession(ctx, id, token)
		cancel()
		if fresh != nil || session != (Session{}) || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("blocked rotation cancellation lost")
		}
		if err := tx.Rollback(t.Context()); err != nil {
			t.Fatal("release rotation test lock")
		}
		// Acquire the same account lock to wait for cancelled transaction cleanup.
		check, err := pool.Begin(t.Context())
		if err != nil {
			t.Fatal("begin rotation rollback check")
		}
		defer func() { _ = check.Rollback(t.Context()) }()
		if err := lockAccount(t.Context(), check, id, true); err != nil {
			t.Fatal("rotation retained account lock")
		}
		if err := check.Rollback(t.Context()); err != nil {
			t.Fatal("finish rotation rollback check")
		}
		if session, err := store.Resolve(t.Context(), token); err != nil || session != original {
			t.Fatal("cancelled rotation changed old session")
		}
	}
	pool.Close()
	if fresh, session, err := store.RotateSession(t.Context(), id, token); fresh != nil || session != (Session{}) || err == nil || bytes.Contains([]byte(err.Error()), []byte("postgres")) {
		t.Fatal("closed pool rotation admitted or leaked diagnostics")
	}
}

func newAccount(t *testing.T, store *Store) ID {
	t.Helper()
	id, err := store.Create(t.Context())
	if err != nil || id == (ID{}) {
		t.Fatal("create test account")
	}
	return id
}

func startSession(t *testing.T, store *Store, id ID) ([]byte, Session) {
	t.Helper()
	token, session, err := store.StartSession(t.Context(), id, MaxLifetime)
	if err != nil || len(token) != TokenSize || session.AccountID != id || session.ExpiresAt.Sub(session.CreatedAt) != MaxLifetime {
		t.Fatal("start test session")
	}
	t.Cleanup(func() { clear(token) })
	return token, session
}

func testPostgresLifecycle(t *testing.T) {
	store, pool := testStore(t)
	first, second := newAccount(t, store), newAccount(t, store)
	if first == second {
		t.Fatal("account IDs reused")
	}
	token, session := startSession(t, store, first)
	other, _ := startSession(t, store, first)
	secondToken, _ := startSession(t, store, second)
	if bytes.Equal(token, other) {
		t.Fatal("session secrets reused")
	}
	before := bytes.Clone(token)
	defer clear(before)
	resolved, err := store.Resolve(t.Context(), token)
	if err != nil || resolved != session || !bytes.Equal(before, token) {
		t.Fatal("session lookup or token ownership differs")
	}
	digest, _ := tokenDigest(token)
	var stored []byte
	if err := pool.QueryRow(t.Context(), "SELECT token_digest FROM anonce.account_sessions WHERE account_id=$1 AND token_digest=$2", first[:], digest[:]).Scan(&stored); err != nil || !bytes.Equal(stored, digest[:]) || bytes.Equal(stored, token) {
		t.Fatal("raw session secret stored or digest missing")
	}
	unknown := make([]byte, TokenSize)
	rand.Read(unknown)
	defer clear(unknown)
	if _, err := store.Resolve(t.Context(), unknown); !errors.Is(err, ErrUnavailable) {
		t.Fatal("unknown token resolved")
	}
	for i := range token {
		changed := bytes.Clone(token)
		changed[i] ^= 1
		_, err := store.Resolve(t.Context(), changed)
		clear(changed)
		if !errors.Is(err, ErrUnavailable) {
			t.Fatal("modified token resolved")
		}
	}
	for range 2 {
		if err := store.Revoke(t.Context(), token); err != nil {
			t.Fatal("idempotent revocation failed")
		}
	}
	if _, err := store.Resolve(t.Context(), token); !errors.Is(err, ErrUnavailable) {
		t.Fatal("revoked session resolved")
	}
	if _, err := store.Resolve(t.Context(), other); err != nil {
		t.Fatal("individual revocation removed sibling")
	}
	if err := store.RevokeAll(t.Context(), first); err != nil {
		t.Fatal("revoke all failed")
	}
	if _, err := store.Resolve(t.Context(), other); !errors.Is(err, ErrUnavailable) {
		t.Fatal("sibling survived revoke-all")
	}
	if _, err := store.Resolve(t.Context(), secondToken); err != nil {
		t.Fatal("cross-account revocation")
	}
	fresh, _ := startSession(t, store, first)
	for range 2 {
		if err := store.Disable(t.Context(), first); err != nil {
			t.Fatal("disable failed")
		}
	}
	if _, err := store.Resolve(t.Context(), fresh); !errors.Is(err, ErrUnavailable) {
		t.Fatal("disabled account resolved")
	}
	for _, id := range []ID{first, {1}} {
		if token, session, err := store.StartSession(t.Context(), id, time.Second); token != nil || session != (Session{}) || !errors.Is(err, ErrUnavailable) {
			t.Fatal("disabled or unknown account started session")
		}
	}
	if _, err := store.Resolve(t.Context(), secondToken); err != nil {
		t.Fatal("disabling changed another account")
	}
	if err := store.Disable(t.Context(), ID{1}); !errors.Is(err, ErrUnavailable) {
		t.Fatal("unknown account disabled")
	}
	if err := store.Revoke(t.Context(), unknown); err != nil {
		t.Fatal("unknown token revocation failed")
	}
}

func testPostgresConstraints(t *testing.T) {
	store, pool := testStore(t)
	id := newAccount(t, store)
	token, _ := startSession(t, store, id)
	digest, _ := tokenDigest(token)
	for _, tc := range []struct{ query, state string }{
		{"INSERT INTO anonce.accounts(id) VALUES ('\\x01')", "23514"},
		{"INSERT INTO anonce.accounts(id) SELECT id FROM anonce.accounts LIMIT 1", "23505"},
		{"UPDATE anonce.accounts SET state='unknown'", "23514"},
		{"UPDATE anonce.accounts SET state='disabled'", "23514"},
		{"INSERT INTO anonce.account_sessions(token_digest, account_id, expires_at) VALUES ('\\x01', $1, statement_timestamp()+interval '1 hour')", "23514"},
		{"INSERT INTO anonce.account_sessions(token_digest, account_id, expires_at) VALUES (decode(repeat('ab',32),'hex'), decode(repeat('ab',16),'hex'), statement_timestamp()+interval '1 hour')", "23503"},
		{"INSERT INTO anonce.account_sessions(token_digest, account_id, expires_at) VALUES (decode(repeat('ab',32),'hex'), $1, statement_timestamp())", "23514"},
		{"INSERT INTO anonce.account_sessions(token_digest, account_id, expires_at) VALUES (decode(repeat('ab',32),'hex'), $1, statement_timestamp()+interval '13 hours')", "23514"},
		{"INSERT INTO anonce.account_sessions SELECT * FROM anonce.account_sessions LIMIT 1", "23505"},
		{"UPDATE anonce.accounts SET created_at=statement_timestamp()", "42501"},
		{"UPDATE anonce.accounts SET id=id", "42501"},
		{"DELETE FROM anonce.accounts", "42501"},
		{"UPDATE anonce.account_sessions SET expires_at=expires_at+interval '1 hour'", "42501"},
		{"TRUNCATE anonce.account_sessions", "42501"},
		{"ALTER TABLE anonce.accounts ADD COLUMN forbidden integer", "42501"},
		{"SET ROLE anonce_owner", "42501"},
		{"SELECT * FROM anonce.identity_schema_version", "42501"},
	} {
		var args []any
		if bytes.Contains([]byte(tc.query), []byte("$1")) {
			args = []any{id[:]}
		}
		_, err := pool.Exec(t.Context(), tc.query, args...)
		if err == nil || sqlState(err) != tc.state {
			t.Fatalf("constraint/grant expectation failed: expected %s", tc.state)
		}
	}
	var count int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM information_schema.columns WHERE table_schema='anonce' AND table_name='account_sessions'`).Scan(&count); err != nil || count != 4 {
		t.Fatal("session schema contains unexpected fields")
	}
	if err := pool.QueryRow(t.Context(), "SELECT count(*) FROM anonce.account_sessions WHERE token_digest=$1", digest[:]).Scan(&count); err != nil || count != 1 {
		t.Fatal("failed statements changed session")
	}
}

func sqlState(err error) string {
	if state, ok := errors.AsType[*pgconn.PgError](err); ok {
		return state.SQLState()
	}
	return ""
}

func testPostgresExpiry(t *testing.T) {
	store, pool := testStore(t)
	id := newAccount(t, store)
	live, _ := startSession(t, store, id)
	var tokens [][]byte
	defer func() {
		for _, token := range tokens {
			clear(token)
		}
	}()
	for range 3 {
		token := make([]byte, TokenSize)
		rand.Read(token)
		tokens = append(tokens, token)
		digest, _ := tokenDigest(token)
		_, err := pool.Exec(t.Context(), `INSERT INTO anonce.account_sessions(token_digest, account_id, created_at, expires_at)
            VALUES ($1,$2,statement_timestamp()-interval '2 hours',statement_timestamp()-interval '1 hour')`, digest[:], id[:])
		if err != nil {
			t.Fatal("insert synthetic expired session")
		}
		if session, err := store.Resolve(t.Context(), token); session != (Session{}) || !errors.Is(err, ErrUnavailable) {
			t.Fatal("expired session resolved")
		}
	}
	for _, want := range []int64{2, 1, 0} {
		if count, err := store.PurgeExpired(t.Context(), 2); err != nil || count != want {
			t.Fatal("bounded expired cleanup differs")
		}
	}
	if _, err := store.Resolve(t.Context(), live); err != nil {
		t.Fatal("cleanup removed live session")
	}
	short, _, err := store.StartSession(t.Context(), id, time.Second)
	if err != nil {
		t.Fatal("minimum session lifetime failed")
	}
	defer clear(short)
	// The actual database clock, not a mocked application clock, advances.
	time.Sleep(1100 * time.Millisecond)
	if _, err := store.Resolve(t.Context(), short); !errors.Is(err, ErrUnavailable) {
		t.Fatal("absolute expiry not enforced")
	}
}

func testPostgresConcurrentDisable(t *testing.T) {
	store, pool := testStore(t)
	for range 8 {
		id := newAccount(t, store)
		gate := make(chan struct{})
		var wg sync.WaitGroup
		for range 8 {
			wg.Go(func() {
				<-gate
				token, _, err := store.StartSession(t.Context(), id, time.Minute)
				defer clear(token)
				if err != nil && !errors.Is(err, ErrUnavailable) {
					t.Error("concurrent session failed unexpectedly")
				}
			})
		}
		wg.Go(func() {
			<-gate
			if err := store.Disable(t.Context(), id); err != nil {
				t.Error("concurrent disable failed")
			}
		})
		close(gate)
		wg.Wait()
		var count int
		if err := pool.QueryRow(t.Context(), "SELECT count(*) FROM anonce.account_sessions WHERE account_id=$1", id[:]).Scan(&count); err != nil || count != 0 {
			t.Fatal("session survived concurrent disable")
		}
	}
}

func testPostgresCancellation(t *testing.T) {
	store, pool := testStore(t)
	id := newAccount(t, store)
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal("begin test lock")
	}
	defer func() { _ = tx.Rollback(t.Context()) }()
	if err := lockAccount(t.Context(), tx, id, false); err != nil {
		t.Fatal("hold test lock")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	if token, session, err := store.StartSession(ctx, id, time.Minute); token != nil || session != (Session{}) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("blocked start cancellation lost")
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal("release test lock")
	}
	var count int
	if err := pool.QueryRow(t.Context(), "SELECT count(*) FROM anonce.account_sessions WHERE account_id=$1", id[:]).Scan(&count); err != nil || count != 0 {
		t.Fatal("cancelled start persisted session")
	}
	cancelled, stop := context.WithCancel(t.Context())
	stop()
	if _, err := New(cancelled, pool); !errors.Is(err, context.Canceled) {
		t.Fatal("constructor cancellation lost")
	}
	pool.Close()
	if _, err := store.Create(t.Context()); err == nil || bytes.Contains([]byte(err.Error()), []byte("postgres")) {
		t.Fatal("closed pool accepted or driver details leaked")
	}
}

func testPostgresDisableRollback(t *testing.T) {
	store, pool := testStore(t)
	id := newAccount(t, store)
	token, _ := startSession(t, store, id)
	digest, _ := tokenDigest(token)
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal("begin test session lock")
	}
	defer func() { _ = tx.Rollback(t.Context()) }()
	// Hold a row lock using only the runtime DELETE grant. Rollback restores
	// this synthetic deletion; the concurrently blocked disable must roll back
	// its preceding account update rather than partially disabling the account.
	if _, err := tx.Exec(t.Context(), "DELETE FROM anonce.account_sessions WHERE token_digest=$1", digest[:]); err != nil {
		t.Fatal("hold test session lock")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	if err := store.Disable(ctx, id); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("blocked disable did not propagate cancellation")
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal("release test session lock")
	}
	// A cancelled rollback may close the physical connection. Wait for that
	// transaction to finish by acquiring the account lock in a fresh transaction.
	check, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal("begin rollback verification")
	}
	defer func() { _ = check.Rollback(t.Context()) }()
	if err := lockAccount(t.Context(), check, id, true); err != nil {
		t.Fatal("cancelled disable changed account status")
	}
	if err := check.Rollback(t.Context()); err != nil {
		t.Fatal("finish rollback verification")
	}
	if _, err := store.Resolve(t.Context(), token); err != nil {
		t.Fatal("cancelled disable removed original session")
	}
}

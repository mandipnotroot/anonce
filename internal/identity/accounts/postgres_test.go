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
	"github.com/jackc/pgx/v5/pgtype"
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
	t.Run("session-limit", testPostgresSessionLimit)
	t.Run("concurrent-session-limit", testPostgresConcurrentSessionLimit)
	t.Run("session-limit-after-lock-wait", testPostgresSessionLimitWait)
	t.Run("session-inventory", testPostgresSessionInventory)
	t.Run("session-selectors", testPostgresSessionSelectors)
	t.Run("selected-session-revocation", testPostgresSelectedSession)
	t.Run("concurrent-selected-session-revocation", testPostgresConcurrentSelectedSession)
	t.Run("selected-session-after-lock-wait", testPostgresSelectedSessionWait)
	t.Run("selected-session-rollback", testPostgresSelectedSessionRollback)
	t.Run("session-scoped-sign-out", testPostgresAllSessions)
	t.Run("concurrent-session-scoped-sign-out", testPostgresConcurrentAllSessions)
	t.Run("sign-out-after-lock-wait", testPostgresAllSessionsWait)
	t.Run("sign-out-rollback", testPostgresAllSessionsRollback)
	t.Run("session-scoped-disable", testPostgresSessionDisable)
	t.Run("concurrent-session-scoped-disable", testPostgresConcurrentSessionDisable)
	t.Run("session-disable-after-lock-wait", testPostgresSessionDisableWait)
	t.Run("session-disable-rollback", testPostgresSessionDisableRollback)
	t.Run("inventory-after-lock-wait", testPostgresInventoryWait)
	t.Run("revoke-other-sessions", testPostgresRevokeOthers)
	t.Run("concurrent-revoke-other-sessions", testPostgresConcurrentRevokeOthers)
	t.Run("revoke-others-after-lock-wait", testPostgresRevokeOthersWait)
	t.Run("revoke-others-cancellation-and-rollback", testPostgresRevokeOthersRollback)
}

func testPostgresRevokeOthers(t *testing.T) {
	store, pool := testStore(t)
	id, other := newAccount(t, store), newAccount(t, store)
	token, original := startSession(t, store, id)
	otherToken, otherSession := startSession(t, store, other)
	before := bytes.Clone(token)
	defer clear(before)
	var siblings [][]byte
	for range MaxSessionsPerAccount - 1 {
		sibling, _ := startSession(t, store, id)
		siblings = append(siblings, sibling)
	}
	// Removing siblings must work even with excess restored/direct-SQL rows,
	// expired references, and nonfuture-policy violations.
	for _, offset := range []time.Duration{-2 * time.Hour, time.Hour, -time.Minute} {
		sibling, _ := syntheticSession(t, pool, id, offset, time.Hour)
		siblings = append(siblings, sibling)
	}
	if count, err := store.RevokeOtherSessions(t.Context(), token); err != nil || count != int64(len(siblings)) || !bytes.Equal(before, token) {
		t.Fatal("sibling revocation returned wrong count or changed bearer")
	}
	if current, err := store.Resolve(t.Context(), token); err != nil || current != original {
		t.Fatal("sibling revocation changed the current token, owner, or expiry")
	}
	for _, sibling := range siblings {
		if _, err := store.Resolve(t.Context(), sibling); !errors.Is(err, ErrUnavailable) {
			t.Fatal("sibling remained usable")
		}
		digest, _ := tokenDigest(sibling)
		var exists bool
		if err := pool.QueryRow(t.Context(), "SELECT EXISTS (SELECT 1 FROM anonce.account_sessions WHERE token_digest=$1)", digest[:]).Scan(&exists); err != nil || exists {
			t.Fatal("sibling reference was not removed")
		}
	}
	if current, err := store.Resolve(t.Context(), otherToken); err != nil || current != otherSession {
		t.Fatal("sibling revocation changed another account")
	}
	if count, err := store.RevokeOtherSessions(t.Context(), token); err != nil || count != 0 {
		t.Fatal("repeated sibling revocation was not idempotent")
	}
	// A separately authenticated start ordered later is allowed and can be seen.
	startSession(t, store, id)
	if entries, err := store.ListSessions(t.Context(), token); err != nil || len(entries) != 2 {
		t.Fatal("sibling revocation prevented a later authenticated start")
	}
	for _, state := range []string{"malformed", "unknown", "expired", "future", "revoked", "disabled", "old", "boundary"} {
		t.Run(state, func(t *testing.T) {
			owner := newAccount(t, store)
			candidate, _ := startSession(t, store, owner)
			sibling, _ := startSession(t, store, owner)
			want := ErrUnavailable
			switch state {
			case "malformed":
				candidate = candidate[:TokenSize-1]
			case "unknown":
				candidate = make([]byte, TokenSize)
				rand.Read(candidate)
				defer clear(candidate)
			case "expired":
				candidate, _ = syntheticSession(t, pool, owner, -2*time.Hour, time.Hour)
			case "future":
				candidate, _ = syntheticSession(t, pool, owner, time.Hour, time.Hour)
			case "revoked":
				if err := store.Revoke(t.Context(), candidate); err != nil {
					t.Fatal("revoke sibling-management bearer")
				}
			case "disabled":
				// Keep references to prove the authorization gate precedes deletion.
				if _, err := pool.Exec(t.Context(), "UPDATE anonce.accounts SET state='disabled',disabled_at=statement_timestamp() WHERE id=$1", owner[:]); err != nil {
					t.Fatal("disable sibling-management owner")
				}
			case "old", "boundary":
				offset := -RecentAuthenticationWindow
				if state == "old" {
					offset -= time.Second
				}
				candidate, _ = syntheticSession(t, pool, owner, offset, time.Hour)
				want = ErrReauthenticationRequired
			}
			var beforeCount int
			if err := pool.QueryRow(t.Context(), "SELECT count(*) FROM anonce.account_sessions WHERE account_id=$1", owner[:]).Scan(&beforeCount); err != nil {
				t.Fatal("count sessions before denied revocation")
			}
			if count, err := store.RevokeOtherSessions(t.Context(), candidate); count != 0 || !errors.Is(err, want) {
				t.Fatal("invalid or old bearer revoked siblings or exposed count")
			}
			var afterCount int
			if err := pool.QueryRow(t.Context(), "SELECT count(*) FROM anonce.account_sessions WHERE account_id=$1", owner[:]).Scan(&afterCount); err != nil || afterCount != beforeCount {
				t.Fatal("denied sibling revocation changed references")
			}
			if state == "old" || state == "boundary" {
				if entries, err := store.ListSessions(t.Context(), candidate); err != nil || len(entries) != beforeCount {
					t.Fatal("authentication age denied inventory")
				}
				fresh, rotated, err := store.RotateSession(t.Context(), owner, candidate)
				if err != nil {
					t.Fatal("rotate after caller-verified reauthentication")
				}
				defer clear(fresh)
				if count, err := store.RevokeOtherSessions(t.Context(), fresh); err != nil || count != int64(beforeCount-1) {
					t.Fatal("reauthenticated bearer could not revoke siblings")
				}
				if current, err := store.Resolve(t.Context(), fresh); err != nil || current != rotated {
					t.Fatal("sibling revocation changed reauthenticated session")
				}
				if _, err := store.Resolve(t.Context(), sibling); !errors.Is(err, ErrUnavailable) {
					t.Fatal("reauthenticated sibling revocation retained a sibling")
				}
			}
		})
	}
	nearOwner := newAccount(t, store)
	near, admitted := syntheticSession(t, pool, nearOwner, -RecentAuthenticationWindow+30*time.Second, time.Hour)
	startSession(t, store, nearOwner)
	if count, err := store.RevokeOtherSessions(t.Context(), near); err != nil || count != 1 {
		t.Fatal("recent near-boundary session could not revoke siblings")
	}
	if current, err := store.Resolve(t.Context(), near); err != nil || current != admitted {
		t.Fatal("near-boundary sibling revocation changed current session")
	}
	pool.Close()
	if count, err := store.RevokeOtherSessions(t.Context(), token); count != 0 || err == nil || bytes.Contains([]byte(err.Error()), []byte("postgres")) {
		t.Fatal("closed sibling-revocation pool returned count or driver details")
	}
}

func testPostgresConcurrentRevokeOthers(t *testing.T) {
	store, _ := testStore(t)
	peer, _ := testStore(t)
	for _, operation := range []string{"same-bearer", "competing-bearers", "sibling-rotation", "revoke-all", "disable"} {
		t.Run(operation, func(t *testing.T) {
			id := newAccount(t, store)
			token, _ := startSession(t, store, id)
			sibling, _ := startSession(t, store, id)
			gate := make(chan struct{})
			counts := make(chan int64, 2)
			var wg sync.WaitGroup
			wg.Go(func() {
				<-gate
				count, err := store.RevokeOtherSessions(t.Context(), token)
				if err != nil && (!errors.Is(err, ErrUnavailable) || operation == "same-bearer" || operation == "sibling-rotation") {
					t.Error("concurrent sibling revocation failed unexpectedly")
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
					count, err := peer.RevokeOtherSessions(t.Context(), bearer)
					if err != nil && (!errors.Is(err, ErrUnavailable) || operation == "same-bearer") {
						t.Error("peer sibling revocation failed unexpectedly")
					}
					counts <- count
				case "sibling-rotation":
					fresh, _, err := peer.RotateSession(t.Context(), id, sibling)
					defer clear(fresh)
					if err != nil && !errors.Is(err, ErrUnavailable) {
						t.Error("sibling rotation failed unexpectedly")
					}
				case "revoke-all":
					if err := peer.RevokeAll(t.Context(), id); err != nil {
						t.Error("competing revoke-all failed")
					}
				case "disable":
					if err := peer.Disable(t.Context(), id); err != nil {
						t.Error("competing disable failed")
					}
				}
			})
			close(gate)
			wg.Wait()
			close(counts)
			var total int64
			for count := range counts {
				total += count
			}
			if operation == "revoke-all" || operation == "disable" {
				if _, err := store.Resolve(t.Context(), token); !errors.Is(err, ErrUnavailable) {
					t.Fatal("current session survived account invalidation")
				}
			} else {
				bearer := token
				if _, err := store.Resolve(t.Context(), token); errors.Is(err, ErrUnavailable) && operation == "competing-bearers" {
					bearer = sibling
				}
				if entries, err := store.ListSessions(t.Context(), bearer); err != nil || len(entries) != 1 || !entries[0].Current || total != 1 {
					t.Fatal("competing operations did not leave exactly one current session")
				}
			}
		})
	}
}

func testPostgresRevokeOthersWait(t *testing.T) {
	store, pool := testStore(t)
	for _, operation := range []string{"expiry", "age", "revocation", "insertion", "disable", "cancellation"} {
		t.Run(operation, func(t *testing.T) {
			id := newAccount(t, store)
			var token []byte
			var session Session
			if operation == "age" {
				token, session = syntheticSession(t, pool, id, -RecentAuthenticationWindow+time.Second, time.Hour)
			} else {
				lifetime := MaxLifetime
				if operation == "expiry" {
					lifetime = time.Second
				}
				var err error
				token, session, err = store.StartSession(t.Context(), id, lifetime)
				if err != nil {
					t.Fatal("prepare queued sibling revocation")
				}
				defer clear(token)
			}
			startSession(t, store, id)
			tx, err := pool.Begin(t.Context())
			if err != nil {
				t.Fatal("begin sibling revocation lock")
			}
			defer func() { _ = tx.Rollback(t.Context()) }()
			if err := lockAccount(t.Context(), tx, id, true); err != nil {
				t.Fatal("hold sibling revocation account lock")
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				count, err := store.RevokeOtherSessions(ctx, token)
				if err != nil && count != 0 || err == nil && count != 2 {
					t.Error("queued sibling revocation returned unexpected count")
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
				_, err = pool.Exec(t.Context(), "SELECT pg_sleep(GREATEST(0, EXTRACT(EPOCH FROM ($1::timestamptz - clock_timestamp()))) + 0.05)", deadline)
			case "revocation":
				digest, _ := tokenDigest(token)
				_, err = tx.Exec(t.Context(), "DELETE FROM anonce.account_sessions WHERE token_digest=$1", digest[:])
				remaining = 1
			case "insertion":
				next := make([]byte, TokenSize)
				rand.Read(next)
				digest, _ := tokenDigest(next)
				clear(next)
				_, err = tx.Exec(t.Context(), `INSERT INTO anonce.account_sessions(token_digest,account_id,expires_at)
                    VALUES ($1,$2,statement_timestamp()+interval '1 hour')`, digest[:], id[:])
				want, remaining = nil, 1
			case "disable":
				_, err = tx.Exec(t.Context(), "UPDATE anonce.accounts SET state='disabled',disabled_at=statement_timestamp() WHERE id=$1", id[:])
			case "cancellation":
				cancel()
				if err := <-done; !errors.Is(err, context.Canceled) {
					t.Fatal("queued sibling revocation lost cancellation")
				}
			}
			if err != nil {
				t.Fatal("prepare post-lock sibling revocation state")
			}
			if err := tx.Commit(t.Context()); err != nil {
				t.Fatal("release sibling revocation account lock")
			}
			if operation != "cancellation" {
				if err := <-done; !errors.Is(err, want) {
					t.Fatal("sibling revocation ignored post-lock state or authentication age")
				}
			}
			var count int
			if err := pool.QueryRow(t.Context(), "SELECT count(*) FROM anonce.account_sessions WHERE account_id=$1", id[:]).Scan(&count); err != nil || count != remaining {
				t.Fatal("queued sibling revocation left unexpected references")
			}
		})
	}
}

func testPostgresRevokeOthersRollback(t *testing.T) {
	store, pool := testStore(t)
	id := newAccount(t, store)
	token, original := startSession(t, store, id)
	var siblings [][]byte
	for range 3 {
		sibling, _ := startSession(t, store, id)
		siblings = append(siblings, sibling)
	}
	digest, _ := tokenDigest(siblings[1])
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal("begin sibling row lock")
	}
	defer func() { _ = tx.Rollback(t.Context()) }()
	if _, err := tx.Exec(t.Context(), "DELETE FROM anonce.account_sessions WHERE token_digest=$1", digest[:]); err != nil {
		t.Fatal("hold sibling row lock")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	if count, err := store.RevokeOtherSessions(ctx, token); count != 0 || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("blocked sibling deletion returned count or lost cancellation")
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal("release sibling row lock")
	}
	// Listing takes the same account lock, waiting for the cancelled transaction
	// to roll back any earlier sibling deletions before verifying the full set.
	if entries, err := store.ListSessions(t.Context(), token); err != nil || len(entries) != len(siblings)+1 {
		t.Fatal("cancelled sibling revocation partially committed")
	}
	for _, sibling := range siblings {
		if _, err := store.Resolve(t.Context(), sibling); err != nil {
			t.Fatal("cancelled sibling revocation removed a session")
		}
	}
	if current, err := store.Resolve(t.Context(), token); err != nil || current != original {
		t.Fatal("cancelled sibling revocation changed current session")
	}
}

func testPostgresSessionInventory(t *testing.T) {
	store, pool := testStore(t)
	id, other := newAccount(t, store), newAccount(t, store)
	oldToken, old := syntheticSession(t, pool, id, -time.Hour, 2*time.Hour)
	token, current := startSession(t, store, id)
	startSession(t, store, other)
	syntheticSession(t, pool, id, -2*time.Hour, time.Hour)
	future, _ := syntheticSession(t, pool, id, time.Hour, time.Hour)
	before := bytes.Clone(token)
	defer clear(before)
	for _, bearer := range [][]byte{token, oldToken} {
		entries, err := store.ListSessions(t.Context(), bearer)
		if err != nil || len(entries) != 2 || entries[0] != (SessionInfo{sessionSelector(t, pool, token), current.CreatedAt, current.ExpiresAt, bytes.Equal(bearer, token)}) ||
			entries[1] != (SessionInfo{sessionSelector(t, pool, oldToken), old.CreatedAt, old.ExpiresAt, bytes.Equal(bearer, oldToken)}) || !bytes.Equal(token, before) {
			t.Fatal("inventory exposed another owner, invalid row, or wrong metadata")
		}
		entries[0] = SessionInfo{}
	}
	for _, state := range []string{"malformed", "unknown", "expired", "future", "revoked", "disabled"} {
		t.Run(state, func(t *testing.T) {
			owner := newAccount(t, store)
			candidate := make([]byte, TokenSize)
			rand.Read(candidate)
			defer clear(candidate)
			switch state {
			case "malformed":
				candidate = candidate[:TokenSize-1]
			case "expired":
				candidate, _ = syntheticSession(t, pool, owner, -2*time.Hour, time.Hour)
			case "future":
				candidate = future
			case "revoked", "disabled":
				candidate, _ = startSession(t, store, owner)
				var err error
				if state == "revoked" {
					err = store.Revoke(t.Context(), candidate)
				} else {
					err = store.Disable(t.Context(), owner)
				}
				if err != nil {
					t.Fatal("invalidate inventory bearer")
				}
			}
			if entries, err := store.ListSessions(t.Context(), candidate); entries != nil || !errors.Is(err, ErrUnavailable) {
				t.Fatal("inventory returned metadata to an invalid bearer")
			}
		})
	}
	// Direct SQL and restored data can exceed the package's admission limit.
	for range MaxSessionsPerAccount - 2 {
		syntheticSession(t, pool, id, -time.Minute, time.Hour)
	}
	if entries, err := store.ListSessions(t.Context(), token); err != nil || len(entries) != MaxSessionsPerAccount {
		t.Fatal("inventory rejected exact capacity")
	}
	syntheticSession(t, pool, id, -time.Minute, time.Hour)
	if entries, err := store.ListSessions(t.Context(), token); entries != nil || !errors.Is(err, ErrSessionLimit) {
		t.Fatal("over-capacity inventory returned a partial list")
	}
	if _, err := store.Resolve(t.Context(), token); err != nil {
		t.Fatal("inventory denial changed current session")
	}
	pool.Close()
	if entries, err := store.ListSessions(t.Context(), token); entries != nil || err == nil || bytes.Contains([]byte(err.Error()), []byte("postgres")) {
		t.Fatal("closed inventory pool returned metadata or driver details")
	}
}

func syntheticSession(t *testing.T, pool *pgxpool.Pool, owner ID, offset, lifetime time.Duration) ([]byte, Session) {
	t.Helper()
	token := make([]byte, TokenSize)
	rand.Read(token)
	t.Cleanup(func() { clear(token) })
	digest, _ := tokenDigest(token)
	session := Session{AccountID: owner}
	err := pool.QueryRow(t.Context(), `INSERT INTO anonce.account_sessions(token_digest,account_id,created_at,expires_at)
        VALUES ($1,$2,statement_timestamp()+$3*interval '1 second',statement_timestamp()+$4*interval '1 second')
        RETURNING created_at, expires_at`, digest[:], owner[:], int64(offset/time.Second), int64((offset+lifetime)/time.Second)).Scan(&session.CreatedAt, &session.ExpiresAt)
	if err != nil {
		t.Fatal("insert synthetic session metadata")
	}
	return token, session
}

func sessionSelector(t *testing.T, pool *pgxpool.Pool, token []byte) SessionID {
	t.Helper()
	digest, _ := tokenDigest(token)
	var id pgtype.UUID
	if err := pool.QueryRow(t.Context(), "SELECT session_id FROM anonce.account_sessions WHERE token_digest=$1", digest[:]).Scan(&id); err != nil || !id.Valid || id.Bytes == ([16]byte{}) {
		t.Fatal("read session selector")
	}
	return SessionID(id.Bytes)
}

func testPostgresSessionSelectors(t *testing.T) {
	store, pool := testStore(t)
	owner := newAccount(t, store)
	token, original := startSession(t, store, owner)
	sibling, _ := startSession(t, store, owner)
	currentID, siblingID := sessionSelector(t, pool, token), sessionSelector(t, pool, sibling)
	if currentID == siblingID {
		t.Fatal("independent sessions share a selector")
	}
	for _, bearer := range [][]byte{token, sibling} {
		entries, err := store.ListSessions(t.Context(), bearer)
		if err != nil || len(entries) != 2 || entries[0].ID != siblingID || entries[1].ID != currentID {
			t.Fatal("inventory selectors are unstable or bearer-dependent")
		}
	}
	for _, selector := range []SessionID{currentID, siblingID} {
		// Neither the selector bytes nor a token-sized padded selector authorize.
		for _, size := range []int{len(selector), TokenSize} {
			candidate := make([]byte, size)
			copy(candidate, selector[:])
			if _, err := store.Resolve(t.Context(), candidate); !errors.Is(err, ErrUnavailable) {
				t.Fatal("selector resolved as a credential")
			}
			if entries, err := store.ListSessions(t.Context(), candidate); entries != nil || !errors.Is(err, ErrUnavailable) {
				t.Fatal("selector authorized inventory")
			}
		}
	}
	for _, tc := range []struct{ value, state string }{
		{"NULL", "23502"},
		{"'00000000-0000-0000-0000-000000000000'::uuid", "23514"},
		{"(SELECT session_id FROM anonce.account_sessions LIMIT 1)", "23505"},
	} {
		_, err := pool.Exec(t.Context(), `INSERT INTO anonce.account_sessions(token_digest,account_id,expires_at,session_id)
            VALUES (decode(repeat('ac',32),'hex'),$1,statement_timestamp()+interval '1 hour',`+tc.value+`)`, owner[:])
		pgerr, ok := errors.AsType[*pgconn.PgError](err)
		if !ok || pgerr.Code != tc.state {
			t.Fatal("invalid or duplicate selector admitted")
		}
	}
	if _, err := pool.Exec(t.Context(), "UPDATE anonce.account_sessions SET session_id=gen_random_uuid()"); err == nil {
		t.Fatal("runtime can change existing selectors")
	}
	fresh, rotated, err := store.RotateSession(t.Context(), owner, token)
	if err != nil || rotated.ExpiresAt != original.ExpiresAt {
		t.Fatal("rotate selector session")
	}
	defer clear(fresh)
	if next := sessionSelector(t, pool, fresh); next == currentID || next == siblingID || sessionSelector(t, pool, sibling) != siblingID {
		t.Fatal("rotation reused a selector or changed a sibling")
	}
	var exists bool
	if err := pool.QueryRow(t.Context(), "SELECT EXISTS (SELECT 1 FROM anonce.account_sessions WHERE session_id=$1)", pgtype.UUID{Bytes: currentID, Valid: true}).Scan(&exists); err != nil || exists {
		t.Fatal("rotation retained the old selector")
	}
}

func testPostgresInventoryWait(t *testing.T) {
	store, pool := testStore(t)
	for _, operation := range []string{"expiry", "revocation", "rotation", "disable", "insertion", "cancellation"} {
		t.Run(operation, func(t *testing.T) {
			id := newAccount(t, store)
			lifetime := MaxLifetime
			if operation == "expiry" {
				lifetime = time.Second
			}
			token, session, err := store.StartSession(t.Context(), id, lifetime)
			if err != nil {
				t.Fatal("prepare inventory lock wait")
			}
			defer clear(token)
			digest, _ := tokenDigest(token)
			tx, err := pool.Begin(t.Context())
			if err != nil {
				t.Fatal("begin inventory lock")
			}
			defer func() { _ = tx.Rollback(t.Context()) }()
			if err := lockAccount(t.Context(), tx, id, true); err != nil {
				t.Fatal("hold inventory account lock")
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				entries, err := store.ListSessions(ctx, token)
				if err != nil && entries != nil || err == nil && (len(entries) != 2 || !entries[1].Current) {
					t.Error("queued inventory returned unexpected metadata")
				}
				done <- err
			}()
			waitForBlockedStart(t, pool, tx.Conn().PgConn().PID())
			want := ErrUnavailable
			switch operation {
			case "expiry":
				_, err = pool.Exec(t.Context(), "SELECT pg_sleep(GREATEST(0, EXTRACT(EPOCH FROM ($1::timestamptz - clock_timestamp()))) + 0.05)", session.ExpiresAt)
			case "revocation", "rotation":
				_, err = tx.Exec(t.Context(), "DELETE FROM anonce.account_sessions WHERE token_digest=$1", digest[:])
				if err == nil && operation == "rotation" {
					next := make([]byte, TokenSize)
					rand.Read(next)
					replacement, _ := tokenDigest(next)
					clear(next)
					_, err = tx.Exec(t.Context(), `INSERT INTO anonce.account_sessions(token_digest, account_id, expires_at)
                        VALUES ($1,$2,$3)`, replacement[:], id[:], session.ExpiresAt)
				}
			case "disable":
				_, err = tx.Exec(t.Context(), "UPDATE anonce.accounts SET state='disabled',disabled_at=statement_timestamp() WHERE id=$1", id[:])
			case "insertion":
				next := make([]byte, TokenSize)
				rand.Read(next)
				sibling, _ := tokenDigest(next)
				clear(next)
				_, err = tx.Exec(t.Context(), `INSERT INTO anonce.account_sessions(token_digest,account_id,expires_at)
                    VALUES ($1,$2,statement_timestamp()+interval '1 hour')`, sibling[:], id[:])
				want = nil
			case "cancellation":
				cancel()
				if err := <-done; !errors.Is(err, context.Canceled) {
					t.Fatal("inventory lost blocked cancellation")
				}
			}
			if err != nil {
				t.Fatal("prepare post-lock inventory state")
			}
			if err := tx.Commit(t.Context()); err != nil {
				t.Fatal("release inventory lock")
			}
			if operation != "cancellation" {
				if err := <-done; !errors.Is(err, want) {
					t.Fatal("inventory ignored post-lock authorization or state")
				}
			}
		})
	}
}

func testPostgresSessionLimit(t *testing.T) {
	store, pool := testStore(t)
	id := newAccount(t, store)
	var tokens [][]byte
	for range MaxSessionsPerAccount {
		token, _ := startSession(t, store, id)
		tokens = append(tokens, token)
	}
	for range 2 {
		if token, session, err := store.StartSession(t.Context(), id, time.Minute); token != nil || session != (Session{}) || !errors.Is(err, ErrSessionLimit) {
			t.Fatal("full account admitted a session or returned material")
		}
	}
	for _, token := range tokens {
		if _, err := store.Resolve(t.Context(), token); err != nil {
			t.Fatal("limit denial evicted an existing session")
		}
	}
	other := newAccount(t, store)
	otherToken, _ := startSession(t, store, other)
	// Rotation replaces one row, so it must remain available at capacity.
	fresh, _, err := store.RotateSession(t.Context(), id, tokens[0])
	if err != nil || len(fresh) != TokenSize {
		t.Fatal("rotation denied at capacity")
	}
	defer clear(fresh)
	if err := store.Revoke(t.Context(), fresh); err != nil {
		t.Fatal("revoke at capacity")
	}
	startSession(t, store, id)
	if err := store.RevokeAll(t.Context(), id); err != nil {
		t.Fatal("revoke-all at capacity")
	}
	startSession(t, store, id)
	if _, err := store.Resolve(t.Context(), otherToken); err != nil {
		t.Fatal("session admission changed another account")
	}
	// Runtime SQL can bypass this package policy. Existing excess rows must deny
	// new starts without eviction; the policy is not a schema constraint.
	for range MaxSessionsPerAccount {
		token := make([]byte, TokenSize)
		rand.Read(token)
		digest, _ := tokenDigest(token)
		clear(token)
		if _, err := pool.Exec(t.Context(), `INSERT INTO anonce.account_sessions(token_digest, account_id, expires_at)
            VALUES ($1,$2,statement_timestamp()+interval '1 hour')`, digest[:], id[:]); err != nil {
			t.Fatal("insert synthetic excess session")
		}
	}
	if token, session, err := store.StartSession(t.Context(), id, time.Minute); token != nil || session != (Session{}) || !errors.Is(err, ErrSessionLimit) {
		t.Fatal("over-capacity account admitted a new session")
	}
	var count int
	if err := pool.QueryRow(t.Context(), "SELECT count(*) FROM anonce.account_sessions WHERE account_id=$1", id[:]).Scan(&count); err != nil || count != MaxSessionsPerAccount+1 {
		t.Fatal("over-capacity denial changed existing sessions")
	}
	if err := store.Disable(t.Context(), id); err != nil {
		t.Fatal("disable over-capacity account")
	}
	if token, session, err := store.StartSession(t.Context(), id, time.Minute); token != nil || session != (Session{}) || !errors.Is(err, ErrUnavailable) {
		t.Fatal("disabled account exposed admission state")
	}
}

func testPostgresConcurrentSessionLimit(t *testing.T) {
	store, pool := testStore(t)
	peer, _ := testStore(t)
	id := newAccount(t, store)
	gate := make(chan struct{})
	results := make(chan []byte, 2*MaxSessionsPerAccount)
	var wg sync.WaitGroup
	for i := range 2 * MaxSessionsPerAccount {
		caller := store
		if i%2 != 0 {
			caller = peer
		}
		wg.Go(func() {
			<-gate
			token, session, err := caller.StartSession(t.Context(), id, MaxLifetime)
			if err == nil {
				if len(token) != TokenSize || session.AccountID != id {
					t.Error("concurrent start returned invalid material")
				}
				results <- token
			} else if !errors.Is(err, ErrSessionLimit) || token != nil || session != (Session{}) {
				t.Error("concurrent start failed unexpectedly")
			}
		})
	}
	close(gate)
	wg.Wait()
	close(results)
	successes := 0
	for token := range results {
		if _, err := store.Resolve(t.Context(), token); err != nil {
			t.Error("admitted session unavailable after competing starts")
		}
		clear(token)
		successes++
	}
	var count int
	if err := pool.QueryRow(t.Context(), "SELECT count(*) FROM anonce.account_sessions WHERE account_id=$1", id[:]).Scan(&count); err != nil || count != MaxSessionsPerAccount || successes != MaxSessionsPerAccount {
		t.Fatal("concurrent starts exceeded or underfilled account capacity")
	}
}

func testPostgresSessionLimitWait(t *testing.T) {
	store, pool := testStore(t)
	for _, operation := range []string{"expiry", "revocation", "insertion", "disable", "cancellation"} {
		t.Run(operation, func(t *testing.T) {
			id := newAccount(t, store)
			for range MaxSessionsPerAccount - 1 {
				startSession(t, store, id)
			}
			var token []byte
			var session Session
			if operation != "insertion" {
				lifetime := MaxLifetime
				if operation == "expiry" {
					lifetime = time.Second
				}
				var err error
				token, session, err = store.StartSession(t.Context(), id, lifetime)
				if err != nil {
					t.Fatal("prepare session limit wait")
				}
				defer clear(token)
			}
			tx, err := pool.Begin(t.Context())
			if err != nil {
				t.Fatal("begin session limit lock")
			}
			defer func() { _ = tx.Rollback(t.Context()) }()
			if err := lockAccount(t.Context(), tx, id, true); err != nil {
				t.Fatal("hold session limit lock")
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				fresh, result, err := store.StartSession(ctx, id, MaxLifetime)
				defer clear(fresh)
				if err != nil && (fresh != nil || result != (Session{})) {
					t.Error("denied queued session returned material")
				}
				done <- err
			}()
			waitForBlockedStart(t, pool, tx.Conn().PgConn().PID())
			want := error(nil)
			count := MaxSessionsPerAccount
			switch operation {
			case "expiry":
				_, err = pool.Exec(t.Context(), "SELECT pg_sleep(GREATEST(0, EXTRACT(EPOCH FROM ($1::timestamptz - clock_timestamp()))) + 0.05)", session.ExpiresAt)
			case "revocation":
				digest, _ := tokenDigest(token)
				_, err = tx.Exec(t.Context(), "DELETE FROM anonce.account_sessions WHERE token_digest=$1", digest[:])
			case "insertion":
				secret := make([]byte, TokenSize)
				rand.Read(secret)
				digest, _ := tokenDigest(secret)
				clear(secret)
				_, err = tx.Exec(t.Context(), `INSERT INTO anonce.account_sessions(token_digest, account_id, expires_at)
                    VALUES ($1,$2,statement_timestamp()+interval '1 hour')`, digest[:], id[:])
				want = ErrSessionLimit
			case "disable":
				_, err = tx.Exec(t.Context(), "UPDATE anonce.accounts SET state='disabled', disabled_at=statement_timestamp() WHERE id=$1", id[:])
				if err == nil {
					_, err = tx.Exec(t.Context(), "DELETE FROM anonce.account_sessions WHERE account_id=$1", id[:])
				}
				want, count = ErrUnavailable, 0
			case "cancellation":
				cancel()
				if err := <-done; !errors.Is(err, context.Canceled) {
					t.Fatal("blocked limit check lost cancellation")
				}
			}
			if err != nil {
				t.Fatal("prepare committed session limit change")
			}
			if err := tx.Commit(t.Context()); err != nil {
				t.Fatal("release session limit lock")
			}
			if operation != "cancellation" {
				if err := <-done; !errors.Is(err, want) {
					t.Fatal("session admission did not observe post-lock state")
				}
			}
			var got int
			if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM anonce.account_sessions
                WHERE account_id=$1 AND expires_at>statement_timestamp()`, id[:]).Scan(&got); err != nil || got != count {
				t.Fatal("queued admission left unexpected live sessions")
			}
		})
	}
}

func waitForBlockedStart(t *testing.T, pool *pgxpool.Pool, blocker uint32) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var blocked bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_stat_activity
            WHERE usename=current_user AND $1::integer=ANY(pg_blocking_pids(pid)))`, int64(blocker)).Scan(&blocked); err != nil {
			t.Fatal("observe queued session start")
		}
		if blocked {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("session start did not reach account lock")
		case <-ticker.C:
		}
	}
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
			switch state {
			case "unknown", "expired", "future":
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
			case "revoked", "disabled":
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
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM information_schema.columns WHERE table_schema='anonce' AND table_name='account_sessions'`).Scan(&count); err != nil || count != 5 {
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

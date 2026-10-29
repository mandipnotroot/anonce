// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

//go:build databaseintegration

package memberbackup

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"math"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/mandipnotroot/anonce/internal/client/memberkey"
	"github.com/mandipnotroot/anonce/internal/identity/accounts"
)

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

func testStores(t *testing.T) (*Store, *accounts.Store, *pgxpool.Pool) {
	t.Helper()
	pool := testPool(t)
	store, err := New(t.Context(), pool)
	if err != nil {
		t.Fatal("admit member backup store")
	}
	accountStore, err := accounts.New(t.Context(), pool)
	if err != nil {
		t.Fatal("admit account store")
	}
	return store, accountStore, pool
}

func newOwner(t *testing.T, store *accounts.Store) accounts.ID {
	t.Helper()
	id, err := store.Create(t.Context())
	if err != nil {
		t.Fatal("create test owner")
	}
	return id
}

func TestPostgresMemberBackups(t *testing.T) {
	if os.Getenv("ANONCE_TEST_SIDE") == "submission" {
		if store, err := New(t.Context(), testPool(t)); err == nil || store != nil {
			t.Fatal("submission database admitted")
		}
		return
	}
	t.Run("lifecycle-and-owner-scope", testPostgresLifecycle)
	t.Run("constraints-and-grants", testPostgresConstraints)
	t.Run("concurrent-writes", testPostgresConcurrentWrites)
	t.Run("concurrent-disable", testPostgresConcurrentDisable)
	t.Run("cancellation-and-rollback", testPostgresCancellation)
	t.Run("revision-exhaustion", testPostgresRevisionExhaustion)
	t.Run("session-owner-scope", testPostgresSessionScope)
	t.Run("session-invalidation", testPostgresSessionInvalidation)
	t.Run("session-lock-order-and-cancellation", testPostgresSessionLocking)
	t.Run("session-expiry-after-lock-wait", testPostgresSessionExpiryWait)
	t.Run("session-revocation-after-lock-wait", testPostgresSessionRevocationWait)
	t.Run("session-recent-authentication", testPostgresSessionRecentAuthentication)
	t.Run("session-authentication-age-after-lock-wait", testPostgresSessionAuthenticationWait)
	t.Run("session-rotation-after-lock-wait", testPostgresSessionRotationWait)
}

func agedSession(t *testing.T, pool *pgxpool.Pool, owner accounts.ID, age time.Duration) []byte {
	t.Helper()
	token := make([]byte, accounts.TokenSize)
	rand.Read(token)
	t.Cleanup(func() { clear(token) })
	digest := sha256.Sum256(token)
	_, err := pool.Exec(t.Context(), `INSERT INTO anonce.account_sessions(token_digest,account_id,created_at,expires_at)
        VALUES ($1,$2,statement_timestamp()-$3*interval '1 second',statement_timestamp()+interval '2 hours')`,
		digest[:], owner[:], int64(age/time.Second))
	if err != nil {
		t.Fatal("insert synthetic aged session")
	}
	return token
}

func testPostgresSessionRecentAuthentication(t *testing.T) {
	store, accountStore, pool := testStores(t)
	for _, tc := range []struct {
		name string
		age  time.Duration
		want error
	}{
		{"fresh", 0, nil},
		{"within-window", RecentAuthenticationWindow - 30*time.Second, nil},
		{"at-window", RecentAuthenticationWindow, ErrReauthenticationRequired},
		{"outside-window", RecentAuthenticationWindow + time.Second, ErrReauthenticationRequired},
		{"future", -time.Minute, ErrUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			owner := newOwner(t, accountStore)
			token := agedSession(t, pool, owner, tc.age)
			if revision, err := store.PutForSession(t.Context(), token, 0, make([]byte, 32), envelope()); tc.want != nil {
				if revision != 0 || !errors.Is(err, tc.want) {
					t.Fatal("creation age policy bypassed")
				}
				if _, err := store.Get(t.Context(), owner); !errors.Is(err, ErrUnavailable) {
					t.Fatal("denied creation persisted slot")
				}
				if _, err := store.Put(t.Context(), owner, 0, make([]byte, 32), envelope()); err != nil {
					t.Fatal("prepare authentication-age slot")
				}
			} else if err != nil || revision != 1 {
				t.Fatal("recent session creation failed")
			}
			if record, err := store.GetForSession(t.Context(), token); tc.age >= 0 && (err != nil || record.Revision != 1) || tc.age < 0 && (!errors.Is(err, ErrUnavailable) || record.Revision != 0) {
				t.Fatal("read incorrectly applied authentication-age policy")
			}
			for _, expected := range []int64{0, 1, 9} {
				revision, err := store.PutForSession(t.Context(), token, expected, make([]byte, 32), envelope())
				if tc.want != nil {
					if revision != 0 || !errors.Is(err, tc.want) {
						t.Fatal("write age policy bypassed or exposed revision conflict")
					}
				} else if expected == 1 {
					if revision != 2 || err != nil {
						t.Fatal("recent session replacement failed")
					}
				} else if revision != 0 || !errors.Is(err, ErrConflict) {
					t.Fatal("recent session bypassed revision policy")
				}
			}
			expected := int64(1)
			if tc.want == nil {
				expected = 2
			}
			revision, err := store.DeleteForSession(t.Context(), token, expected)
			if tc.want != nil {
				if revision != 0 || !errors.Is(err, tc.want) {
					t.Fatal("delete age policy bypassed")
				}
				if record, err := store.Get(t.Context(), owner); err != nil || record.Revision != 1 || !bytes.Equal(record.Backup, envelope()) {
					t.Fatal("denied mutations changed backup")
				}
			} else if err != nil || revision != 3 {
				t.Fatal("recent session deletion failed")
			}
			if errors.Is(tc.want, ErrReauthenticationRequired) {
				original, err := accountStore.Resolve(t.Context(), token)
				if err != nil {
					t.Fatal("aged session no longer live")
				}
				fresh, session, err := accountStore.RotateSession(t.Context(), owner, token)
				defer clear(fresh)
				if err != nil || session.ExpiresAt != original.ExpiresAt {
					t.Fatal("verified reauthentication rotation failed")
				}
				deniedSession(t, store, token)
				if revision, err := store.PutForSession(t.Context(), fresh, 1, make([]byte, 32), envelope()); err != nil || revision != 2 {
					t.Fatal("rotated session could not replace backup")
				}
				if revision, err := store.DeleteForSession(t.Context(), fresh, 2); err != nil || revision != 3 {
					t.Fatal("rotated session could not delete backup")
				}
			}
		})
	}
}

func testPostgresSessionAuthenticationWait(t *testing.T) {
	store, accountStore, pool := testStores(t)
	for _, operation := range []string{"put", "delete"} {
		t.Run(operation, func(t *testing.T) {
			owner := newOwner(t, accountStore)
			token := agedSession(t, pool, owner, RecentAuthenticationWindow-time.Second)
			session, err := accountStore.Resolve(t.Context(), token)
			if err != nil {
				t.Fatal("resolve near-boundary session")
			}
			if _, err := store.Put(t.Context(), owner, 0, make([]byte, 32), envelope()); err != nil {
				t.Fatal("prepare queued authentication slot")
			}
			tx, err := pool.Begin(t.Context())
			if err != nil {
				t.Fatal("begin authentication-age lock")
			}
			defer func() { _ = tx.Rollback(t.Context()) }()
			if _, err := tx.Exec(t.Context(), "SELECT state FROM anonce.accounts WHERE id=$1 FOR UPDATE", owner[:]); err != nil {
				t.Fatal("hold authentication-age lock")
			}
			done := make(chan error, 1)
			go func() {
				var revision int64
				var err error
				if operation == "put" {
					revision, err = store.PutForSession(t.Context(), token, 1, make([]byte, 32), envelope())
				} else {
					revision, err = store.DeleteForSession(t.Context(), token, 1)
				}
				if revision != 0 {
					t.Error("aged queued mutation returned revision")
				}
				done <- err
			}()
			waitForBlockedAccess(t, pool, tx.Conn().PgConn().PID())
			if _, err := pool.Exec(t.Context(), "SELECT pg_sleep(GREATEST(0, EXTRACT(EPOCH FROM ($1::timestamptz - clock_timestamp()))) + 0.05)", session.CreatedAt.Add(RecentAuthenticationWindow)); err != nil {
				t.Fatal("wait for authentication-age boundary")
			}
			if err := tx.Rollback(t.Context()); err != nil {
				t.Fatal("release authentication-age lock")
			}
			if err := <-done; !errors.Is(err, ErrReauthenticationRequired) {
				t.Fatal("queued mutation ignored post-lock authentication age")
			}
			if record, err := store.GetForSession(t.Context(), token); err != nil || record.Revision != 1 {
				t.Fatal("aged session cannot read or denied mutation changed slot")
			}
		})
	}
}

func testPostgresSessionRotationWait(t *testing.T) {
	store, accountStore, pool := testStores(t)
	for _, invalidation := range []string{"revoke", "disable", "expiry"} {
		t.Run(invalidation, func(t *testing.T) {
			owner := newOwner(t, accountStore)
			lifetime := time.Minute
			if invalidation == "expiry" {
				lifetime = time.Second
			}
			token, session, err := accountStore.StartSession(t.Context(), owner, lifetime)
			if err != nil {
				t.Fatal("prepare queued rotation session")
			}
			defer clear(token)
			tx, err := pool.Begin(t.Context())
			if err != nil {
				t.Fatal("begin queued rotation lock")
			}
			defer func() { _ = tx.Rollback(t.Context()) }()
			if _, err := tx.Exec(t.Context(), "SELECT state FROM anonce.accounts WHERE id=$1 FOR UPDATE", owner[:]); err != nil {
				t.Fatal("hold queued rotation lock")
			}
			done := make(chan error, 1)
			go func() {
				fresh, session, err := accountStore.RotateSession(t.Context(), owner, token)
				if fresh != nil || session != (accounts.Session{}) {
					clear(fresh)
					t.Error("invalidated queued rotation returned material")
				}
				done <- err
			}()
			waitForBlockedAccess(t, pool, tx.Conn().PgConn().PID())
			if invalidation == "expiry" {
				if _, err := pool.Exec(t.Context(), "SELECT pg_sleep(GREATEST(0, EXTRACT(EPOCH FROM ($1::timestamptz - clock_timestamp()))) + 0.05)", session.ExpiresAt); err != nil {
					t.Fatal("wait for queued rotation expiry")
				}
			} else {
				if invalidation == "disable" {
					if _, err := tx.Exec(t.Context(), "UPDATE anonce.accounts SET state='disabled', disabled_at=statement_timestamp() WHERE id=$1", owner[:]); err != nil {
						t.Fatal("disable queued rotation account")
					}
				}
				digest := sha256.Sum256(token)
				if _, err := tx.Exec(t.Context(), "DELETE FROM anonce.account_sessions WHERE token_digest=$1", digest[:]); err != nil {
					t.Fatal("revoke queued rotation session")
				}
			}
			if err := tx.Commit(t.Context()); err != nil {
				t.Fatal("release queued rotation lock")
			}
			if err := <-done; !errors.Is(err, accounts.ErrUnavailable) {
				t.Fatal("queued rotation survived invalidation")
			}
			deniedSession(t, store, token)
		})
	}
}

func testPostgresLifecycle(t *testing.T) {
	store, accountStore, _ := testStores(t)
	first, second := newOwner(t, accountStore), newOwner(t, accountStore)
	key, err := memberkey.Generate(t.Context())
	if err != nil {
		t.Fatal("generate local test key")
	}
	defer clear(key)
	password := []byte("synthetic local unlock passphrase")
	defer clear(password)
	backup, err := memberkey.Seal(t.Context(), password, key)
	if err != nil {
		t.Fatal("seal local test key")
	}
	public := key[32:]
	original := bytes.Clone(backup)
	if _, err := store.Get(t.Context(), first); !errors.Is(err, ErrUnavailable) {
		t.Fatal("absent slot returned")
	}
	if revision, err := store.Put(t.Context(), first, 0, public, backup); err != nil || revision != 1 || !bytes.Equal(original, backup) {
		t.Fatal("create or input ownership differs")
	}
	if _, err := store.Get(t.Context(), second); !errors.Is(err, ErrUnavailable) {
		t.Fatal("other owner read first backup")
	}
	if _, err := store.Put(t.Context(), second, 1, public, backup); !errors.Is(err, ErrConflict) {
		t.Fatal("other owner replaced first backup")
	}
	if _, err := store.Delete(t.Context(), second, 1); !errors.Is(err, ErrConflict) {
		t.Fatal("other owner deleted first backup")
	}
	if _, err := store.Put(t.Context(), second, 0, public, backup); err != nil {
		t.Fatal("independent owner creation failed")
	}
	record, err := store.Get(t.Context(), first)
	if err != nil || record.Revision != 1 || !bytes.Equal(record.PublicKey[:], public) || !bytes.Equal(record.Backup, backup) {
		t.Fatal("stored backup differs")
	}
	restored, err := memberkey.Open(t.Context(), password, record.Backup)
	if err != nil {
		t.Fatal("restore persisted member backup")
	}
	defer clear(restored)
	if !bytes.Equal(restored, key) {
		t.Fatal("persisted key changed")
	}
	record.Backup[50] ^= 1
	fresh, err := store.Get(t.Context(), first)
	if err != nil || !bytes.Equal(fresh.Backup, backup) {
		t.Fatal("returned buffer aliases stored state")
	}
	otherPublic := bytes.Clone(public)
	otherPublic[0] ^= 1
	if _, err := store.Put(t.Context(), first, 1, otherPublic, backup); !errors.Is(err, ErrConflict) {
		t.Fatal("key rebinding admitted")
	}
	if _, err := store.Put(t.Context(), first, 0, public, backup); !errors.Is(err, ErrConflict) {
		t.Fatal("stale create admitted")
	}
	// Storage admits only the public envelope, not the encrypted payload. A
	// damaged ciphertext remains opaque and must fail device-side restoration.
	damaged := bytes.Clone(backup)
	damaged[50] ^= 1
	if revision, err := store.Put(t.Context(), first, 1, public, damaged); err != nil || revision != 2 {
		t.Fatal("bounded opaque replacement failed")
	}
	if revision, err := store.Delete(t.Context(), first, 2); err != nil || revision != 3 {
		t.Fatal("delete failed")
	}
	tombstone, err := store.Get(t.Context(), first)
	if err != nil || tombstone.Backup != nil || tombstone.Revision != 3 || !bytes.Equal(tombstone.PublicKey[:], public) {
		t.Fatal("deletion lost revision/binding or retained live ciphertext")
	}
	for _, expected := range []int64{0, 1, 2} {
		if _, err := store.Put(t.Context(), first, expected, public, backup); !errors.Is(err, ErrConflict) {
			t.Fatal("stale write resurrected deleted slot")
		}
	}
	if _, err := store.Delete(t.Context(), first, 3); !errors.Is(err, ErrConflict) {
		t.Fatal("deleted slot deleted twice")
	}
	if _, err := store.Put(t.Context(), first, 3, otherPublic, backup); !errors.Is(err, ErrConflict) {
		t.Fatal("deleted slot rebound")
	}
	if revision, err := store.Put(t.Context(), first, 3, public, backup); err != nil || revision != 4 {
		t.Fatal("explicit same-key recreation failed")
	}
	if _, err := store.Delete(t.Context(), first, 2); !errors.Is(err, ErrConflict) {
		t.Fatal("stale delete removed recreated backup")
	}
	if err := accountStore.Disable(t.Context(), first); err != nil {
		t.Fatal("disable owner")
	}
	for _, owner := range []accounts.ID{first, {1}} {
		if record, err := store.Get(t.Context(), owner); record.Backup != nil || !errors.Is(err, ErrUnavailable) {
			t.Fatal("disabled or missing owner read backup")
		}
		if _, err := store.Put(t.Context(), owner, 4, public, backup); !errors.Is(err, ErrUnavailable) {
			t.Fatal("disabled or missing owner wrote backup")
		}
		if _, err := store.Delete(t.Context(), owner, 4); !errors.Is(err, ErrUnavailable) {
			t.Fatal("disabled or missing owner deleted backup")
		}
	}
	if record, err := store.Get(t.Context(), second); err != nil || record.Revision != 1 || !bytes.Equal(record.Backup, backup) {
		t.Fatal("another owner's state changed")
	}
}

func testPostgresConstraints(t *testing.T) {
	store, accountStore, pool := testStores(t)
	owner := newOwner(t, accountStore)
	public, backup := make([]byte, 32), envelope()
	query := "INSERT INTO anonce.member_key_backups(account_id, public_key, revision, backup) VALUES ($1,$2,$3,$4)"
	for _, tc := range []struct {
		owner    accounts.ID
		public   []byte
		revision int64
		backup   []byte
		state    string
	}{
		{owner, make([]byte, 31), 1, backup, "23514"},
		{owner, public, 0, backup, "23514"},
		{owner, public, -1, backup, "23514"},
		{owner, public, 1, make([]byte, BackupSize), "23514"},
		{owner, public, 1, backup[:BackupSize-1], "23514"},
		{accounts.ID{1}, public, 1, backup, "23503"},
	} {
		_, err := pool.Exec(t.Context(), query, tc.owner[:], tc.public, tc.revision, tc.backup)
		if state, ok := errors.AsType[*pgconn.PgError](err); !ok || state.SQLState() != tc.state {
			t.Fatal("database backup constraint differs")
		}
	}
	for _, offset := range []int{8, 9, 10, 11, 28, 31} {
		changed := bytes.Clone(backup)
		changed[offset] ^= 1
		_, err := pool.Exec(t.Context(), query, owner[:], public, 1, changed)
		if state, ok := errors.AsType[*pgconn.PgError](err); !ok || state.SQLState() != "23514" {
			t.Fatal("database admitted unsupported envelope")
		}
	}
	if _, err := store.Put(t.Context(), owner, 0, public, backup); err != nil {
		t.Fatal("create constraint test backup")
	}
	for _, query := range []string{
		"UPDATE anonce.member_key_backups SET public_key=public_key",
		"UPDATE anonce.member_key_backups SET account_id=account_id",
		"DELETE FROM anonce.member_key_backups",
		"TRUNCATE anonce.member_key_backups",
		"ALTER TABLE anonce.member_key_backups ADD COLUMN forbidden integer",
		"SELECT * FROM anonce.identity_schema_version",
		"SET ROLE anonce_owner",
	} {
		_, err := pool.Exec(t.Context(), query)
		if state, ok := errors.AsType[*pgconn.PgError](err); !ok || state.SQLState() != "42501" {
			t.Fatal("runtime backup grant differs")
		}
	}
	var count int
	if err := pool.QueryRow(t.Context(), "SELECT count(*) FROM information_schema.columns WHERE table_schema='anonce' AND table_name='member_key_backups'").Scan(&count); err != nil || count != 4 {
		t.Fatal("backup schema contains unexpected fields")
	}
}

func testPostgresConcurrentWrites(t *testing.T) {
	store, accountStore, _ := testStores(t)
	for _, operation := range []string{"create", "replace-or-delete"} {
		owner := newOwner(t, accountStore)
		expected := int64(0)
		if operation != "create" {
			if _, err := store.Put(t.Context(), owner, 0, make([]byte, 32), envelope()); err != nil {
				t.Fatal("prepare concurrent slot")
			}
			expected = 1
		}
		gate := make(chan struct{})
		var successes atomic.Int32
		var wg sync.WaitGroup
		for i := range 8 {
			wg.Go(func() {
				<-gate
				var err error
				if operation != "create" && i%2 == 0 {
					_, err = store.Delete(t.Context(), owner, expected)
				} else {
					_, err = store.Put(t.Context(), owner, expected, make([]byte, 32), envelope())
				}
				if err == nil {
					successes.Add(1)
				} else if !errors.Is(err, ErrConflict) {
					t.Error("concurrent write failed unexpectedly")
				}
			})
		}
		close(gate)
		wg.Wait()
		if successes.Load() != 1 {
			t.Fatal("concurrent writes did not have exactly one winner")
		}
		if record, err := store.Get(t.Context(), owner); err != nil || record.Revision != expected+1 {
			t.Fatal("concurrent write revision differs")
		}
	}
}

func testPostgresConcurrentDisable(t *testing.T) {
	store, accountStore, _ := testStores(t)
	for range 8 {
		owner := newOwner(t, accountStore)
		gate := make(chan struct{})
		var wg sync.WaitGroup
		for range 4 {
			wg.Go(func() {
				<-gate
				_, err := store.Put(t.Context(), owner, 0, make([]byte, 32), envelope())
				if err != nil && !errors.Is(err, ErrConflict) && !errors.Is(err, ErrUnavailable) {
					t.Error("write racing disable failed unexpectedly")
				}
			})
		}
		wg.Go(func() {
			<-gate
			if err := accountStore.Disable(t.Context(), owner); err != nil {
				t.Error("concurrent owner disable failed")
			}
		})
		close(gate)
		wg.Wait()
		if _, err := store.Get(t.Context(), owner); !errors.Is(err, ErrUnavailable) {
			t.Fatal("backup accessible after disable")
		}
		if _, err := store.Put(t.Context(), owner, 0, make([]byte, 32), envelope()); !errors.Is(err, ErrUnavailable) {
			t.Fatal("backup writable after disable")
		}
	}
}

func testPostgresCancellation(t *testing.T) {
	store, accountStore, pool := testStores(t)
	owner := newOwner(t, accountStore)
	if _, err := store.Put(t.Context(), owner, 0, make([]byte, 32), envelope()); err != nil {
		t.Fatal("prepare cancellation backup")
	}
	for _, lock := range []string{
		"SELECT state FROM anonce.accounts WHERE id=$1 FOR UPDATE",
		"SELECT revision FROM anonce.member_key_backups WHERE account_id=$1 FOR UPDATE",
	} {
		tx, err := pool.Begin(t.Context())
		if err != nil {
			t.Fatal("begin test lock")
		}
		defer func() { _ = tx.Rollback(t.Context()) }()
		if _, err := tx.Exec(t.Context(), lock, owner[:]); err != nil {
			t.Fatal("hold test lock")
		}
		for _, deleting := range []bool{false, true} {
			ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
			var revision int64
			if deleting {
				revision, err = store.Delete(ctx, owner, 1)
			} else {
				revision, err = store.Put(ctx, owner, 1, make([]byte, 32), envelope())
			}
			cancel()
			if revision != 0 || !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("blocked write cancellation lost")
			}
		}
		if err := tx.Rollback(t.Context()); err != nil {
			t.Fatal("release test lock")
		}
		// A fresh write acquires the account lock after the cancelled transaction
		// has rolled back, proving the failed operations left revision 1 intact.
		if revision, err := store.Put(t.Context(), owner, 1, make([]byte, 32), envelope()); err != nil || revision != 2 {
			t.Fatal("cancelled write changed slot or retained account lock")
		}
		owner = newOwner(t, accountStore)
		if _, err := store.Put(t.Context(), owner, 0, make([]byte, 32), envelope()); err != nil {
			t.Fatal("prepare next cancellation backup")
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := New(ctx, pool); !errors.Is(err, context.Canceled) {
		t.Fatal("constructor cancellation lost")
	}
	pool.Close()
	if _, err := store.Get(t.Context(), owner); err == nil || bytes.Contains([]byte(err.Error()), []byte("postgres")) {
		t.Fatal("closed pool admitted or driver details leaked")
	}
}

func testPostgresRevisionExhaustion(t *testing.T) {
	store, accountStore, pool := testStores(t)
	owner := newOwner(t, accountStore)
	if _, err := store.Put(t.Context(), owner, 0, make([]byte, 32), envelope()); err != nil {
		t.Fatal("prepare exhausted revision")
	}
	if _, err := pool.Exec(t.Context(), "UPDATE anonce.member_key_backups SET revision=$2 WHERE account_id=$1", owner[:], int64(math.MaxInt64-1)); err != nil {
		t.Fatal("set synthetic revision boundary")
	}
	if revision, err := store.Delete(t.Context(), owner, math.MaxInt64-1); err != nil || revision != math.MaxInt64 {
		t.Fatal("last revision failed")
	}
	if _, err := store.Put(t.Context(), owner, math.MaxInt64, make([]byte, 32), envelope()); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("exhausted revision wrapped")
	}
	if record, err := store.Get(t.Context(), owner); err != nil || record.Revision != math.MaxInt64 || record.Backup != nil {
		t.Fatal("exhausted tombstone changed")
	}
}

func sessionToken(t *testing.T, store *accounts.Store, owner accounts.ID) []byte {
	t.Helper()
	token, _, err := store.StartSession(t.Context(), owner, time.Minute)
	if err != nil {
		t.Fatal("create backup test session")
	}
	t.Cleanup(func() { clear(token) })
	return token
}

func deniedSession(t *testing.T, store *Store, token []byte) {
	t.Helper()
	if record, err := store.GetForSession(t.Context(), token); record.Revision != 0 || record.Backup != nil || record.PublicKey != ([32]byte{}) || !errors.Is(err, ErrUnavailable) {
		t.Fatal("unavailable session read backup")
	}
	if revision, err := store.PutForSession(t.Context(), token, 1, make([]byte, 32), envelope()); revision != 0 || !errors.Is(err, ErrUnavailable) {
		t.Fatal("unavailable session wrote backup")
	}
	if revision, err := store.DeleteForSession(t.Context(), token, 1); revision != 0 || !errors.Is(err, ErrUnavailable) {
		t.Fatal("unavailable session deleted backup")
	}
}

func testPostgresSessionScope(t *testing.T) {
	store, accountStore, _ := testStores(t)
	first, second := newOwner(t, accountStore), newOwner(t, accountStore)
	token, other := sessionToken(t, accountStore, first), sessionToken(t, accountStore, second)
	before := bytes.Clone(token)
	defer clear(before)
	public, backup := make([]byte, 32), envelope()
	if revision, err := store.PutForSession(t.Context(), token, 0, public, backup); err != nil || revision != 1 {
		t.Fatal("session slot creation failed")
	}
	if _, err := store.GetForSession(t.Context(), other); !errors.Is(err, ErrUnavailable) {
		t.Fatal("another session read first owner's slot")
	}
	if _, err := store.PutForSession(t.Context(), other, 1, public, backup); !errors.Is(err, ErrConflict) {
		t.Fatal("another session replaced first owner's slot")
	}
	if _, err := store.DeleteForSession(t.Context(), other, 1); !errors.Is(err, ErrConflict) {
		t.Fatal("another session deleted first owner's slot")
	}
	if revision, err := store.PutForSession(t.Context(), other, 0, public, backup); err != nil || revision != 1 {
		t.Fatal("independent session slot creation failed")
	}
	for _, expected := range []int64{0, 2} {
		if _, err := store.PutForSession(t.Context(), token, expected, public, backup); !errors.Is(err, ErrConflict) {
			t.Fatal("session write ignored revision")
		}
	}
	changed := bytes.Clone(public)
	changed[0] = 1
	if _, err := store.PutForSession(t.Context(), token, 1, changed, backup); !errors.Is(err, ErrConflict) {
		t.Fatal("session write rebound key")
	}
	if revision, err := store.PutForSession(t.Context(), token, 1, public, backup); err != nil || revision != 2 {
		t.Fatal("session replacement failed")
	}
	if revision, err := store.DeleteForSession(t.Context(), token, 2); err != nil || revision != 3 {
		t.Fatal("session deletion failed")
	}
	if record, err := store.GetForSession(t.Context(), token); err != nil || record.Revision != 3 || record.Backup != nil || record.PublicKey != ([32]byte{}) {
		t.Fatal("session tombstone lost")
	}
	if _, err := store.PutForSession(t.Context(), token, 0, public, backup); !errors.Is(err, ErrConflict) {
		t.Fatal("session stale create restored tombstone")
	}
	if revision, err := store.PutForSession(t.Context(), token, 3, public, backup); err != nil || revision != 4 {
		t.Fatal("session same-key restoration failed")
	}
	record, err := store.GetForSession(t.Context(), token)
	if err != nil || record.Revision != 4 || !bytes.Equal(record.Backup, backup) || !bytes.Equal(before, token) {
		t.Fatal("session data or input ownership differs")
	}
	record.Backup[50] ^= 1
	if fresh, err := store.GetForSession(t.Context(), token); err != nil || !bytes.Equal(fresh.Backup, backup) {
		t.Fatal("session result aliases storage")
	}
	if record, err := store.GetForSession(t.Context(), other); err != nil || record.Revision != 1 {
		t.Fatal("session writes affected another owner")
	}
}

func testPostgresSessionInvalidation(t *testing.T) {
	store, accountStore, pool := testStores(t)
	for _, operation := range []string{"revoke", "revoke-others", "revoke-all", "disable", "expired", "unknown"} {
		t.Run(operation, func(t *testing.T) {
			owner := newOwner(t, accountStore)
			token, sibling := sessionToken(t, accountStore, owner), sessionToken(t, accountStore, owner)
			if _, err := store.PutForSession(t.Context(), token, 0, make([]byte, 32), envelope()); err != nil {
				t.Fatal("prepare session invalidation slot")
			}
			var err error
			switch operation {
			case "revoke":
				err = accountStore.Revoke(t.Context(), token)
			case "revoke-others":
				var count int64
				count, err = accountStore.RevokeOtherSessions(t.Context(), sibling)
				if err == nil && count != 1 {
					t.Fatal("sibling revocation removed unexpected backup sessions")
				}
			case "revoke-all":
				err = accountStore.RevokeAll(t.Context(), owner)
			case "disable":
				err = accountStore.Disable(t.Context(), owner)
			case "expired":
				// Runtime can insert synthetic expired sessions, but cannot extend
				// or edit a live session's immutable expiry.
				token = make([]byte, accounts.TokenSize)
				rand.Read(token)
				defer clear(token)
				digest := sha256.Sum256(token)
				_, err = pool.Exec(t.Context(), `INSERT INTO anonce.account_sessions(token_digest, account_id, created_at, expires_at)
                    VALUES ($1,$2,statement_timestamp()-interval '2 hours',statement_timestamp()-interval '1 hour')`, digest[:], owner[:])
			case "unknown":
				token = make([]byte, accounts.TokenSize)
				rand.Read(token)
				defer clear(token)
			}
			if err != nil {
				t.Fatal("invalidate backup session")
			}
			deniedSession(t, store, token)
			if operation == "disable" || operation == "revoke-all" {
				deniedSession(t, store, sibling)
			} else if record, err := store.GetForSession(t.Context(), sibling); err != nil || record.Revision != 1 {
				t.Fatal("invalidation affected sibling or backup")
			}
		})
	}
	pool.Close()
	denied := make([]byte, accounts.TokenSize)
	if record, err := store.GetForSession(t.Context(), denied); err == nil || record.Backup != nil || bytes.Contains([]byte(err.Error()), []byte("postgres")) {
		t.Fatal("closed session pool admitted or leaked diagnostics")
	}
}

func testPostgresSessionLocking(t *testing.T) {
	store, accountStore, pool := testStores(t)
	for _, operation := range []string{"revoke", "revoke-others", "revoke-all", "disable"} {
		t.Run(operation, func(t *testing.T) {
			owner := newOwner(t, accountStore)
			token := sessionToken(t, accountStore, owner)
			sibling := sessionToken(t, accountStore, owner)
			// The callback runs only after the account lock and session recheck.
			// Each invalidator must wait for this transaction, then cancel cleanly.
			err := store.withSession(t.Context(), token, false, func(ctx context.Context, _ pgx.Tx, _ accounts.ID) error {
				ctx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
				defer cancel()
				var err error
				switch operation {
				case "revoke":
					err = accountStore.Revoke(ctx, token)
				case "revoke-others":
					var count int64
					count, err = accountStore.RevokeOtherSessions(ctx, sibling)
					if count != 0 {
						t.Error("cancelled sibling revocation returned a count")
					}
				case "revoke-all":
					err = accountStore.RevokeAll(ctx, owner)
				case "disable":
					err = accountStore.Disable(ctx, owner)
				}
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Error("invalidation did not wait for authorized operation")
				}
				return nil
			})
			if err != nil {
				t.Fatal("authorized transaction failed")
			}
			if revision, err := store.PutForSession(t.Context(), token, 0, make([]byte, 32), envelope()); err != nil || revision != 1 {
				t.Fatal("cancelled invalidation changed session or retained lock")
			}
		})
	}
	owner := newOwner(t, accountStore)
	token := sessionToken(t, accountStore, owner)
	if _, err := store.PutForSession(t.Context(), token, 0, make([]byte, 32), envelope()); err != nil {
		t.Fatal("prepare blocked session access")
	}
	for _, lock := range []string{
		"SELECT state FROM anonce.accounts WHERE id=$1 FOR UPDATE",
		"SELECT revision FROM anonce.member_key_backups WHERE account_id=$1 FOR UPDATE",
	} {
		tx, err := pool.Begin(t.Context())
		if err != nil {
			t.Fatal("begin session access test lock")
		}
		defer func() { _ = tx.Rollback(t.Context()) }()
		if _, err := tx.Exec(t.Context(), lock, owner[:]); err != nil {
			t.Fatal("hold session access test lock")
		}
		for _, operation := range []string{"read", "put", "delete"} {
			if operation == "read" && lock != "SELECT state FROM anonce.accounts WHERE id=$1 FOR UPDATE" {
				continue // Reads do not lock the backup row.
			}
			ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
			switch operation {
			case "read":
				record, readErr := store.GetForSession(ctx, token)
				err = readErr
				if record.Revision != 0 || record.Backup != nil {
					t.Error("cancelled session read returned material")
				}
			case "put":
				_, err = store.PutForSession(ctx, token, 1, make([]byte, 32), envelope())
			case "delete":
				_, err = store.DeleteForSession(ctx, token, 1)
			}
			cancel()
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("session access cancellation lost")
			}
		}
		if err := tx.Rollback(t.Context()); err != nil {
			t.Fatal("release session access test lock")
		}
		if record, err := store.GetForSession(t.Context(), token); err != nil || record.Revision != 1 {
			t.Fatal("cancelled access changed slot or retained lock")
		}
	}
}

func testPostgresSessionExpiryWait(t *testing.T) {
	store, accountStore, pool := testStores(t)
	owner := newOwner(t, accountStore)
	if _, err := store.Put(t.Context(), owner, 0, make([]byte, 32), envelope()); err != nil {
		t.Fatal("prepare expiry test slot")
	}
	token, session, err := accountStore.StartSession(t.Context(), owner, time.Second)
	if err != nil {
		t.Fatal("create short backup session")
	}
	defer clear(token)
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal("begin expiry test lock")
	}
	defer func() { _ = tx.Rollback(t.Context()) }()
	if _, err := tx.Exec(t.Context(), "SELECT state FROM anonce.accounts WHERE id=$1 FOR UPDATE", owner[:]); err != nil {
		t.Fatal("hold expiry test lock")
	}
	done := make(chan error, 1)
	go func() {
		_, err := store.PutForSession(t.Context(), token, 1, make([]byte, 32), envelope())
		done <- err
	}()
	waitForBlockedAccess(t, pool, tx.Conn().PgConn().PID())
	// Keep the account locked beyond absolute expiry using the database clock.
	if _, err := pool.Exec(t.Context(), "SELECT pg_sleep(GREATEST(0, EXTRACT(EPOCH FROM ($1::timestamptz - clock_timestamp()))) + 0.05)", session.ExpiresAt); err != nil {
		t.Fatal("wait for database session expiry")
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal("release expiry test lock")
	}
	if err := <-done; !errors.Is(err, ErrUnavailable) {
		t.Fatal("session expiring during lock wait wrote backup")
	}
	if record, err := store.Get(t.Context(), owner); err != nil || record.Revision != 1 {
		t.Fatal("expired queued access changed backup")
	}
}

func waitForBlockedAccess(t *testing.T, pool *pgxpool.Pool, blocker uint32) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var blocked bool
		err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_stat_activity
            WHERE usename = current_user AND $1::integer = ANY(pg_blocking_pids(pid)))`, int64(blocker)).Scan(&blocked)
		if err != nil {
			t.Fatal("observe blocked session access")
		}
		if blocked {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("session access did not reach account lock")
		case <-ticker.C:
		}
	}
}

func testPostgresSessionRevocationWait(t *testing.T) {
	store, accountStore, pool := testStores(t)
	for _, operation := range []string{"read", "put", "delete"} {
		t.Run(operation, func(t *testing.T) {
			owner := newOwner(t, accountStore)
			token := sessionToken(t, accountStore, owner)
			if _, err := store.PutForSession(t.Context(), token, 0, make([]byte, 32), envelope()); err != nil {
				t.Fatal("prepare queued revocation slot")
			}
			tx, err := pool.Begin(t.Context())
			if err != nil {
				t.Fatal("begin test revocation")
			}
			defer func() { _ = tx.Rollback(t.Context()) }()
			if _, err := tx.Exec(t.Context(), "SELECT state FROM anonce.accounts WHERE id=$1 FOR UPDATE", owner[:]); err != nil {
				t.Fatal("hold test revocation account lock")
			}
			done := make(chan error, 1)
			go func() {
				var err error
				switch operation {
				case "read":
					record, readErr := store.GetForSession(t.Context(), token)
					err = readErr
					if record.Revision != 0 || record.Backup != nil {
						t.Error("queued revoked read returned material")
					}
				case "put":
					_, err = store.PutForSession(t.Context(), token, 1, make([]byte, 32), envelope())
				case "delete":
					_, err = store.DeleteForSession(t.Context(), token, 1)
				}
				done <- err
			}()
			waitForBlockedAccess(t, pool, tx.Conn().PgConn().PID())
			// Match Revoke's transaction after proving the access already found
			// its owner and is waiting. Only a post-lock statement sees deletion.
			digest := sha256.Sum256(token)
			if _, err := tx.Exec(t.Context(), "DELETE FROM anonce.account_sessions WHERE token_digest=$1", digest[:]); err != nil {
				t.Fatal("delete queued session")
			}
			if err := tx.Commit(t.Context()); err != nil {
				t.Fatal("commit queued session revocation")
			}
			if err := <-done; !errors.Is(err, ErrUnavailable) {
				t.Fatal("queued access survived committed revocation")
			}
			if record, err := store.Get(t.Context(), owner); err != nil || record.Revision != 1 || record.Backup == nil {
				t.Fatal("queued revoked access changed backup")
			}
		})
	}
}

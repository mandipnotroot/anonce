// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

//go:build databaseintegration

package memberbackup

import (
	"bytes"
	"context"
	"errors"
	"math"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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

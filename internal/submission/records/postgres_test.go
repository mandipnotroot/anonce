// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

//go:build databaseintegration

package records

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
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
		t.Fatal("configure submission test pool")
	}
	config.ConnConfig.Password = string(password)
	config.ConnConfig.RuntimeParams = map[string]string{"search_path": "pg_catalog,anonce"}
	config.MaxConns = 8
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal("open submission test pool")
	}
	t.Cleanup(pool.Close)
	return pool
}

func testStore(t *testing.T) (*Store, *pgxpool.Pool) {
	t.Helper()
	pool := testPool(t)
	store, err := New(t.Context(), pool)
	if err != nil {
		t.Fatal("admit submission store")
	}
	return store, pool
}

func newRound(t *testing.T, store *Store, pool *pgxpool.Pool) Round {
	t.Helper()
	var now time.Time
	if err := pool.QueryRow(t.Context(), "SELECT statement_timestamp()").Scan(&now); err != nil {
		t.Fatal("read database clock")
	}
	round := Round{OpensAt: now.Add(-time.Minute), ClosesAt: now.Add(time.Hour)}
	rand.Read(round.ID[:])
	rand.Read(round.BulletinDigest[:])
	if err := store.CreateRound(t.Context(), round); err != nil {
		t.Fatal("create submission test round")
	}
	return round
}

func TestPostgresSubmissionRecords(t *testing.T) {
	if os.Getenv("ANONCE_TEST_SIDE") == "identity" {
		if store, err := New(t.Context(), testPool(t)); err == nil || store != nil {
			t.Fatal("identity database admitted to submission storage")
		}
		return
	}
	t.Run("persistence-and-retries", testPostgresPersistence)
	t.Run("concurrent-spending", testPostgresSpending)
	t.Run("constraints-and-grants", testPostgresGrants)
	t.Run("round-admission", testPostgresRoundAdmission)
	t.Run("post-lock-window-and-cancellation", testPostgresRoundWait)
	t.Run("cancellation-order-and-rollback", testPostgresCancelOrder)
	t.Run("round-provisioning-rollback", testPostgresProvisionRollback)
	t.Run("uncommitted-conflict", testPostgresUncommittedConflict)
	t.Run("cancelled-insert-rollback", testPostgresInsertRollback)
}

func testPostgresPersistence(t *testing.T) {
	store, pool := testStore(t)
	round := newRound(t, store, pool)
	spend := bytes.Repeat([]byte{3}, 32)
	ciphertext := bytes.Repeat([]byte{4}, MaxCiphertextSize)
	before := bytes.Clone(ciphertext)
	first, err := store.Accept(t.Context(), round.ID, round.BulletinDigest[:], spend, ciphertext)
	if err != nil || first.ID == (ID{}) || first.AcceptedAt.IsZero() || !bytes.Equal(ciphertext, before) {
		t.Fatal("initial acceptance failed or changed ciphertext")
	}
	other, _ := testStore(t)
	second, err := other.Accept(t.Context(), round.ID, round.BulletinDigest[:], spend, ciphertext)
	if err != nil || second != first {
		t.Fatal("exact retry did not preserve durable reference across pools")
	}
	ciphertext[0] ^= 1
	if got, err := store.Accept(t.Context(), round.ID, round.BulletinDigest[:], spend, ciphertext); got != (Reference{}) || !errors.Is(err, ErrConflict) {
		t.Fatal("changed payload replaced a spent record or disclosed reference")
	}
	var stored []byte
	if err := pool.QueryRow(t.Context(), "SELECT ciphertext FROM anonce.submission_records WHERE id=$1", first.ID[:]).Scan(&stored); err != nil || !bytes.Equal(stored, before) {
		t.Fatal("stored ciphertext changed")
	}
	spend[0] ^= 1
	third, err := store.Accept(t.Context(), round.ID, round.BulletinDigest[:], spend, ciphertext)
	if err != nil || third.ID == first.ID {
		t.Fatal("distinct spend was not independently accepted")
	}
	assertCount(t, pool, round.ID, 2)
	// The same digest in another round is a different uniqueness scope. Token
	// validation must still bind it to that round before calling this store.
	another := newRound(t, store, pool)
	if _, err := store.Accept(t.Context(), another.ID, another.BulletinDigest[:], spend, []byte{5}); err != nil {
		t.Fatal("round uniqueness scopes overlap")
	}
}

func testPostgresSpending(t *testing.T) {
	store, pool := testStore(t)
	other, _ := testStore(t)
	round := newRound(t, store, pool)
	spend := bytes.Repeat([]byte{6}, 32)
	type result struct {
		reference Reference
		err       error
		payload   byte
	}
	results := make(chan result, 24)
	start := make(chan struct{})
	var group sync.WaitGroup
	for i := range 24 {
		group.Go(func() {
			<-start
			writer := store
			if i%2 == 0 {
				writer = other
			}
			payload := byte(i % 3)
			reference, err := writer.Accept(t.Context(), round.ID, round.BulletinDigest[:], spend, []byte{payload})
			results <- result{reference, err, payload}
		})
	}
	close(start)
	group.Wait()
	close(results)
	var winner Reference
	var payload byte
	successes := 0
	for result := range results {
		if result.err == nil {
			if successes == 0 {
				winner, payload = result.reference, result.payload
			}
			if result.reference != winner || result.payload != payload {
				t.Fatal("competing payloads were accepted or retries changed reference")
			}
			successes++
		} else if !errors.Is(result.err, ErrConflict) || result.reference != (Reference{}) {
			t.Fatal("concurrent spend did not return a closed conflict")
		}
	}
	if successes != 8 {
		t.Fatal("identical contenders did not all resolve to one durable winner")
	}
	assertCount(t, pool, round.ID, 1)
}

func testPostgresGrants(t *testing.T) {
	store, pool := testStore(t)
	round := newRound(t, store, pool)
	for _, query := range []string{
		"UPDATE anonce.submission_records SET ciphertext=ciphertext",
		"DELETE FROM anonce.submission_records",
		"TRUNCATE anonce.submission_records",
		"UPDATE anonce.submission_rounds SET opens_at=opens_at",
		"UPDATE anonce.submission_rounds SET bulletin_digest=bulletin_digest",
		"DELETE FROM anonce.submission_rounds",
		"ALTER TABLE anonce.submission_records ADD COLUMN forbidden integer",
	} {
		_, err := pool.Exec(t.Context(), query)
		var databaseError *pgconn.PgError
		if !errors.As(err, &databaseError) || databaseError.Code != "42501" {
			t.Fatal("runtime mutation or schema ownership was not denied")
		}
	}
	for _, test := range []struct{ id, spend, ciphertext int }{
		{15, 32, 1}, {17, 32, 1}, {16, 31, 1}, {16, 33, 1}, {16, 32, 0}, {16, 32, MaxCiphertextSize + 1},
	} {
		_, err := pool.Exec(t.Context(), `INSERT INTO anonce.submission_records(id,round_id,spend_digest,ciphertext)
            VALUES ($1,$2,$3,$4)`, make([]byte, test.id), round.ID[:], make([]byte, test.spend), make([]byte, test.ciphertext))
		var databaseError *pgconn.PgError
		if !errors.As(err, &databaseError) || databaseError.Code != "23514" {
			t.Fatal("invalid stored record passed SQL constraints")
		}
	}
	for _, query := range []string{
		"INSERT INTO anonce.submission_rounds VALUES (decode(repeat('aa',15),'hex'),decode(repeat('bb',32),'hex'),now(),now()+interval '1 hour',false)",
		"INSERT INTO anonce.submission_rounds VALUES (decode(repeat('aa',16),'hex'),decode(repeat('bb',31),'hex'),now(),now()+interval '1 hour',false)",
		"INSERT INTO anonce.submission_rounds VALUES (decode(repeat('aa',16),'hex'),decode(repeat('bb',32),'hex'),now(),now(),false)",
		"INSERT INTO anonce.submission_rounds VALUES (decode(repeat('aa',16),'hex'),decode(repeat('bb',32),'hex'),now(),'infinity',false)",
	} {
		_, err := pool.Exec(t.Context(), query)
		var databaseError *pgconn.PgError
		if !errors.As(err, &databaseError) || databaseError.Code != "23514" {
			t.Fatal("invalid round passed SQL constraints")
		}
	}
	assertCount(t, pool, round.ID, 0)
}

func testPostgresRoundAdmission(t *testing.T) {
	store, pool := testStore(t)
	round := newRound(t, store, pool)
	if err := store.CreateRound(t.Context(), round); !errors.Is(err, ErrConflict) {
		t.Fatal("round policy could be overwritten")
	}
	for _, kind := range []string{"unknown", "wrong-bulletin", "unopened", "closed", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			candidate := round
			rand.Read(candidate.ID[:])
			switch kind {
			case "wrong-bulletin":
				candidate = round
				candidate.BulletinDigest[0] ^= 1
			case "unopened":
				candidate.OpensAt = round.ClosesAt
				candidate.ClosesAt = round.ClosesAt.Add(time.Hour)
			case "closed":
				candidate.ClosesAt = round.OpensAt
				candidate.OpensAt = round.OpensAt.Add(-time.Hour)
			}
			if kind != "unknown" && kind != "wrong-bulletin" {
				if err := store.CreateRound(t.Context(), candidate); err != nil {
					t.Fatal("create admission fixture")
				}
			}
			if kind == "cancelled" {
				for range 2 {
					if err := store.CancelRound(t.Context(), candidate.ID); err != nil {
						t.Fatal("round cancellation was not idempotent")
					}
				}
			}
			got, err := store.Accept(t.Context(), candidate.ID, candidate.BulletinDigest[:], make([]byte, 32), []byte{1})
			if got != (Reference{}) || !errors.Is(err, ErrUnavailable) {
				t.Fatal("unavailable or differently bound round admitted a submission")
			}
			assertCount(t, pool, candidate.ID, 0)
		})
	}
	spend := make([]byte, 32)
	if _, err := store.Accept(t.Context(), round.ID, round.BulletinDigest[:], spend, []byte{1}); err != nil {
		t.Fatal("accept before cancellation")
	}
	if err := store.CancelRound(t.Context(), round.ID); err != nil {
		t.Fatal("cancel accepted round")
	}
	if got, err := store.Accept(t.Context(), round.ID, round.BulletinDigest[:], spend, []byte{1}); got != (Reference{}) || !errors.Is(err, ErrUnavailable) {
		t.Fatal("cancelled round admitted an exact retry")
	}
	assertCount(t, pool, round.ID, 1)
	if err := store.CancelRound(t.Context(), ID{255}); !errors.Is(err, ErrUnavailable) {
		t.Fatal("unknown round cancellation succeeded")
	}
}

func waitFor(t *testing.T, pool *pgxpool.Pool, query string, argument any) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		var done bool
		if err := pool.QueryRow(ctx, query, argument).Scan(&done); err != nil {
			t.Fatal("observe submission test synchronization")
		}
		if done {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("submission synchronization deadline")
		case <-ticker.C:
		}
	}
}

func waitBlocked(t *testing.T, pool *pgxpool.Pool, pid uint32) {
	t.Helper()
	waitFor(t, pool, "SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid)))", int64(pid))
}

func testPostgresRoundWait(t *testing.T) {
	for _, kind := range []string{"close", "cancel", "context"} {
		t.Run(kind, func(t *testing.T) {
			store, pool := testStore(t)
			round := newRound(t, store, pool)
			if kind == "close" {
				rand.Read(round.ID[:])
				var now time.Time
				if err := pool.QueryRow(t.Context(), "SELECT statement_timestamp()").Scan(&now); err != nil {
					t.Fatal("read close-test clock")
				}
				round.ClosesAt = now.Add(time.Second)
				if err := store.CreateRound(t.Context(), round); err != nil {
					t.Fatal("create closing round")
				}
			}
			tx, err := pool.Begin(t.Context())
			if err != nil {
				t.Fatal("begin round blocker")
			}
			defer func() { _ = tx.Rollback(t.Context()) }()
			if _, err := tx.Exec(t.Context(), "SELECT id FROM anonce.submission_rounds WHERE id=$1 FOR UPDATE", round.ID[:]); err != nil {
				t.Fatal("lock test round")
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				got, err := store.Accept(ctx, round.ID, round.BulletinDigest[:], make([]byte, 32), []byte{1})
				if got != (Reference{}) {
					t.Error("queued acceptance exposed a reference")
				}
				done <- err
			}()
			waitBlocked(t, pool, tx.Conn().PgConn().PID())
			want := ErrUnavailable
			switch kind {
			case "close":
				waitFor(t, pool, "SELECT statement_timestamp() >= $1", round.ClosesAt)
			case "cancel":
				if _, err := tx.Exec(t.Context(), "UPDATE anonce.submission_rounds SET cancelled=true WHERE id=$1", round.ID[:]); err != nil {
					t.Fatal("cancel locked round")
				}
			case "context":
				cancel()
				want = context.Canceled
			}
			if err := tx.Commit(t.Context()); err != nil {
				t.Fatal("release round blocker")
			}
			if err := <-done; !errors.Is(err, want) {
				t.Fatal("queued acceptance ignored closure, cancellation, or context")
			}
			assertCount(t, pool, round.ID, 0)
		})
	}
}

func insertBlocked(t *testing.T, pool *pgxpool.Pool, round Round, spend []byte) pgx.Tx {
	t.Helper()
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal("begin uncommitted spend")
	}
	t.Cleanup(func() { _ = tx.Rollback(context.Background()) })
	var id ID
	rand.Read(id[:])
	if _, err := tx.Exec(t.Context(), "INSERT INTO anonce.submission_records(id,round_id,spend_digest,ciphertext) VALUES ($1,$2,$3,$4)", id[:], round.ID[:], spend, []byte{1}); err != nil {
		t.Fatal("insert uncommitted spend")
	}
	return tx
}

func testPostgresUncommittedConflict(t *testing.T) {
	store, pool := testStore(t)
	round := newRound(t, store, pool)
	spend := make([]byte, 32)
	tx := insertBlocked(t, pool, round, spend)
	done := make(chan error, 1)
	var got Reference
	go func() {
		var err error
		got, err = store.Accept(t.Context(), round.ID, round.BulletinDigest[:], spend, []byte{1})
		done <- err
	}()
	waitBlocked(t, pool, tx.Conn().PgConn().PID())
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal("commit competing spend")
	}
	if err := <-done; err != nil || got.ID == (ID{}) {
		t.Fatal("fresh statement did not observe conflict winner")
	}
	assertCount(t, pool, round.ID, 1)
}

func testPostgresInsertRollback(t *testing.T) {
	store, pool := testStore(t)
	round := newRound(t, store, pool)
	spend := make([]byte, 32)
	tx := insertBlocked(t, pool, round, spend)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		got, err := store.Accept(ctx, round.ID, round.BulletinDigest[:], spend, []byte{2})
		if got != (Reference{}) {
			t.Error("cancelled insert exposed a reference")
		}
		done <- err
	}()
	waitBlocked(t, pool, tx.Conn().PgConn().PID())
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal("blocked insert ignored cancellation")
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal("roll back competing spend")
	}
	assertCount(t, pool, round.ID, 0)
	if _, err := store.Accept(t.Context(), round.ID, round.BulletinDigest[:], spend, []byte{2}); err != nil {
		t.Fatal("rolled-back insertion consumed the spend")
	}
	assertCount(t, pool, round.ID, 1)
}

func testPostgresCancelOrder(t *testing.T) {
	store, pool := testStore(t)
	round := newRound(t, store, pool)
	spend := make([]byte, 32)
	blocker := insertBlocked(t, pool, round, spend)
	accepted := make(chan error, 1)
	go func() {
		_, err := store.Accept(t.Context(), round.ID, round.BulletinDigest[:], spend, []byte{1})
		accepted <- err
	}()
	waitBlocked(t, pool, blocker.Conn().PgConn().PID())
	cancelled := make(chan error, 1)
	go func() { cancelled <- store.CancelRound(t.Context(), round.ID) }()
	// Acceptance waits on uniqueness while holding a shared round lock;
	// cancellation must wait for that admitted transaction, not overtake it.
	waitFor(t, pool, `SELECT count(*) >= $1 FROM pg_stat_activity
        WHERE datname=current_database() AND cardinality(pg_blocking_pids(pid)) > 0`, 2)
	if err := blocker.Commit(t.Context()); err != nil {
		t.Fatal("release admitted acceptance")
	}
	if err := <-accepted; err != nil {
		t.Fatal("cancellation overtook admitted acceptance")
	}
	if err := <-cancelled; err != nil {
		t.Fatal("ordered cancellation failed")
	}
	if got, err := store.Accept(t.Context(), round.ID, round.BulletinDigest[:], spend, []byte{1}); got != (Reference{}) || !errors.Is(err, ErrUnavailable) {
		t.Fatal("completed cancellation did not deny subsequent admission")
	}
	assertCount(t, pool, round.ID, 1)

	round = newRound(t, store, pool)
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal("begin cancellation rollback blocker")
	}
	defer func() { _ = tx.Rollback(t.Context()) }()
	if _, err := tx.Exec(t.Context(), "SELECT id FROM anonce.submission_rounds WHERE id=$1 FOR SHARE", round.ID[:]); err != nil {
		t.Fatal("hold shared round lock")
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go func() { cancelled <- store.CancelRound(ctx, round.ID) }()
	waitBlocked(t, pool, tx.Conn().PgConn().PID())
	cancel()
	if err := <-cancelled; !errors.Is(err, context.Canceled) {
		t.Fatal("queued cancellation ignored context")
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal("release cancellation rollback blocker")
	}
	if _, err := store.Accept(t.Context(), round.ID, round.BulletinDigest[:], spend, []byte{1}); err != nil {
		t.Fatal("cancelled cancellation changed round admission")
	}
}

func testPostgresProvisionRollback(t *testing.T) {
	store, pool := testStore(t)
	round := newRound(t, store, pool)
	rand.Read(round.ID[:])
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal("begin provisioning blocker")
	}
	defer func() { _ = tx.Rollback(t.Context()) }()
	if _, err := tx.Exec(t.Context(), `INSERT INTO anonce.submission_rounds(id,bulletin_digest,opens_at,closes_at)
        VALUES ($1,$2,$3,$4)`, round.ID[:], round.BulletinDigest[:], round.OpensAt, round.ClosesAt); err != nil {
		t.Fatal("insert uncommitted round")
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- store.CreateRound(ctx, round) }()
	waitBlocked(t, pool, tx.Conn().PgConn().PID())
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal("queued provisioning ignored cancellation")
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal("release provisioning blocker")
	}
	if err := store.CreateRound(t.Context(), round); err != nil {
		t.Fatal("cancelled provisioning left a durable round")
	}
}

func assertCount(t *testing.T, pool *pgxpool.Pool, round ID, want int) {
	t.Helper()
	var count int
	if err := pool.QueryRow(t.Context(), "SELECT count(*) FROM anonce.submission_records WHERE round_id=$1", round[:]).Scan(&count); err != nil || count != want {
		t.Fatal("unexpected durable submission count")
	}
}

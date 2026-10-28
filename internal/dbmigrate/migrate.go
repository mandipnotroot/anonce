// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

// Package dbmigrate applies the local development database histories. HTTP
// services never import this operator-only package or assume the owner role.
package dbmigrate

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/mandipnotroot/anonce/migrations"
)

const Timeout = 60 * time.Second

// Apply connects only to the selected Compose database using the migration
// credential. It supports forward migration only, with no reset or down path.
// The password is borrowed; callers must clear their owned bytes. Driver strings
// and opaque runtime copies cannot be explicitly erased.
func Apply(ctx context.Context, side string, password []byte) error {
	if _, err := migrations.Files(side); err != nil {
		return err
	}
	if !validPassword(password) {
		return errors.New("invalid migration credential")
	}
	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()
	cfg, err := pgx.ParseConfig("postgres://anonce_migrator@" + side + "-db:5432/" + side + "?sslmode=disable&connect_timeout=5")
	if err != nil {
		return errors.New("configure migration connection")
	}
	// Do not inherit PGOPTIONS, application names, or other environment GUCs.
	cfg.RuntimeParams = map[string]string{"search_path": "pg_catalog,anonce"}
	cfg.Password = string(password)
	db := stdlib.OpenDB(*cfg, stdlib.OptionAfterConnect(func(ctx context.Context, conn *pgx.Conn) error {
		return prepare(ctx, conn, side)
	}))
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	defer func() { _ = db.Close() }()
	if err := apply(ctx, db, side); err != nil {
		// Driver and SQL errors can contain server-controlled details. Keep them
		// out of operator diagnostics while preserving cancellation semantics.
		return errors.Join(errors.New("apply database migrations"), ctx.Err())
	}
	return nil
}

func validPassword(password []byte) bool {
	if len(password) != 64 {
		return false
	}
	for _, b := range password {
		if (b < '0' || b > '9') && (b < 'a' || b > 'f') {
			return false
		}
	}
	return true
}

func prepare(ctx context.Context, conn *pgx.Conn, side string) error {
	var database, user string
	var privileged bool
	err := conn.QueryRow(ctx, `SELECT current_database(), session_user,
        rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls
        FROM pg_roles WHERE rolname = session_user`).Scan(&database, &user, &privileged)
	if err != nil || database != side || user != "anonce_migrator" || privileged {
		return errors.New("invalid migration database or role")
	}
	_, err = conn.Exec(ctx, `SET ROLE anonce_owner;
        SET statement_timeout = '30s'; SET lock_timeout = '5s';
        SET idle_in_transaction_session_timeout = '30s';
        SELECT pg_advisory_lock(4097083626)`)
	if err != nil {
		return errors.New("acquire migration ownership and lock")
	}
	// The session lock is held until the physical connection closes. Every new
	// connection acquires it before Goose can inspect or create its version table.
	// A single-connection pool keeps preflight and all SQL on that locked session.
	return checkHistory(ctx, conn, side)
}

func checkHistory(ctx context.Context, conn *pgx.Conn, side string) error {
	table := "anonce." + side + "_schema_version"
	var exists bool
	if err := conn.QueryRow(ctx, "SELECT to_regclass($1) IS NOT NULL", table).Scan(&exists); err != nil {
		return errors.New("inspect migration history")
	}
	if !exists {
		return nil
	}
	latest := int64(1)
	if side == "identity" {
		latest = 3
	}
	rows, err := conn.Query(ctx, "SELECT version_id, is_applied FROM "+table+" ORDER BY id LIMIT $1", latest+2)
	if err != nil {
		return errors.New("read migration history")
	}
	defer rows.Close()
	var next int64
	for rows.Next() {
		var version int64
		var applied bool
		if err := rows.Scan(&version, &applied); err != nil || version != next || version > latest || !applied {
			return errors.New("unsupported migration history")
		}
		next++
	}
	if rows.Err() != nil || next == 0 {
		return errors.New("invalid migration history")
	}
	rows.Close()
	if next > 1 {
		var matches bool
		if err := conn.QueryRow(ctx, "SELECT count(*) = 1 AND bool_and(singleton AND service = $1) FROM anonce.storage_boundary", side).Scan(&matches); err != nil || !matches {
			return errors.New("invalid storage boundary")
		}
	}
	return nil
}

func apply(ctx context.Context, db *sql.DB, side string) error {
	files, err := migrations.Files(side)
	if err != nil {
		return err
	}
	provider, err := goose.NewProvider(goose.DialectPostgres, db, files,
		goose.WithTableName("anonce."+side+"_schema_version"),
		goose.WithDisableGlobalRegistry(true),
		goose.WithSlog(slog.New(slog.NewTextHandler(io.Discard, nil))))
	if err != nil {
		return fmt.Errorf("configure migrations: %w", err)
	}
	if _, err := provider.Up(ctx); err != nil {
		return fmt.Errorf("migrate forward: %w", err)
	}
	return nil
}

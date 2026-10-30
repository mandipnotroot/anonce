// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

package browserapp

import (
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestRuntimeDatabaseBoundary(t *testing.T) {
	for _, tc := range []struct {
		name, dsn, side string
		container, want bool
	}{
		{"native", "postgres://anonce_runtime@127.0.0.1:55431/identity?sslmode=disable", "identity", false, true},
		{"identity", "postgres://anonce_runtime@identity-db:5432/identity?sslmode=disable", "identity", true, true},
		{"submission", "postgres://anonce_runtime@submission-db:5432/submission?sslmode=disable", "submission", true, true},
		{"cross-host", "postgres://anonce_runtime@submission-db:5432/identity?sslmode=disable", "identity", true, false},
		{"cross-database", "postgres://anonce_runtime@identity-db:5432/submission?sslmode=disable", "identity", true, false},
		{"owner", "postgres://anonce_owner@identity-db:5432/identity?sslmode=disable", "identity", true, false},
		{"password", "postgres://anonce_runtime:synthetic@identity-db:5432/identity?sslmode=disable", "identity", true, false},
		{"implicit-container", "postgres://anonce_runtime@identity-db:5432/identity?sslmode=disable", "identity", false, false},
		{"remote", "postgres://anonce_runtime@example.invalid:5432/identity?sslmode=disable", "identity", true, false},
		{"port", "postgres://anonce_runtime@identity-db:55431/identity?sslmode=disable", "identity", true, false},
		{"fallback", "postgres://anonce_runtime@identity-db:5432/identity?sslmode=prefer", "identity", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := pgx.ParseConfig(tc.dsn)
			if err != nil {
				t.Fatal(err)
			}
			if runtimeDatabase(c, tc.side, tc.container) != tc.want {
				t.Fatal("incorrect runtime database admission")
			}
		})
	}
	if runtimeDatabase(nil, "identity", false) {
		t.Fatal("nil config admitted")
	}
}

func FuzzRuntimeDatabaseBoundary(f *testing.F) {
	f.Add("identity-db", "identity", "identity", "anonce_runtime", "", uint16(5432), true)
	f.Add("127.0.0.1", "submission", "submission", "anonce_runtime", "", uint16(55432), false)
	f.Fuzz(func(t *testing.T, host, side, database, user, password string, port uint16, container bool) {
		if len(host) > 129 || len(side) > 17 || len(database) > 17 || len(user) > 33 || len(password) > 65 {
			return
		}
		c := &pgx.ConnConfig{Config: pgconn.Config{Host: host, Database: database, User: user, Password: password, Port: port}}
		want := (side == "identity" || side == "submission") && database == side && user == "anonce_runtime" && password == "" &&
			(!container && host == "127.0.0.1" || container && host == side+"-db" && port == 5432)
		if runtimeDatabase(c, side, container) != want {
			t.Fatal("runtime database boundary mismatch")
		}
	})
}

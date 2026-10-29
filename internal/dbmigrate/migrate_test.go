// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

package dbmigrate

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/mandipnotroot/anonce/migrations"
)

func TestMigrationAdmission(t *testing.T) {
	t.Parallel()
	for _, side := range []string{"", "Identity", "../identity", "postgres", "identity\x00", strings.Repeat("x", 1025)} {
		if err := Apply(t.Context(), side, bytes.Repeat([]byte{'a'}, 64)); err == nil {
			t.Fatalf("accepted invalid service %q", side)
		}
	}
	for _, password := range [][]byte{nil, {}, bytes.Repeat([]byte{'a'}, 63), bytes.Repeat([]byte{'a'}, 65), bytes.Repeat([]byte{'G'}, 64), bytes.Repeat([]byte{0}, 64)} {
		if err := Apply(t.Context(), "identity", password); err == nil {
			t.Fatal("accepted invalid credential")
		}
	}
	for _, args := range [][]string{nil, {}, {"identity", "submission"}, {"down"}, {"--help"}, {"identity\n"}} {
		if err := Command(t.Context(), args); err == nil {
			t.Fatal("accepted invalid command")
		}
	}
}

func TestMigrationCancellation(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	var wg sync.WaitGroup
	for _, side := range []string{"identity", "submission"} {
		wg.Go(func() {
			if err := Apply(ctx, side, bytes.Repeat([]byte{'a'}, 64)); !errors.Is(err, context.Canceled) {
				t.Errorf("Apply cancellation: %v", err)
			}
			if err := Command(ctx, []string{side}); !errors.Is(err, context.Canceled) {
				t.Errorf("Command cancellation: %v", err)
			}
		})
	}
	wg.Wait()
}

func TestMigrationCredentialFiles(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	path := filepath.Join(dir, "migration_password")
	synthetic := bytes.Repeat([]byte{'a'}, 64)
	for _, input := range [][]byte{nil, []byte("synthetic-input"), bytes.Repeat([]byte{'a'}, 65), bytes.Repeat([]byte{'A'}, 64), synthetic} {
		if err := os.WriteFile(path, input, 0o400); err != nil {
			t.Fatal(err)
		}
		got, err := readCredential(root)
		if validPassword(input) {
			if err != nil || !bytes.Equal(got, synthetic) {
				t.Fatal("valid credential failed")
			}
			clear(got)
		} else if err == nil || got != nil {
			t.Fatal("invalid credential returned bytes")
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("missing", path); err != nil {
		t.Fatal(err)
	}
	if got, err := readCredential(root); err == nil || got != nil || strings.Contains(err.Error(), path) {
		t.Fatal("symlink accepted or path reflected")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, synthetic, 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("target", path); err != nil {
		t.Fatal(err)
	}
	if got, err := readCredential(root); err == nil || got != nil {
		t.Fatal("regular-file symlink accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := readCredential(root); err == nil || got != nil {
		t.Fatal("FIFO accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if got, err := readCredential(root); err == nil || got != nil {
		t.Fatal("directory accepted")
	}
}

func TestMigrationFiles(t *testing.T) {
	t.Parallel()
	for _, side := range []string{"identity", "submission"} {
		files, err := migrations.Files(side)
		if err != nil {
			t.Fatal(err)
		}
		data, err := fs.ReadFile(files, "00001_storage_boundary.sql")
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(data, []byte("service = '"+side+"'")) || !bytes.Contains(data, []byte("-- +goose Up")) {
			t.Fatal("wrong embedded history")
		}
		if _, err := fs.ReadFile(files, "../"+side+"/00001_storage_boundary.sql"); err == nil {
			t.Fatal("history traversal accepted")
		}
		accounts, err := fs.ReadFile(files, "00002_accounts.sql")
		if side == "submission" {
			if !errors.Is(err, fs.ErrNotExist) {
				t.Fatal("submission history contains account migration")
			}
		} else if err != nil || !bytes.Contains(accounts, []byte("CREATE TABLE anonce.accounts")) || !bytes.Contains(accounts, []byte("CREATE TABLE anonce.account_sessions")) {
			t.Fatal("identity account migration missing")
		}
		backups, err := fs.ReadFile(files, "00003_member_key_backups.sql")
		if side == "submission" {
			if !errors.Is(err, fs.ErrNotExist) {
				t.Fatal("submission history contains member backup migration")
			}
		} else if err != nil || !bytes.Contains(backups, []byte("CREATE TABLE anonce.member_key_backups")) {
			t.Fatal("identity member backup migration missing")
		}
		selectors, err := fs.ReadFile(files, "00004_session_selectors.sql")
		if side == "submission" {
			if !errors.Is(err, fs.ErrNotExist) {
				t.Fatal("submission history contains session selector migration")
			}
		} else if err != nil || !bytes.Contains(selectors, []byte("ADD COLUMN session_id uuid NOT NULL DEFAULT gen_random_uuid()")) {
			t.Fatal("identity session selector migration missing")
		}
	}
}

func FuzzMigrationAdmission(f *testing.F) {
	f.Add("identity", []byte("synthetic-input"))
	f.Add("submission", bytes.Repeat([]byte{'a'}, 64))
	f.Add("../identity", []byte{})
	f.Fuzz(func(t *testing.T, side string, password []byte) {
		if len(side) > 1025 || len(password) > 65 {
			return
		}
		want := len(password) == 64
		for _, b := range password {
			want = want && strings.ContainsRune("0123456789abcdef", rune(b))
		}
		if validPassword(password) != want {
			t.Fatal("credential admission differs")
		}
		if side != "identity" && side != "submission" || !want {
			if err := Apply(t.Context(), side, password); err == nil {
				t.Fatal("invalid input admitted")
			}
		}
	})
}

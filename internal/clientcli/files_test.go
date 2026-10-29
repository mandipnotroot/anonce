// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

package clientcli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/mandipnotroot/anonce/internal/client/keystore"
)

func TestClientBackupFiles(t *testing.T) {
	t.Parallel()
	directory := privateDirectory(t)
	path := filepath.Join(directory, "backup")
	// Non-key data exercises publication independently of encryption.
	data := []byte("synthetic encrypted-file stand-in")
	if err := writeBackup(t.Context(), path, data); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatal("backup was not created with owner-only permissions")
	}
	read, err := readBackup(t.Context(), path)
	if err != nil || !bytes.Equal(read, data) {
		t.Fatal("backup file round trip failed")
	}
	if err := writeBackup(t.Context(), path, []byte("replacement")); err == nil {
		t.Fatal("overwrote an existing file")
	}
	read, err = os.ReadFile(path)
	if err != nil || !bytes.Equal(read, data) {
		t.Fatal("failed write changed existing data")
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 1 {
		t.Fatal("temporary encrypted file was not cleaned up")
	}
}

func TestClientBackupRejectsUnsafePaths(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		setup func(*testing.T, string) string
	}{
		{"empty name", func(t *testing.T, dir string) string { return dir + string(os.PathSeparator) }},
		{"dot", func(t *testing.T, dir string) string { return filepath.Join(dir, "backup") + "/." }},
		{"missing parent", func(t *testing.T, dir string) string { return filepath.Join(dir, "missing", "backup") }},
		{"public parent", func(t *testing.T, dir string) string {
			if err := os.Chmod(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(dir, "backup")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			path := tc.setup(t, privateDirectory(t))
			if err := writeBackup(t.Context(), path, []byte("synthetic")); err == nil {
				t.Fatal("accepted unsafe destination")
			}
			if _, err := readBackup(t.Context(), path); err == nil {
				t.Fatal("accepted unsafe source")
			}
		})
	}
	for _, tc := range []struct {
		name string
		data []byte
		mode os.FileMode
	}{
		{"public file", []byte("synthetic"), 0o644},
		{"group-readable file", []byte("synthetic"), 0o640},
		{"other-readable file", []byte("synthetic"), 0o604},
		{"empty file", nil, 0o600},
		{"oversized file", make([]byte, keystore.MaxBackupSize+1), 0o600},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(privateDirectory(t), "backup")
			if err := os.WriteFile(path, tc.data, 0o600); err != nil {
				t.Fatal(err)
			}
			// Creation permissions are narrowed by umask. Set the intended
			// fixture mode explicitly without changing the process-wide mask.
			if err := os.Chmod(path, tc.mode); err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(path)
			if err != nil || info.Mode().Perm() != tc.mode {
				t.Fatal("unsafe-file fixture does not have the intended permissions")
			}
			if data, err := readBackup(t.Context(), path); err == nil || data != nil {
				t.Fatal("accepted unsafe file")
			}
		})
	}
	t.Run("symlink", func(t *testing.T) {
		directory := privateDirectory(t)
		target := filepath.Join(directory, "target")
		data := []byte("existing synthetic file")
		if err := os.WriteFile(target, data, 0o600); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"target", "missing"} {
			path := filepath.Join(directory, "link-"+name)
			if err := os.Symlink(name, path); err != nil {
				t.Fatal(err)
			}
			if err := writeBackup(t.Context(), path, []byte("replacement")); err == nil {
				t.Fatal("replaced or followed symlink destination")
			}
			if _, err := readBackup(t.Context(), path); err == nil {
				t.Fatal("followed symlink input")
			}
		}
		read, err := os.ReadFile(target)
		if err != nil || !bytes.Equal(read, data) {
			t.Fatal("symlink target was changed")
		}
		if _, err := os.Lstat(filepath.Join(directory, "missing")); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("created dangling symlink target")
		}
	})
	t.Run("directory", func(t *testing.T) {
		path := filepath.Join(privateDirectory(t), "backup")
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := readBackup(t.Context(), path); err == nil {
			t.Fatal("read directory as backup")
		}
		if err := writeBackup(t.Context(), path, []byte("synthetic")); err == nil {
			t.Fatal("replaced directory")
		}
	})
}

func TestClientBackupConcurrentPublication(t *testing.T) {
	t.Parallel()
	directory := privateDirectory(t)
	path := filepath.Join(directory, "backup")
	data := bytes.Repeat([]byte("synthetic encrypted-file stand-in"), 100)
	var successes atomic.Int32
	var group sync.WaitGroup
	for range 8 {
		group.Go(func() {
			if err := writeBackup(t.Context(), path, data); err == nil {
				successes.Add(1)
			}
		})
	}
	group.Wait()
	if successes.Load() != 1 {
		t.Fatal("publication did not have exactly one winner")
	}
	read, err := readBackup(t.Context(), path)
	if err != nil || !bytes.Equal(read, data) {
		t.Fatal("concurrent publication exposed incomplete data")
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 1 {
		t.Fatal("concurrent writers left temporary files")
	}
}

func TestClientBackupCancellation(t *testing.T) {
	t.Parallel()
	path := filepath.Join(privateDirectory(t), "backup")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := writeBackup(ctx, path, []byte("synthetic")); !errors.Is(err, context.Canceled) {
		t.Fatal("write ignored cancellation")
	}
	if _, err := readBackup(ctx, path); !errors.Is(err, context.Canceled) {
		t.Fatal("read ignored cancellation")
	}
	// The second check is immediately before the publication commit point.
	ctx = &cancelAtCheck{Context: t.Context(), at: 2}
	if err := writeBackup(ctx, path, []byte("synthetic")); !errors.Is(err, context.Canceled) {
		t.Fatal("write ignored pre-publication cancellation")
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("cancelled publication created final path")
	}
	ctx = &cancelAtCheck{Context: t.Context(), at: 3}
	if err := writeBackup(ctx, path, []byte("synthetic")); !errors.Is(err, context.Canceled) {
		t.Fatal("write ignored post-publication cancellation")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("post-publication cancellation lost the complete backup")
	}
	ctx = &cancelAtCheck{Context: t.Context(), at: 2}
	if data, err := readBackup(ctx, path); !errors.Is(err, context.Canceled) || data != nil {
		t.Fatal("cancelled read returned data")
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(entries) != 1 {
		t.Fatal("cancelled writers left temporary files")
	}
}

type cancelAtCheck struct {
	context.Context
	calls int
	at    int
}

func privateDirectory(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return directory
}

// unchangedPath snapshots absence, file identity and regular-file contents before
// a rejected publication. Symlinks are compared without following their targets.
func unchangedPath(t *testing.T, path string) func() {
	t.Helper()
	before, err := os.Lstat(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	var contents []byte
	if err == nil && before.Mode().IsRegular() {
		contents, err = os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
	}
	return func() {
		t.Helper()
		after, err := os.Lstat(path)
		if before == nil {
			if !errors.Is(err, os.ErrNotExist) {
				t.Fatal("failed publication created a destination")
			}
			return
		}
		if err != nil || !os.SameFile(before, after) {
			t.Fatal("existing destination was replaced")
		}
		if before.Mode().IsRegular() {
			data, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(data, contents) {
				t.Fatal("existing destination was modified")
			}
		}
	}
}

func (c *cancelAtCheck) Err() error {
	c.calls++
	if c.calls >= c.at {
		return context.Canceled
	}
	return c.Context.Err()
}

// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

package clientcli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/mandipnotroot/anonce/internal/client/keystore"
)

// openParent pins the caller-selected directory. Its ancestors and owner must
// be trusted; permissions do not protect against that owner, ACLs, or root.
func openParent(path string) (*os.Root, string, error) {
	parent, name := filepath.Split(path)
	if name == "" || name == "." || name == ".." {
		return nil, "", errors.New("backup: invalid file path")
	}
	if parent == "" {
		parent = "."
	}
	root, err := os.OpenRoot(parent)
	if err != nil {
		return nil, "", errors.New("backup: open parent directory")
	}
	info, err := root.Stat(".")
	if err != nil || info.Mode().Perm()&0o077 != 0 {
		_ = root.Close()
		return nil, "", errors.New("backup: parent directory must have owner-only permissions")
	}
	return root, name, nil
}

func readBackup(ctx context.Context, path string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("read backup: %w", err)
	}
	root, name, err := openParent(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	info, err := root.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 ||
		info.Size() < 1 || info.Size() > keystore.MaxBackupSize {
		return nil, errors.New("read backup: expected bounded owner-only regular file, not a symlink")
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, errors.New("read backup: open file")
	}
	defer func() { _ = file.Close() }()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) || !opened.Mode().IsRegular() || opened.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("read backup: file changed while opening")
	}
	backup, err := io.ReadAll(io.LimitReader(file, keystore.MaxBackupSize+1))
	if err != nil || len(backup) > keystore.MaxBackupSize {
		clear(backup)
		return nil, errors.New("read backup: unreadable or oversized file")
	}
	if err := ctx.Err(); err != nil {
		clear(backup)
		return nil, fmt.Errorf("read backup: %w", err)
	}
	return backup, nil
}

// writeBackup publishes only a complete, synced encrypted file. Hard-link
// creation is the no-replace commit point; unsupported filesystems fail closed.
// After that point an error or cancellation can leave the complete final file.
func writeBackup(ctx context.Context, path string, backup []byte) (result error) {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("write backup: %w", err)
	}
	root, name, err := openParent(path)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return errors.New("write backup: temporary name randomness unavailable")
	}
	temporary := ".anonce-backup-" + hex.EncodeToString(random[:])
	file, err := root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errors.New("write backup: create temporary file")
	}
	defer func() {
		if err := root.Remove(temporary); err != nil && !errors.Is(err, os.ErrNotExist) {
			result = errors.Join(result, errors.New("write backup: temporary encrypted file cleanup failed"))
		}
	}()
	defer func() { _ = file.Close() }()
	if _, err := file.Write(backup); err != nil {
		return errors.New("write backup: write encrypted file")
	}
	if err := file.Sync(); err != nil {
		return errors.New("write backup: sync encrypted file")
	}
	if err := file.Close(); err != nil {
		return errors.New("write backup: close encrypted file")
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("write backup: %w", err)
	}
	if err := root.Link(temporary, name); err != nil {
		return errors.New("write backup: cannot publish without replacing a path; destination must not exist and filesystem must support hard links")
	}
	if err := root.Remove(temporary); err != nil {
		return errors.New("write backup: backup published but temporary file cleanup failed")
	}
	directory, err := root.Open(".")
	if err != nil {
		return errors.New("write backup: backup published but directory open failed")
	}
	defer func() { _ = directory.Close() }()
	if err := directory.Sync(); err != nil {
		return errors.New("write backup: backup published but directory sync failed")
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("write backup: backup published: %w", err)
	}
	return nil
}

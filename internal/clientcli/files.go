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
		return nil, "", errors.New("file: invalid file path")
	}
	if parent == "" {
		parent = "."
	}
	root, err := os.OpenRoot(parent)
	if err != nil {
		return nil, "", errors.New("file: open parent directory")
	}
	info, err := root.Stat(".")
	if err != nil || info.Mode().Perm()&0o077 != 0 {
		_ = root.Close()
		return nil, "", errors.New("file: parent directory must have owner-only permissions")
	}
	return root, name, nil
}

func readBackup(ctx context.Context, path string) ([]byte, error) {
	data, err := readOwnedFile(ctx, path, keystore.MaxBackupSize)
	if err != nil {
		return nil, fmt.Errorf("read backup: %w", err)
	}
	return data, nil
}

// readOwnedFile shares trusted-directory and bounded regular-file import checks.
// The selected directory must not contain hostile same-user writers.
func readOwnedFile(ctx context.Context, path string, maxSize int64) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("read input: %w", err)
	}
	root, name, err := openParent(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	info, err := root.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 ||
		info.Size() < 1 || info.Size() > maxSize {
		return nil, errors.New("read input: expected bounded owner-only regular file, not a symlink")
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, errors.New("read input: open file")
	}
	defer func() { _ = file.Close() }()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) || !opened.Mode().IsRegular() || opened.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("read input: file changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxSize+1))
	if err != nil || int64(len(data)) > maxSize {
		clear(data)
		return nil, errors.New("read input: unreadable or oversized file")
	}
	if err := ctx.Err(); err != nil {
		clear(data)
		return nil, fmt.Errorf("read input: %w", err)
	}
	return data, nil
}

func writeBackup(ctx context.Context, path string, backup []byte) error {
	if err := writeOwnedFile(ctx, path, backup, ".anonce-backup-"); err != nil {
		return fmt.Errorf("write backup: %w", err)
	}
	return nil
}

// writeOwnedFile publishes only a complete, synced owner-only file. Hard-link
// creation is the no-replace commit point; unsupported filesystems fail closed.
// After that point an error or cancellation can leave the complete final file.
// The temporary prefix is a fixed internal label, never caller-selected input.
func writeOwnedFile(ctx context.Context, path string, data []byte, prefix string) (result error) {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("write file: %w", err)
	}
	root, name, err := openParent(path)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return errors.New("write file: temporary name randomness unavailable")
	}
	temporary := prefix + hex.EncodeToString(random[:])
	file, err := root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errors.New("write file: create temporary file")
	}
	defer func() {
		if err := root.Remove(temporary); err != nil && !errors.Is(err, os.ErrNotExist) {
			result = errors.Join(result, errors.New("write file: temporary file cleanup failed"))
		}
	}()
	defer func() { _ = file.Close() }()
	if _, err := file.Write(data); err != nil {
		return errors.New("write file: write data")
	}
	if err := file.Sync(); err != nil {
		return errors.New("write file: sync data")
	}
	if err := file.Close(); err != nil {
		return errors.New("write file: close data")
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("write file: %w", err)
	}
	if err := root.Link(temporary, name); err != nil {
		return errors.New("write file: cannot publish without replacing a path; destination must not exist and filesystem must support hard links")
	}
	if err := root.Remove(temporary); err != nil {
		return errors.New("write file: file published but temporary file cleanup failed")
	}
	directory, err := root.Open(".")
	if err != nil {
		return errors.New("write file: file published but directory open failed")
	}
	defer func() { _ = directory.Close() }()
	if err := directory.Sync(); err != nil {
		return errors.New("write file: file published but directory sync failed")
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("write file: file published: %w", err)
	}
	return nil
}

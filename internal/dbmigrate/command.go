// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

package dbmigrate

import (
	"context"
	"errors"
	"io"
	"os"
	"syscall"
)

// Command accepts exactly one fixed database target. Credentials enter through a
// bounded regular file, never an argument, URL, environment setting, or stdin.
func Command(ctx context.Context, args []string) error {
	if len(args) != 1 || args[0] != "identity" && args[0] != "submission" {
		return errors.New("usage: migrate identity|submission")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	root, err := os.OpenRoot("/run/secrets")
	if err != nil {
		return errors.New("open migration credential directory")
	}
	defer func() { _ = root.Close() }()
	password, err := readCredential(root)
	if err != nil {
		return err
	}
	defer clear(password)
	return Apply(ctx, args[0], password)
}

func readCredential(root *os.Root) ([]byte, error) {
	// The operator supplies a trusted read-only mount. Root confines resolution,
	// but follows in-root symlinks even with O_NOFOLLOW, so admit the inode first.
	info, err := root.Lstat("migration_password")
	if err != nil || !info.Mode().IsRegular() || info.Size() != 64 {
		return nil, errors.New("invalid migration credential file")
	}
	file, err := root.OpenFile("migration_password", os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("open migration credential")
	}
	defer func() { _ = file.Close() }()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) || !opened.Mode().IsRegular() || opened.Size() != 64 {
		return nil, errors.New("invalid migration credential file")
	}
	password, err := io.ReadAll(io.LimitReader(file, 65))
	if err != nil || !validPassword(password) {
		clear(password)
		return nil, errors.New("read migration credential")
	}
	return password, nil
}

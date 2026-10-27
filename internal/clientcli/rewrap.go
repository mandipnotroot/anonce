// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

package clientcli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/mandipnotroot/anonce/internal/client/keystore"
	"github.com/mandipnotroot/anonce/internal/client/memberkey"
	"github.com/mandipnotroot/anonce/internal/client/reviewerkey"
)

func runRewrap(ctx context.Context, cfg config, input *os.File) error {
	data, err := readPasswordInput(ctx, input, 3)
	if err != nil {
		return err
	}
	current, replacement, err := parseRewrapPasswords(data)
	clear(data)
	if err != nil {
		return err
	}
	defer clear(current)
	defer clear(replacement)
	backup, err := readBackup(ctx, cfg.input)
	if err != nil {
		return err
	}
	defer clear(backup)
	sealed, err := rewrap(ctx, cfg.kind, current, replacement, backup)
	if err != nil {
		return fmt.Errorf("rewrap backup: %w", err)
	}
	defer clear(sealed)
	return writeBackup(ctx, cfg.output, sealed)
}

// parseRewrapPasswords returns independently owned passwords only after the
// entire framing and replacement confirmation have passed validation.
func parseRewrapPasswords(data []byte) ([]byte, []byte, error) {
	current, rest, ok := bytes.Cut(data, []byte{'\n'})
	if !ok || len(current) == 0 || len(current) > keystore.MaxPasswordSize {
		return nil, nil, errors.New("read password: expected bounded LF-terminated password lines and EOF")
	}
	replacement, err := parsePassword(rest, true)
	if err != nil {
		return nil, nil, err
	}
	return bytes.Clone(current), replacement, nil
}

// rewrap validates through the typed importer before re-exporting the same key.
// It does not change key identity, revoke previous backups, or enforce retention.
func rewrap(ctx context.Context, kind string, current, replacement, backup []byte) ([]byte, error) {
	if kind != "member" && kind != "reviewer" {
		return nil, errArguments
	}
	if kind == "member" {
		key, err := memberkey.Open(ctx, current, backup)
		if err != nil {
			return nil, err
		}
		defer clear(key)
		return memberkey.Seal(ctx, replacement, key)
	}
	key, err := reviewerkey.Open(ctx, current, backup)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	return reviewerkey.Seal(ctx, replacement, key)
}

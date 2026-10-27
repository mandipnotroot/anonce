// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

package clientcli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

// readExpectedPublicKey snapshots an independently trusted public record before
// password or subject-file access. File permissions alone do not establish trust.
func readExpectedPublicKey(ctx context.Context, kind, path string) ([]byte, error) {
	data, err := readOwnedFile(ctx, path, int64(len(kind)+1+2*ed25519.PublicKeySize+1))
	if err != nil {
		return nil, fmt.Errorf("read expected public key: %w", err)
	}
	return parsePublicKeyLine(kind, data)
}

// parsePublicKeyLine accepts only the existing canonical public export for kind.
// Neither partial decoding nor an unknown/wrong kind can enable unpinned work.
func parsePublicKeyLine(kind string, data []byte) ([]byte, error) {
	invalid := errors.New("read expected public key: invalid public-key record")
	if (kind != "member" && kind != "reviewer") || len(data) != len(kind)+1+2*ed25519.PublicKeySize+1 {
		return nil, invalid
	}
	public := make([]byte, ed25519.PublicKeySize)
	if _, err := hex.Decode(public, data[len(kind)+1:len(data)-1]); err != nil ||
		!bytes.Equal(data, fmt.Appendf(nil, "%s:%x\n", kind, public)) {
		return nil, invalid
	}
	return public, nil
}

// outputPublicKey is called only after validation and optional expected-key
// matching. File output never falls back to stdout on publication failure.
func outputPublicKey(ctx context.Context, kind string, public []byte, path string, output io.Writer) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("write public key: %w", err)
	}
	line := fmt.Sprintf("%s:%x\n", kind, public)
	if path != "" {
		if err := writeOwnedFile(ctx, path, []byte(line), ".anonce-public-key-"); err != nil {
			return fmt.Errorf("write public key: %w", err)
		}
		return nil
	}
	if n, err := io.WriteString(output, line); err != nil || n != len(line) {
		return errors.New("write public key: incomplete output")
	}
	return nil
}

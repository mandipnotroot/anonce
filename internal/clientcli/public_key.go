// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

package clientcli

import (
	"context"
	"errors"
	"fmt"
	"io"
)

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

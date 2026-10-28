// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

package clientcli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"

	"github.com/mandipnotroot/anonce/internal/client/membercsr"
	"github.com/mandipnotroot/anonce/internal/client/memberkey"
)

func createCSR(ctx context.Context, password, backup, expected []byte) ([]byte, error) {
	key, err := memberkey.Open(ctx, password, backup)
	if err != nil {
		return nil, fmt.Errorf("member request: %w", err)
	}
	defer clear(key)
	// Compare public bytes only after typed authentication and validation, before
	// signing with this same in-memory key or creating any output file.
	if expected != nil && !bytes.Equal(key[ed25519.SeedSize:], expected) {
		return nil, errors.New("member request: public key does not match expected key")
	}
	der, err := membercsr.Create(ctx, key)
	if err != nil {
		return nil, err
	}
	return der, nil
}

func writeCSRFile(ctx context.Context, password, backup, expected []byte, path string) error {
	der, err := createCSR(ctx, password, backup, expected)
	if err != nil {
		return err
	}
	if err := writeOwnedFile(ctx, path, der, ".anonce-request-"); err != nil {
		return fmt.Errorf("member request: %w", err)
	}
	return nil
}

func writeCSR(ctx context.Context, password, backup, expected []byte, output io.Writer) error {
	der, err := createCSR(ctx, password, backup, expected)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("member request: %w", err)
	}
	if n, err := output.Write(der); err != nil || n != len(der) {
		return errors.New("member request: write public request")
	}
	return nil
}

func verifyCSR(ctx context.Context, path string, expected ed25519.PublicKey, destination string, output io.Writer) error {
	der, err := readOwnedFile(ctx, path, membercsr.DERSize)
	if err != nil {
		return fmt.Errorf("verify member request: %w", err)
	}
	public, err := membercsr.Parse(der)
	if err != nil {
		return fmt.Errorf("verify member request: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("verify member request: %w", err)
	}
	// Both keys are public. Compare only after the shared profile/signature check;
	// a matching key alone must never make a malformed request acceptable.
	if expected != nil && !bytes.Equal(public, expected) {
		return errors.New("verify member request: public key does not match expected key")
	}
	if err := outputPublicKey(ctx, "member", public, destination, output); err != nil {
		return fmt.Errorf("verify member request: %w", err)
	}
	return nil
}

// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

// Package reviewerkey generates local X25519 reviewer keys and validates their
// encrypted backups using reviewer-key payload profile 1 in docs/cryptography.md.
// It performs no persistence, transport, round binding, or envelope decryption.
package reviewerkey

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/mandipnotroot/anonce/internal/client/keystore"
)

const privateKeyDERSize = 48

// Generate creates a fresh X25519 reviewer key, returning its 32-byte private
// encoding in a caller-owned buffer. Clear it after use; never store it
// unencrypted. Library-internal private-key copies cannot be explicitly erased.
func Generate(ctx context.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("generate reviewer key: %w", err)
	}
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, errors.New("generate reviewer key: randomness unavailable")
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("generate reviewer key: %w", err)
	}
	return key.Bytes(), nil
}

// Seal validates an X25519 private encoding and encrypts its canonical PKCS #8
// representation with fresh backup randomness. Invalid keys or passwords wrap
// keystore.ErrInvalidInput. Inputs remain caller-owned and must not be mutated
// during the call; callers must clear private bytes and passwords after use.
func Seal(ctx context.Context, password, privateKey []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("seal reviewer key: %w", err)
	}
	key, err := ecdh.X25519().NewPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("seal reviewer key: %w", keystore.ErrInvalidInput)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, errors.New("seal reviewer key: encode private key")
	}
	defer clear(der)
	backup, err := keystore.Seal(ctx, keystore.ReviewerKey, password, der)
	if err != nil {
		return nil, fmt.Errorf("seal reviewer key: %w", err)
	}
	return backup, nil
}

// Open decrypts a reviewer-purpose backup and accepts only canonical X25519
// PKCS #8. Wrong passwords, wrong purposes, and invalid payloads all wrap
// keystore.ErrInvalidBackup without key output. Input errors and cancellation
// retain the underlying keystore error. Inputs must not be mutated during the
// call. The returned 32-byte private encoding is independently owned: clear it.
func Open(ctx context.Context, password, backup []byte) ([]byte, error) {
	der, err := keystore.Open(ctx, keystore.ReviewerKey, password, backup)
	if err != nil {
		return nil, fmt.Errorf("open reviewer key: %w", err)
	}
	defer clear(der)
	key, err := parsePrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("open reviewer key: %w", err)
	}
	if err := ctx.Err(); err != nil {
		clear(key)
		return nil, fmt.Errorf("open reviewer key: %w", err)
	}
	return key, nil
}

// parsePrivateKey bounds ASN.1 work independently of the outer backup limit.
// Re-encoding rejects extensions or alternate representations accepted by x509.
func parsePrivateKey(der []byte) ([]byte, error) {
	if len(der) != privateKeyDERSize {
		return nil, keystore.ErrInvalidBackup
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, keystore.ErrInvalidBackup
	}
	key, ok := parsed.(*ecdh.PrivateKey)
	if !ok || key.Curve() != ecdh.X25519() {
		// The same bounded DER size can also encode an Ed25519 private key.
		if other, ok := parsed.(ed25519.PrivateKey); ok {
			clear(other)
		}
		return nil, keystore.ErrInvalidBackup
	}
	canonical, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, keystore.ErrInvalidBackup
	}
	defer clear(canonical)
	if subtle.ConstantTimeCompare(der, canonical) != 1 {
		return nil, keystore.ErrInvalidBackup
	}
	return key.Bytes(), nil
}

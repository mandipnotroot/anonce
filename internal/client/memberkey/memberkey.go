// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

// Package memberkey generates local member keys and validates their encrypted
// backups using member-key payload profile 1 in docs/cryptography.md. It performs
// no persistence, transport, enrollment, or authorization.
package memberkey

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/mandipnotroot/anonce/internal/client/keystore"
)

const privateKeyDERSize = 48

// Generate creates a fresh Ed25519 member key. The returned private key is a
// caller-owned buffer: clear it after use and never store it unencrypted.
func Generate(ctx context.Context) (ed25519.PrivateKey, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("generate member key: %w", err)
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		clear(key)
		return nil, errors.New("generate member key: randomness unavailable")
	}
	if err := ctx.Err(); err != nil {
		clear(key)
		return nil, fmt.Errorf("generate member key: %w", err)
	}
	return key, nil
}

// Seal validates a complete Go Ed25519 private key and encrypts its canonical
// PKCS #8 representation with fresh backup randomness. Invalid keys or passwords
// wrap keystore.ErrInvalidInput. Inputs remain caller-owned and must not be
// mutated during the call; callers must clear keys and passwords after use.
func Seal(ctx context.Context, password []byte, key ed25519.PrivateKey) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("seal member key: %w", err)
	}
	if len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("seal member key: %w", keystore.ErrInvalidInput)
	}
	derived := ed25519.NewKeyFromSeed(key[:ed25519.SeedSize])
	defer clear(derived)
	if subtle.ConstantTimeCompare(key, derived) != 1 {
		return nil, fmt.Errorf("seal member key: %w", keystore.ErrInvalidInput)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, errors.New("seal member key: encode private key")
	}
	defer clear(der)
	backup, err := keystore.Seal(ctx, keystore.MemberKey, password, der)
	if err != nil {
		return nil, fmt.Errorf("seal member key: %w", err)
	}
	return backup, nil
}

// Open decrypts a member-purpose backup and accepts only the canonical Ed25519
// payload. Wrong passwords, wrong purposes, and malformed payloads all wrap
// keystore.ErrInvalidBackup and return no key. Input errors and cancellation
// retain the underlying keystore error. Inputs must not be mutated during the
// call. The returned private key is independently owned and must be cleared.
func Open(ctx context.Context, password, backup []byte) (ed25519.PrivateKey, error) {
	der, err := keystore.Open(ctx, keystore.MemberKey, password, backup)
	if err != nil {
		return nil, fmt.Errorf("open member key: %w", err)
	}
	defer clear(der)
	key, err := parsePrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("open member key: %w", err)
	}
	if err := ctx.Err(); err != nil {
		clear(key)
		return nil, fmt.Errorf("open member key: %w", err)
	}
	return key, nil
}

// parsePrivateKey bounds ASN.1 work independently of the outer backup limit.
// Re-encoding rejects extensions or alternate representations accepted by x509.
func parsePrivateKey(der []byte) (ed25519.PrivateKey, error) {
	if len(der) != privateKeyDERSize {
		return nil, keystore.ErrInvalidBackup
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, keystore.ErrInvalidBackup
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, keystore.ErrInvalidBackup
	}
	canonical, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		clear(key)
		return nil, keystore.ErrInvalidBackup
	}
	defer clear(canonical)
	if subtle.ConstantTimeCompare(der, canonical) != 1 {
		clear(key)
		return nil, keystore.ErrInvalidBackup
	}
	return key, nil
}

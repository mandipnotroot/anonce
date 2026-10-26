// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

// Package keystore encrypts bounded device secrets using device-backup profile 1
// in docs/cryptography.md. It performs no key generation, persistence, or I/O.
package keystore

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
)

// Purpose binds a backup to the caller's expected use, not to an identity or round.
type Purpose byte

const (
	MemberKey   Purpose = 1
	ReviewerKey Purpose = 2

	MaxSecretSize   = 64 * 1024
	MaxPasswordSize = 1024
	MaxBackupSize   = headerSize + MaxSecretSize + overhead

	headerSize = 32
	overhead   = 12 + 16 // Random GCM nonce and authentication tag.
	magic      = "ANONCEKS"
	version    = 1
	profile    = 1
)

var (
	// ErrInvalidInput reports unsupported purposes or out-of-bounds caller inputs.
	ErrInvalidInput = errors.New("invalid keystore input")
	// ErrInvalidBackup deliberately does not distinguish wrong passwords from
	// corrupt, unsupported, or wrong-purpose backups. No plaintext is returned.
	ErrInvalidBackup = errors.New("invalid keystore backup")

	// Serialize expensive derivations, including across concurrent import calls.
	// The library's unreachable work arena may remain allocated until collection.
	kdfSlot = make(chan struct{}, 1)
)

// Seal encrypts a secret with a fresh salt and library-generated nonce. Inputs
// remain caller-owned and must not be mutated during the call. Clear secret and
// password when no longer needed. The returned backup is a new, owned buffer.
func Seal(ctx context.Context, purpose Purpose, password, secret []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("seal keystore: %w", err)
	}
	if !validInput(purpose, password) {
		return nil, fmt.Errorf("seal keystore: %w", ErrInvalidInput)
	}
	secretSize := len(secret)
	if secretSize < 1 || secretSize > MaxSecretSize {
		return nil, fmt.Errorf("seal keystore: %w", ErrInvalidInput)
	}
	backup := make([]byte, headerSize, headerSize+secretSize+overhead)
	copy(backup, magic)
	backup[8], backup[9], backup[10] = version, profile, byte(purpose)
	if _, err := rand.Read(backup[12:28]); err != nil {
		return nil, errors.New("seal keystore: generate salt")
	}
	binary.BigEndian.PutUint32(backup[28:32], uint32(secretSize)+overhead)
	aead, err := deriveAEAD(ctx, password, backup[12:28])
	if err != nil {
		return nil, fmt.Errorf("seal keystore: %w", err)
	}
	// #nosec G407 -- NewGCMWithRandomNonce requires an empty nonce argument and generates a fresh nonce internally.
	backup = aead.Seal(backup, nil, secret, backup)
	if err := ctx.Err(); err != nil {
		clear(backup)
		return nil, fmt.Errorf("seal keystore: %w", err)
	}
	return backup, nil
}

// Open validates a complete backup before deriving a key. The purpose must be
// chosen by the caller, not read from the untrusted file. Successful output is a
// new, caller-owned secret buffer that must be cleared after use. Key syntax and
// authorization are not checked. Inputs must not be mutated during the call.
// Cancellation during Argon2id is observed only when that derivation finishes.
func Open(ctx context.Context, purpose Purpose, password, backup []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("open keystore: %w", err)
	}
	if !validInput(purpose, password) {
		return nil, fmt.Errorf("open keystore: %w", ErrInvalidInput)
	}
	if !validBackup(purpose, backup) {
		return nil, fmt.Errorf("open keystore: %w", ErrInvalidBackup)
	}
	aead, err := deriveAEAD(ctx, password, backup[12:28])
	if err != nil {
		return nil, fmt.Errorf("open keystore: %w", err)
	}
	// Keep ownership of the entire destination even if authentication fails and
	// the AEAD returns nil after having overwritten some of its backing array.
	secret := make([]byte, len(backup)-headerSize-overhead)
	opened, err := aead.Open(secret[:0], nil, backup[headerSize:], backup[:headerSize])
	if err != nil {
		clear(secret)
		return nil, fmt.Errorf("open keystore: %w", ErrInvalidBackup)
	}
	if err := ctx.Err(); err != nil {
		clear(opened)
		return nil, fmt.Errorf("open keystore: %w", err)
	}
	return opened, nil
}

func validInput(purpose Purpose, password []byte) bool {
	return (purpose == MemberKey || purpose == ReviewerKey) && len(password) > 0 && len(password) <= MaxPasswordSize
}

// validBackup is allocation-free and never performs password-derived work.
func validBackup(purpose Purpose, backup []byte) bool {
	if len(backup) < headerSize+overhead+1 || len(backup) > MaxBackupSize {
		return false
	}
	return bytes.Equal(backup[:8], []byte(magic)) &&
		backup[8] == version && backup[9] == profile &&
		(purpose == MemberKey || purpose == ReviewerKey) && backup[10] == byte(purpose) &&
		backup[11] == 0 && int64(binary.BigEndian.Uint32(backup[28:32])) == int64(len(backup)-headerSize)
}

func deriveAEAD(ctx context.Context, password, salt []byte) (cipher.AEAD, error) {
	select {
	case kdfSlot <- struct{}{}:
		defer func() { <-kdfSlot }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	key := argon2.IDKey(password, salt, 3, 64*1024, 4, 32)
	defer clear(key)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.New("initialize keystore cipher")
	}
	aead, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, errors.New("initialize keystore encryption")
	}
	return aead, nil
}

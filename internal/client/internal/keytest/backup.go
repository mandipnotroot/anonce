// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

// Package keytest shares encrypted-backup contract checks between key wrappers.
// It is test support only; algorithm-specific validation stays with each wrapper.
package keytest

import (
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/mandipnotroot/anonce/internal/client/keystore"
)

// Profile supplies the typed operations under test without replacing cryptography.
type Profile[K ~[]byte] struct {
	Purpose  keystore.Purpose
	Generate func(context.Context) (K, error)
	Seal     func(context.Context, []byte, K) ([]byte, error)
	Open     func(context.Context, []byte, []byte) (K, error)
}

func (p Profile[K]) key(t *testing.T) K {
	t.Helper()
	key, err := p.Generate(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(key) })
	return key
}

// RoundTrip checks the common wire profile, ownership, repeat imports and fresh
// exports. Returned keys remain usable for algorithm-specific checks until cleanup.
func (p Profile[K]) RoundTrip(t *testing.T) (K, K) {
	t.Helper()
	key := p.key(t)
	original := bytes.Clone(key)
	defer clear(original)
	password := []byte("synthetic test password")
	defer clear(password)
	backup, err := p.Seal(t.Context(), password, key)
	if err != nil {
		t.Fatal(err)
	}
	if len(backup) != 108 || backup[8] != 1 || backup[9] != 2 || backup[10] != byte(p.Purpose) {
		t.Fatal("unexpected key-backup size, profile, or purpose")
	}
	backupCopy := bytes.Clone(backup)
	opened, err := p.Open(t.Context(), password, backup)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(opened)
	if subtle.ConstantTimeCompare(key, opened) != 1 || subtle.ConstantTimeCompare(key, original) != 1 ||
		!bytes.Equal(backup, backupCopy) || string(password) != "synthetic test password" {
		t.Fatal("round trip changed key or caller-owned inputs")
	}
	clear(opened)
	if subtle.ConstantTimeCompare(key, original) != 1 {
		t.Fatal("import returned an alias of caller-owned private bytes")
	}
	again, err := p.Open(t.Context(), password, backup)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(again) })
	if subtle.ConstantTimeCompare(again, original) != 1 {
		t.Fatal("clearing imported key changed backup or later imports")
	}
	second, err := p.Seal(t.Context(), password, key)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(backup, second) || bytes.Equal(backup[12:28], second[12:28]) || bytes.Equal(backup[32:44], second[32:44]) {
		t.Fatal("re-export reused backup randomness")
	}
	return key, again
}

// RejectUnauthenticatedBackup checks that authentication failures return no key.
func (p Profile[K]) RejectUnauthenticatedBackup(t *testing.T) {
	t.Helper()
	key := p.key(t)
	password := []byte("synthetic test password")
	defer clear(password)
	backup, err := p.Seal(t.Context(), password, key)
	if err != nil {
		t.Fatal(err)
	}
	wrongPurpose := bytes.Clone(backup)
	wrongPurpose[10] = byte(keystore.MemberKey)
	if p.Purpose == keystore.MemberKey {
		wrongPurpose[10] = byte(keystore.ReviewerKey)
	}
	tampered := bytes.Clone(backup)
	tampered[len(tampered)-1] ^= 1
	for _, tc := range []struct {
		name     string
		password []byte
		backup   []byte
	}{
		{"wrong password", []byte("different synthetic test password"), backup},
		{"wrong purpose", password, wrongPurpose},
		{"tampered ciphertext", password, tampered},
		{"missing backup", password, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opened, err := p.Open(t.Context(), tc.password, tc.backup)
			defer clear(opened)
			if opened != nil || !errors.Is(err, keystore.ErrInvalidBackup) {
				t.Fatalf("unauthenticated backup returned key or wrong error: %v", err)
			}
		})
	}
}

// Cancellation exercises every observed cancellation checkpoint, including entry
// and the final output guard, without fixing the number of nested keystore checks.
// The keystore suite separately names and checks its cryptographic boundaries.
func (p Profile[K]) Cancellation(t *testing.T) {
	t.Helper()
	key := p.key(t)
	password := []byte("synthetic test password")
	defer clear(password)
	backup, err := p.Seal(t.Context(), password, key)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		operate func(context.Context) ([]byte, error)
	}{
		{"generate", func(ctx context.Context) ([]byte, error) { return p.Generate(ctx) }},
		{"seal", func(ctx context.Context) ([]byte, error) { return p.Seal(ctx, password, key) }},
		{"open", func(ctx context.Context) ([]byte, error) { return p.Open(ctx, password, backup) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			observed := &cancelOnCheck{Context: t.Context()}
			output, err := tc.operate(observed)
			clear(output)
			if err != nil || output == nil || observed.checks.Load() == 0 {
				t.Fatal("could not observe a successful cancellable operation")
			}
			for at := int32(1); at <= observed.checks.Load(); at++ {
				t.Run(fmt.Sprintf("checkpoint=%d", at), func(t *testing.T) {
					parent, cancel := context.WithCancel(t.Context())
					defer cancel()
					ctx := &cancelOnCheck{Context: parent, cancel: cancel, trigger: at}
					output, err := tc.operate(ctx)
					defer clear(output)
					if output != nil || !errors.Is(err, context.Canceled) || parent.Err() != context.Canceled {
						t.Fatalf("cancelled operation returned output or wrong error: %v", err)
					}
				})
			}
		})
	}
}

type cancelOnCheck struct {
	context.Context
	cancel  context.CancelFunc
	trigger int32
	checks  atomic.Int32
}

func (c *cancelOnCheck) Err() error {
	if c.checks.Add(1) == c.trigger {
		c.cancel()
	}
	return c.Context.Err()
}

// Concurrent checks shared-key export/import without mutating caller-owned inputs.
func (p Profile[K]) Concurrent(t *testing.T) {
	t.Helper()
	key := p.key(t)
	password := []byte("synthetic test password")
	defer clear(password)
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			backup, err := p.Seal(t.Context(), password, key)
			if err != nil {
				t.Error(err)
				return
			}
			opened, err := p.Open(t.Context(), password, backup)
			defer clear(opened)
			if err != nil || subtle.ConstantTimeCompare(key, opened) != 1 {
				t.Errorf("concurrent import failed or changed key: %v", err)
			}
		})
	}
	wg.Wait()
}

// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

package keystore

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// All payloads are synthetic non-key data. No private key fixtures are retained.
func TestKeystoreRoundTrip(t *testing.T) {
	cases := []struct {
		name     string
		purpose  Purpose
		password []byte
		secret   []byte
	}{
		{"member", MemberKey, []byte("synthetic test password"), []byte("synthetic non-key payload")},
		{"reviewer", ReviewerKey, []byte("synthetic test password"), []byte("synthetic reviewer payload")},
		{"minimum", MemberKey, []byte{0}, []byte{0}},
		{"maximum", ReviewerKey, bytes.Repeat([]byte{0xff}, MaxPasswordSize), bytes.Repeat([]byte{0xa5}, MaxSecretSize)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			password, secret := bytes.Clone(tc.password), bytes.Clone(tc.secret)
			backup, err := Seal(t.Context(), tc.purpose, password, secret)
			if err != nil {
				t.Fatal(err)
			}
			if len(backup) != 60+len(secret) || !validBackup(tc.purpose, backup) {
				t.Fatal("unexpected backup format or size")
			}
			original := bytes.Clone(backup)
			opened, err := Open(t.Context(), tc.purpose, password, backup)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(opened, secret) {
				t.Fatal("round trip changed secret")
			}
			clear(opened)
			if !bytes.Equal(secret, tc.secret) || !bytes.Equal(password, tc.password) || !bytes.Equal(backup, original) {
				t.Fatal("operation changed caller-owned input")
			}
		})
	}
}

func TestKeystoreFreshRandomness(t *testing.T) {
	password, secret := []byte("synthetic test password"), []byte("synthetic non-key payload")
	first, err := Seal(t.Context(), MemberKey, password, secret)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Seal(t.Context(), MemberKey, password, secret)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first[12:28], second[12:28]) || bytes.Equal(first[32:44], second[32:44]) || bytes.Equal(first, second) {
		t.Fatal("re-export reused salt, nonce, or ciphertext")
	}
}

func TestKeystoreRejectsInvalidInputs(t *testing.T) {
	password, secret := []byte("synthetic test password"), []byte("synthetic non-key payload")
	cases := []struct {
		name     string
		purpose  Purpose
		password []byte
	}{
		{"missing purpose", 0, password},
		{"unknown purpose", 255, password},
		{"empty password", MemberKey, nil},
		{"long password", MemberKey, make([]byte, MaxPasswordSize+1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			backup, err := Seal(t.Context(), tc.purpose, tc.password, secret)
			if backup != nil || !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("Seal returned output or wrong error: %v", err)
			}
			opened, err := Open(t.Context(), tc.purpose, tc.password, formatOnlyBackup(1))
			if opened != nil || !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("Open returned output or wrong error: %v", err)
			}
		})
	}
	for _, secret := range [][]byte{nil, {}, make([]byte, MaxSecretSize+1)} {
		backup, err := Seal(t.Context(), MemberKey, password, secret)
		if backup != nil || !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("Seal accepted out-of-bounds secret: %v", err)
		}
	}
}

func TestKeystoreRejectsUnsafeParameters(t *testing.T) {
	// Occupy the KDF slot: malformed imports must fail without waiting for it.
	kdfSlot <- struct{}{}
	defer func() { <-kdfSlot }()
	for _, purpose := range []Purpose{MemberKey, ReviewerKey} {
		t.Run(fmt.Sprintf("purpose=%d", purpose), func(t *testing.T) {
			reject := func(t *testing.T, backup []byte) {
				t.Helper()
				original := bytes.Clone(backup)
				ctx, cancel := context.WithTimeout(t.Context(), time.Second)
				defer cancel()
				secret, err := Open(ctx, purpose, []byte("synthetic test password"), backup)
				if secret != nil || !errors.Is(err, ErrInvalidBackup) || !bytes.Equal(backup, original) {
					t.Fatalf("malformed import reached derivation, changed input, or returned output: %v", err)
				}
			}
			otherPurpose := MemberKey
			if purpose == MemberKey {
				otherPurpose = ReviewerKey
			}
			cases := []struct {
				name   string
				offset int
				value  byte
			}{
				{"magic", 0, 0},
				{"zero version", 8, 0},
				{"unsupported version", 8, 2},
				{"zero profile", 9, 0},
				{"unsupported profile", 9, 1},
				{"unknown profile", 9, 3},
				{"maximum profile", 9, 255},
				{"missing purpose", 10, 0},
				{"other purpose", 10, byte(otherPurpose)},
				{"unknown purpose", 10, 255},
				{"reserved", 11, 1},
				{"overflow length", 28, 255},
				{"wrong length", 31, 0},
			}
			backup := formatOnlyBackup(24)
			backup[10] = byte(purpose)
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					mutated := bytes.Clone(backup)
					mutated[tc.offset] = tc.value
					reject(t, mutated)
				})
			}
			for end := range len(backup) {
				reject(t, backup[:end])
			}
			reject(t, append(bytes.Clone(backup), 0))
			for _, size := range []int{0, 1, MaxSecretSize, MaxSecretSize + 1} {
				boundary := formatOnlyBackup(size)
				boundary[10] = byte(purpose)
				if size == 0 || size > MaxSecretSize {
					reject(t, boundary)
				} else if !validBackup(purpose, boundary) {
					t.Fatal("rejected valid size boundary")
				}
			}
		})
	}
}

func TestKeystoreRejectsTampering(t *testing.T) {
	password := []byte("synthetic test password")
	backup, err := Seal(t.Context(), MemberKey, password, []byte("synthetic non-key payload"))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		offset int
	}{
		{"salt", 12},
		{"nonce", 32},
		{"ciphertext", 44},
		{"tag", len(backup) - 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mutated := bytes.Clone(backup)
			mutated[tc.offset] ^= 1
			opened, err := Open(t.Context(), MemberKey, password, mutated)
			if opened != nil || !errors.Is(err, ErrInvalidBackup) {
				t.Fatalf("tampered backup returned output or wrong error: %v", err)
			}
		})
	}
	opened, err := Open(t.Context(), MemberKey, []byte("different synthetic test password"), backup)
	if opened != nil || !errors.Is(err, ErrInvalidBackup) {
		t.Fatalf("wrong password returned output or wrong error: %v", err)
	}
	// Changing both caller expectation and the purpose byte must still fail AEAD
	// authentication. Checking the purpose without authenticating it is insufficient.
	mutated := bytes.Clone(backup)
	mutated[10] = byte(ReviewerKey)
	opened, err = Open(t.Context(), ReviewerKey, password, mutated)
	if opened != nil || !errors.Is(err, ErrInvalidBackup) {
		t.Fatalf("relabelled purpose returned output or wrong error: %v", err)
	}
	for _, resized := range [][]byte{bytes.Clone(backup[:len(backup)-1]), append(bytes.Clone(backup), 0)} {
		binary.BigEndian.PutUint32(resized[28:32], uint32(len(resized)-32))
		opened, err := Open(t.Context(), MemberKey, password, resized)
		if opened != nil || !errors.Is(err, ErrInvalidBackup) {
			t.Fatalf("resized ciphertext returned output or wrong error: %v", err)
		}
	}
}

func TestKeystoreLibraryCompatibility(t *testing.T) {
	// Independently compose profile 2 without the production framing or KDF helper.
	// The payload is not a private key and fixed inputs are only a format test.
	password, payload := []byte("synthetic test password"), []byte("synthetic non-key payload")
	header := append([]byte("ANONCEKS\x01\x02\x01\x00"), bytes.Repeat([]byte{0xa5}, 16)...)
	header = binary.BigEndian.AppendUint32(header, uint32(len(payload)+28))
	key := argon2.IDKey(password, header[12:28], 3, 65536, 4, 32)
	defer clear(key)
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		t.Fatal(err)
	}
	nonce := bytes.Repeat([]byte{0x5a}, 12)
	reference := append(bytes.Clone(header), nonce...)
	reference = aead.Seal(reference, nonce, payload, header)
	opened, err := Open(t.Context(), MemberKey, password, reference)
	if err != nil || !bytes.Equal(opened, payload) {
		t.Fatalf("could not open independently composed backup: %v", err)
	}
	clear(opened)

	backup, err := Seal(t.Context(), MemberKey, password, payload)
	if err != nil {
		t.Fatal(err)
	}
	key2 := argon2.IDKey(password, backup[12:28], 3, 65536, 4, 32)
	defer clear(key2)
	aead2, err := chacha20poly1305.New(key2)
	if err != nil {
		t.Fatal(err)
	}
	opened, err = aead2.Open(nil, backup[32:44], backup[44:], backup[:32])
	if err != nil || !bytes.Equal(opened, payload) {
		t.Fatalf("could not independently open production backup: %v", err)
	}
	clear(opened)
}

func TestKeystoreCancellation(t *testing.T) {
	password := []byte("synthetic test password")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	backup, err := Seal(ctx, MemberKey, password, []byte("synthetic non-key payload"))
	if backup != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("Seal ignored cancellation: %v", err)
	}
	secret, err := Open(ctx, MemberKey, password, formatOnlyBackup(1))
	if secret != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("Open ignored cancellation: %v", err)
	}
	kdfSlot <- struct{}{}
	defer func() { <-kdfSlot }()
	for _, seal := range []bool{true, false} {
		ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
		var output []byte
		var err error
		if seal {
			output, err = Seal(ctx, MemberKey, password, []byte("synthetic non-key payload"))
		} else {
			output, err = Open(ctx, MemberKey, password, formatOnlyBackup(1))
		}
		cancel()
		if output != nil || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("queued operation ignored deadline: %v", err)
		}
	}
}

func TestKeystoreConcurrent(t *testing.T) {
	var wg sync.WaitGroup
	failures := make(chan error, 4)
	for range 4 {
		wg.Go(func() {
			password, payload := []byte("synthetic test password"), []byte("synthetic concurrent payload")
			backup, err := Seal(t.Context(), ReviewerKey, password, payload)
			if err != nil {
				failures <- err
				return
			}
			opened, err := Open(t.Context(), ReviewerKey, password, backup)
			if err != nil || !bytes.Equal(opened, payload) {
				failures <- fmt.Errorf("concurrent round trip failed: %w", err)
			}
			clear(opened)
		})
	}
	wg.Wait()
	close(failures)
	for err := range failures {
		t.Error(err)
	}
	if len(kdfSlot) != 0 {
		t.Fatal("derivation slot was not released")
	}
}

func TestKeystoreCancellationBoundaries(t *testing.T) {
	password := []byte("synthetic test password")
	backup, err := Seal(t.Context(), MemberKey, password, []byte("synthetic non-key payload"))
	if err != nil {
		t.Fatal(err)
	}
	for _, boundary := range []struct {
		name  string
		check int32
	}{
		{"after admission", 2},
		{"after derivation", 3},
		{"before output", 4},
	} {
		for _, seal := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/seal=%t", boundary.name, seal), func(t *testing.T) {
				parent, cancel := context.WithCancel(t.Context())
				defer cancel()
				ctx := &cancelOnCheck{Context: parent, cancel: cancel, trigger: boundary.check}
				var output []byte
				var err error
				if seal {
					output, err = Seal(ctx, MemberKey, password, []byte("synthetic non-key payload"))
				} else {
					output, err = Open(ctx, MemberKey, password, backup)
				}
				if output != nil || !errors.Is(err, context.Canceled) {
					t.Fatalf("operation returned output or ignored cancellation: %v", err)
				}
				if len(kdfSlot) != 0 {
					t.Fatal("cancelled operation retained derivation slot")
				}
			})
		}
	}
}

// Cancel at observation boundaries without timing assumptions, mocking a
// primitive, or replacing the real KDF with a reduced-cost test substitute.
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

// formatOnlyBackup is deliberately unauthenticated, synthetic parser input.
func formatOnlyBackup(size int) []byte {
	backup := make([]byte, 32+28+size)
	copy(backup, "ANONCEKS\x01\x02\x01\x00")
	binary.BigEndian.PutUint32(backup[28:32], uint32(28+size))
	return backup
}

func FuzzBackup(f *testing.F) {
	f.Add(byte(MemberKey), formatOnlyBackup(1))
	reviewer := formatOnlyBackup(64)
	reviewer[10] = byte(ReviewerKey)
	f.Add(byte(ReviewerKey), reviewer)
	f.Add(byte(MemberKey), formatOnlyBackup(0))
	overflowLength := formatOnlyBackup(1)
	binary.BigEndian.PutUint32(overflowLength[28:32], ^uint32(0))
	f.Add(byte(MemberKey), overflowLength)
	unknownProfile := formatOnlyBackup(1)
	unknownProfile[9] = 255
	f.Add(byte(MemberKey), unknownProfile)
	f.Add(byte(MemberKey), []byte("synthetic malformed input"))
	f.Add(byte(0), []byte{})
	f.Fuzz(func(t *testing.T, purpose byte, backup []byte) {
		if len(backup) > MaxBackupSize+1 {
			return
		}
		// Fuzz the structural parser only, never attacker-selected KDF work. Full
		// authentication and real profile costs are exercised by the tests above.
		if !validBackup(Purpose(purpose), backup) {
			return
		}
		if len(backup) < 61 || len(backup) > 65596 ||
			string(backup[:8]) != "ANONCEKS" || backup[8] != 1 || backup[9] != 2 ||
			(purpose != 1 && purpose != 2) || backup[10] != purpose || backup[11] != 0 ||
			uint64(binary.BigEndian.Uint32(backup[28:32]))+32 != uint64(len(backup)) {
			t.Fatal("parser accepted a noncanonical or unbounded backup")
		}
	})
}

func BenchmarkKeystore(b *testing.B) {
	password, payload := []byte("synthetic test password"), []byte("synthetic benchmark payload")
	b.Run("Seal", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, err := Seal(b.Context(), MemberKey, password, payload); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("Open", func(b *testing.B) {
		backup, err := Seal(b.Context(), MemberKey, password, payload)
		if err != nil {
			b.Fatal(err)
		}
		b.ReportAllocs()
		for b.Loop() {
			opened, err := Open(b.Context(), MemberKey, password, backup)
			if err != nil {
				b.Fatal(err)
			}
			clear(opened)
		}
	})
}

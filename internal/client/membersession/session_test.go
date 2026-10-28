// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

package membersession

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/mandipnotroot/anonce/internal/client/keystore"
	"github.com/mandipnotroot/anonce/internal/client/membercsr"
	"github.com/mandipnotroot/anonce/internal/client/memberkey"
)

func testSetup(t *testing.T) (*Session, *Setup, []byte) {
	t.Helper()
	s := new(Session)
	t.Cleanup(s.Lock)
	password := []byte("synthetic session password")
	t.Cleanup(func() { clear(password) })
	setup, err := s.Create(t.Context(), password)
	if err != nil {
		t.Fatal(err)
	}
	return s, setup, password
}

func checkEnrollment(t *testing.T, enrollment *Enrollment, expected ed25519.PublicKey) {
	t.Helper()
	if enrollment == nil || !bytes.Equal(enrollment.PublicKey, expected) {
		t.Fatal("missing or mismatched public enrollment key")
	}
	parsed, err := membercsr.Parse(enrollment.CSR)
	if err != nil || !bytes.Equal(parsed, expected) {
		t.Fatal("request does not validate for expected key")
	}
}

func checkLocked(t *testing.T, s *Session) {
	t.Helper()
	if result, err := s.Request(t.Context()); result != nil || !errors.Is(err, ErrState) {
		t.Fatalf("locked session returned a request or wrong error: %v", err)
	}
}

func TestMemberSessionRoundTrip(t *testing.T) {
	s, setup, password := testSetup(t)
	expected := ed25519.PublicKey(bytes.Clone(setup.PublicKey))
	checkEnrollment(t, &setup.Enrollment, expected)
	if len(setup.Backup) != 108 || setup.Backup[9] != 2 {
		t.Fatal("setup changed backup size or profile")
	}
	key, err := memberkey.Open(t.Context(), password, setup.Backup)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	if !bytes.Equal(key[ed25519.SeedSize:], expected) {
		t.Fatal("setup backup holds a different key")
	}
	request, err := s.Request(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	checkEnrollment(t, request, expected)
	if !bytes.Equal(request.CSR, setup.CSR) {
		t.Fatal("session changed the deterministic request")
	}
	// Caller mutation of public output must not change the retained private key.
	clear(setup.PublicKey)
	clear(setup.CSR)
	clear(request.PublicKey)
	clear(request.CSR)
	request, err = s.Request(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	checkEnrollment(t, request, expected)
	owned := s.key
	s.Lock()
	s.Lock()
	if !bytes.Equal(owned, make([]byte, ed25519.PrivateKeySize)) {
		t.Fatal("lock did not clear owned private bytes")
	}
	checkLocked(t, s)
	backupCopy, passwordCopy := bytes.Clone(setup.Backup), bytes.Clone(password)
	defer clear(passwordCopy)
	publicCopy := bytes.Clone(expected)
	restored, err := s.Unlock(t.Context(), password, setup.Backup, expected)
	if err != nil {
		t.Fatal(err)
	}
	checkEnrollment(t, restored, expected)
	if !bytes.Equal(setup.Backup, backupCopy) || !bytes.Equal(password, passwordCopy) || !bytes.Equal(expected, publicCopy) {
		t.Fatal("restoration changed caller inputs")
	}
	clear(restored.PublicKey)
	clear(restored.CSR)
	request, err = s.Request(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	checkEnrollment(t, request, expected)
}

func TestMemberSessionFreshSetup(t *testing.T) {
	s, first, password := testSetup(t)
	s.Lock()
	second, err := s.Create(t.Context(), password)
	if err != nil {
		t.Fatal(err)
	}
	checkEnrollment(t, &second.Enrollment, second.PublicKey)
	if bytes.Equal(first.PublicKey, second.PublicKey) || bytes.Equal(first.Backup[12:28], second.Backup[12:28]) ||
		bytes.Equal(first.Backup[32:44], second.Backup[32:44]) {
		t.Fatal("fresh setup reused key, salt, or nonce")
	}
}

func TestMemberSessionPasswordOwnership(t *testing.T) {
	s := new(Session)
	defer s.Lock()
	password := bytes.Repeat([]byte{0, '\r', '\n', 0xff}, keystore.MaxPasswordSize/4)
	defer clear(password)
	original := bytes.Clone(password)
	defer clear(original)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	setup, err := s.Create(ctx, password)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(password, original) {
		t.Fatal("creation changed caller password")
	}
	clear(password)
	cancel() // An operation context does not own the unlocked session lifetime.
	request, err := s.Request(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	checkEnrollment(t, request, setup.PublicKey)
	s.Lock()
	restored, err := s.Unlock(t.Context(), original, setup.Backup, setup.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	checkEnrollment(t, restored, setup.PublicKey)
}

func TestMemberSessionRejectsInvalidInputs(t *testing.T) {
	cases := []struct {
		name     string
		password []byte
		expected ed25519.PublicKey
	}{
		{"empty password", nil, make([]byte, ed25519.PublicKeySize)},
		{"oversized password", make([]byte, keystore.MaxPasswordSize+1), make([]byte, ed25519.PublicKeySize)},
		{"missing expected key", []byte("synthetic password"), nil},
		{"short expected key", []byte("synthetic password"), make([]byte, ed25519.PublicKeySize-1)},
		{"oversized expected key", []byte("synthetic password"), make([]byte, ed25519.PublicKeySize+1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := new(Session)
			defer s.Lock()
			if result, err := s.Unlock(t.Context(), tc.password, nil, tc.expected); result != nil || !errors.Is(err, keystore.ErrInvalidInput) {
				t.Fatalf("invalid unlock returned output or wrong error: %v", err)
			}
			if len(tc.password) == 0 || len(tc.password) > keystore.MaxPasswordSize {
				if result, err := s.Create(t.Context(), tc.password); result != nil || !errors.Is(err, keystore.ErrInvalidInput) {
					t.Fatalf("invalid setup returned output or wrong error: %v", err)
				}
			}
			if s.pending != nil {
				t.Fatal("invalid input retained pending work")
			}
			checkLocked(t, s)
		})
	}
}

func TestMemberSessionUnlockRejectsBackup(t *testing.T) {
	s, setup, password := testSetup(t)
	s.Lock()
	wrongPurpose := bytes.Clone(setup.Backup)
	wrongPurpose[10] = byte(keystore.ReviewerKey)
	unsupported := bytes.Clone(setup.Backup)
	unsupported[9] = 0xff
	tampered := bytes.Clone(setup.Backup)
	tampered[len(tampered)-1] ^= 1
	nonkey, err := keystore.Seal(t.Context(), keystore.MemberKey, password, make([]byte, 48))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name     string
		password []byte
		backup   []byte
	}{
		{"wrong password", []byte("different synthetic password"), setup.Backup},
		{"wrong purpose", password, wrongPurpose},
		{"unsupported profile", password, unsupported},
		{"ciphertext tampering", password, tampered},
		{"authenticated non-key", password, nonkey},
		{"missing backup", password, nil},
		{"trailing bytes", password, append(bytes.Clone(setup.Backup), 0)},
		{"oversized backup", password, make([]byte, keystore.MaxBackupSize+1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := bytes.Clone(tc.backup)
			result, err := s.Unlock(t.Context(), tc.password, tc.backup, setup.PublicKey)
			if result != nil || !errors.Is(err, keystore.ErrInvalidBackup) {
				t.Fatalf("invalid backup returned output or wrong error: %v", err)
			}
			if !bytes.Equal(before, tc.backup) || s.pending != nil {
				t.Fatal("failed restoration changed input or retained pending work")
			}
			for _, sensitive := range []string{string(tc.password), hex.EncodeToString(setup.PublicKey)} {
				if strings.Contains(err.Error(), sensitive) {
					t.Fatal("restoration error reflected sensitive input")
				}
			}
			checkLocked(t, s)
		})
	}
	// A failed restoration must not poison the next correctly bound attempt.
	result, err := s.Unlock(t.Context(), password, setup.Backup, setup.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	checkEnrollment(t, result, setup.PublicKey)
}

func TestMemberSessionExpectedKey(t *testing.T) {
	s, setup, password := testSetup(t)
	s.Lock()
	for i := range ed25519.PublicKeySize {
		expected := ed25519.PublicKey(bytes.Clone(setup.PublicKey))
		expected[i] ^= 1
		result, err := s.Unlock(t.Context(), password, setup.Backup, expected)
		if result != nil || !errors.Is(err, ErrKeyMismatch) || s.pending != nil {
			t.Fatalf("mismatched expected key byte %d returned output or wrong error: %v", i, err)
		}
		checkLocked(t, s)
	}
}

func TestMemberSessionState(t *testing.T) {
	s, setup, password := testSetup(t)
	if result, err := s.Create(t.Context(), password); result != nil || !errors.Is(err, ErrState) {
		t.Fatalf("setup replaced unlocked key: %v", err)
	}
	if result, err := s.Unlock(t.Context(), password, nil, setup.PublicKey); result != nil || !errors.Is(err, ErrState) {
		t.Fatalf("restore replaced unlocked key: %v", err)
	}
	request, err := s.Request(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	checkEnrollment(t, request, setup.PublicKey)
	s.Lock()
	op, err := s.begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer s.end(op)
	for _, lock := range []bool{false, true} {
		if lock {
			s.Lock()
			if !errors.Is(op.ctx.Err(), context.Canceled) {
				t.Fatal("lock did not cancel pending work")
			}
		}
		if result, err := s.Create(t.Context(), password); result != nil || !errors.Is(err, ErrState) {
			t.Fatalf("setup admitted work while pending: %v", err)
		}
		if result, err := s.Unlock(t.Context(), password, nil, setup.PublicKey); result != nil || !errors.Is(err, ErrState) {
			t.Fatalf("restore admitted work while pending: %v", err)
		}
		checkLocked(t, s)
	}
}

func TestMemberSessionCancellation(t *testing.T) {
	s, setup, password := testSetup(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if result, err := s.Create(ctx, password); result != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled setup returned output: %v", err)
	}
	if result, err := s.Unlock(ctx, password, setup.Backup, setup.PublicKey); result != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled restoration returned output: %v", err)
	}
	if result, err := s.Request(ctx); result != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled request returned output: %v", err)
	}
	s.Lock()
	for _, boundary := range []string{"before prepare", "before install"} {
		t.Run(boundary, func(t *testing.T) {
			op, err := s.begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer s.end(op)
			key, err := memberkey.Generate(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer clear(key)
			if boundary == "before prepare" {
				s.Lock()
			} else {
				// Create checks at entry and after signing. Cancel at the final
				// installation check to exercise the lock-protected commit boundary.
				op.ctx = &cancelOnCheck{Context: op.ctx, cancel: op.cancel, trigger: 3}
			}
			result, err := s.install(op, key)
			if result != nil || !errors.Is(err, context.Canceled) {
				t.Fatalf("cancelled installation returned output: %v", err)
			}
			if !bytes.Equal(key, make([]byte, len(key))) {
				t.Fatal("failed installation retained private bytes")
			}
			checkLocked(t, s)
		})
	}
}

type cancelOnCheck struct {
	context.Context
	cancel  context.CancelFunc
	checks  int
	trigger int
}

func (c *cancelOnCheck) Err() error {
	c.checks++
	if c.checks == c.trigger {
		c.cancel()
	}
	return c.Context.Err()
}

func TestMemberSessionPendingLock(t *testing.T) {
	s, setup, password := testSetup(t)
	s.Lock()
	for _, action := range []string{"create", "createConfirmed", "unlock"} {
		t.Run(action, func(t *testing.T) {
			// Hold the shared derivation slot before Argon2id. No session call
			// can finish cryptographic work until this barrier is released.
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			gate := &derivationGate{Context: ctx, entered: make(chan struct{}), release: make(chan struct{})}
			holderDone := make(chan struct{})
			go func() {
				defer close(holderDone)
				_, err := keystore.Seal(gate, keystore.MemberKey, password, []byte("synthetic non-key payload"))
				if !errors.Is(err, context.Canceled) {
					t.Errorf("derivation barrier returned wrong error: %v", err)
				}
			}()
			defer func() {
				cancel()
				close(gate.release)
				<-holderDone
			}()
			<-gate.entered
			started := &notifyContext{Context: t.Context(), entered: make(chan struct{})}
			done := make(chan error, 1)
			go func() {
				if action == "create" || action == "createConfirmed" {
					var result *Setup
					var err error
					if action == "createConfirmed" {
						result, err = s.CreateConfirmed(started, password, password)
					} else {
						result, err = s.Create(started, password)
					}
					if result != nil {
						t.Error("locked pending setup returned public output")
					}
					done <- err
					return
				}
				result, err := s.Unlock(started, password, setup.Backup, setup.PublicKey)
				if result != nil {
					t.Error("locked pending restoration returned public output")
				}
				done <- err
			}()
			<-started.entered // WithCancel has begun admitting this operation.
			s.Lock()
			if err := <-done; !errors.Is(err, context.Canceled) {
				t.Fatalf("pending operation ignored lock: %v", err)
			}
			if s.pending != nil {
				t.Fatal("cancelled operation did not finish admission cleanup")
			}
			checkLocked(t, s)
		})
	}
}

type derivationGate struct {
	context.Context
	checks  int
	entered chan struct{}
	release chan struct{}
}

func (c *derivationGate) Err() error {
	c.checks++
	if c.checks == 2 {
		close(c.entered)
		<-c.release
	}
	return c.Context.Err()
}

type notifyContext struct {
	context.Context
	once    sync.Once
	entered chan struct{}
}

func (c *notifyContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.entered) })
	return c.Context.Done()
}

func TestMemberSessionConcurrent(t *testing.T) {
	s := new(Session)
	defer s.Lock()
	password := []byte("synthetic concurrent password")
	defer clear(password)
	var successes atomic.Int32
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			result, err := s.Create(t.Context(), password)
			if err == nil {
				successes.Add(1)
				checkEnrollment(t, &result.Enrollment, result.PublicKey)
			} else if result != nil || !errors.Is(err, ErrState) {
				t.Errorf("concurrent setup returned wrong result: %v", err)
			}
		})
	}
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatal("concurrent setup did not install exactly one key")
	}
	for range 8 {
		wg.Go(func() {
			for range 8 {
				result, err := s.Request(t.Context())
				if err == nil {
					checkEnrollment(t, result, result.PublicKey)
				} else if result != nil || !errors.Is(err, ErrState) {
					t.Errorf("request racing lock returned wrong result: %v", err)
				}
				s.Lock()
			}
		})
	}
	wg.Wait()
	checkLocked(t, s)
}

func FuzzMemberSessionUnlockInputs(f *testing.F) {
	f.Add([]byte{}, []byte{}, []byte{})
	f.Add([]byte("synthetic password"), make([]byte, 108), []byte("short public key"))
	f.Add(make([]byte, keystore.MaxPasswordSize+1), []byte{}, make([]byte, ed25519.PublicKeySize))
	f.Fuzz(func(t *testing.T, password, backup, expected []byte) {
		if len(password) > keystore.MaxPasswordSize+1 || len(backup) > keystore.MaxBackupSize+1 || len(expected) > ed25519.PublicKeySize+1 {
			return
		}
		locked := new(Session)
		output, err := locked.Backup(t.Context(), password)
		want := ErrState
		if len(password) == 0 || len(password) > keystore.MaxPasswordSize {
			want = keystore.ErrInvalidInput
		}
		if output != nil || !errors.Is(err, want) || locked.pending != nil {
			t.Fatal("locked backup admission returned output or retained work")
		}
		// Exercise admission bounds without derivation. Backup grammar and typed
		// payload parsing retain their shared, separately fuzzed implementations.
		if len(password) > 0 && len(password) <= keystore.MaxPasswordSize && len(expected) == ed25519.PublicKeySize {
			return
		}
		s := new(Session)
		defer s.Lock()
		result, err := s.Unlock(t.Context(), password, backup, expected)
		if result != nil || !errors.Is(err, keystore.ErrInvalidInput) || s.pending != nil {
			t.Fatalf("invalid admission returned output or wrong error: %v", err)
		}
		checkLocked(t, s)
	})
}

// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

package membersession

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/mandipnotroot/anonce/internal/client/keystore"
	"github.com/mandipnotroot/anonce/internal/client/memberkey"
)

func TestMemberSessionBackup(t *testing.T) {
	s, setup, originalPassword := testSetup(t)
	original, err := memberkey.Open(t.Context(), originalPassword, setup.Backup)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(original)
	for _, tc := range []struct {
		name     string
		password []byte
	}{
		{"same password", bytes.Clone(originalPassword)},
		{"minimum password", []byte{0xff}},
		{"maximum opaque password", bytes.Repeat([]byte{0, '\n', '\r', 0xff}, 256)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer clear(tc.password)
			before := bytes.Clone(tc.password)
			defer clear(before)
			backup, err := s.Backup(t.Context(), tc.password)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(tc.password, before) || len(backup) != 108 || backup[9] != 2 ||
				bytes.Equal(backup[12:28], setup.Backup[12:28]) || bytes.Equal(backup[32:44], setup.Backup[32:44]) {
				t.Fatal("export changed input/profile or reused backup randomness")
			}
			key, err := memberkey.Open(t.Context(), tc.password, backup)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(key)
			if !bytes.Equal(key, original) {
				t.Fatal("export rotated the member key")
			}
			if tc.name != "same password" {
				wrong, err := memberkey.Open(t.Context(), []byte("synthetic different password"), backup)
				defer clear(wrong)
				if wrong != nil || !errors.Is(err, keystore.ErrInvalidBackup) {
					t.Fatal("export accepted a different password")
				}
			}
			clear(backup) // Caller mutation cannot alter the retained key.
			request, err := s.Request(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			checkEnrollment(t, request, setup.PublicKey)
		})
	}
	// Old ciphertext remains valid. Export is not revocation or deletion.
	key, err := memberkey.Open(t.Context(), originalPassword, setup.Backup)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	if !bytes.Equal(key, original) {
		t.Fatal("export changed the original backup")
	}
}

func TestMemberSessionBackupState(t *testing.T) {
	s, setup, password := testSetup(t)
	for _, input := range [][]byte{nil, make([]byte, keystore.MaxPasswordSize+1)} {
		if backup, err := s.Backup(t.Context(), input); backup != nil || !errors.Is(err, keystore.ErrInvalidInput) {
			t.Fatalf("invalid password returned output or wrong error: %v", err)
		}
	}
	op, key, err := s.beginBackup(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer s.end(op)
	defer clear(key)
	for _, action := range []string{"create", "unlock", "backup"} {
		t.Run(action, func(t *testing.T) {
			var err error
			switch action {
			case "create":
				_, err = s.Create(t.Context(), password)
			case "unlock":
				_, err = s.Unlock(t.Context(), password, setup.Backup, setup.PublicKey)
			case "backup":
				_, err = s.Backup(t.Context(), password)
			}
			if !errors.Is(err, ErrState) {
				t.Fatalf("busy export admitted another operation: %v", err)
			}
		})
	}
	request, err := s.Request(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	checkEnrollment(t, request, setup.PublicKey)
	owned := s.key
	s.Lock()
	if !bytes.Equal(owned, make([]byte, ed25519.PrivateKeySize)) || !bytes.Equal(key[32:], setup.PublicKey) {
		t.Fatal("export snapshot aliases the locked session key")
	}
	if !errors.Is(op.ctx.Err(), context.Canceled) {
		t.Fatal("lock did not cancel pending export")
	}
	if backup, err := s.Backup(t.Context(), password); backup != nil || !errors.Is(err, ErrState) {
		t.Fatalf("locked export returned output or wrong error: %v", err)
	}
	checkLocked(t, s)
}

func TestMemberSessionBackupCancellation(t *testing.T) {
	s, setup, password := testSetup(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if backup, err := s.Backup(ctx, password); backup != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled export returned output or wrong error: %v", err)
	}
	for _, action := range []string{"cancel", "lock"} {
		t.Run(action, func(t *testing.T) {
			// Hold derivation admission so cancellation is deterministic, without
			// weakening profile costs or relying on scheduler timing.
			holderCtx, cancelHolder := context.WithCancel(t.Context())
			gate := &derivationGate{Context: holderCtx, entered: make(chan struct{}), release: make(chan struct{})}
			holderDone := make(chan struct{})
			go func() {
				defer close(holderDone)
				_, err := keystore.Seal(gate, keystore.MemberKey, password, []byte("synthetic non-key payload"))
				if !errors.Is(err, context.Canceled) {
					t.Errorf("derivation barrier: %v", err)
				}
			}()
			defer func() { cancelHolder(); close(gate.release); <-holderDone }()
			<-gate.entered
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			started := &notifyContext{Context: ctx, entered: make(chan struct{})}
			done := make(chan error, 1)
			go func() {
				backup, err := s.Backup(started, password)
				if backup != nil {
					t.Error("cancelled export returned ciphertext")
				}
				done <- err
			}()
			<-started.entered
			if action == "lock" {
				s.Lock()
			} else {
				cancel()
			}
			err := <-done
			if !errors.Is(err, context.Canceled) || strings.Contains(err.Error(), string(password)) || s.pending != nil {
				t.Fatalf("export cancellation failed: %v", err)
			}
			if action == "lock" {
				checkLocked(t, s)
			} else {
				request, err := s.Request(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				checkEnrollment(t, request, setup.PublicKey)
			}
		})
	}
}

func TestMemberSessionBackupConcurrent(t *testing.T) {
	s, setup, password := testSetup(t)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			backup, err := s.Backup(t.Context(), password)
			if err == nil {
				key, err := memberkey.Open(t.Context(), password, backup)
				defer clear(key)
				if err != nil || !bytes.Equal(key[32:], setup.PublicKey) {
					t.Error("concurrent export changed the member key")
				}
			} else if backup != nil || (!errors.Is(err, ErrState) && !errors.Is(err, context.Canceled)) {
				t.Errorf("concurrent export returned wrong result: %v", err)
			}
			s.Lock()
		})
	}
	wg.Wait()
	checkLocked(t, s)
}

func TestMemberSessionBackupPublication(t *testing.T) {
	for _, action := range []string{"publish", "cancel", "lock"} {
		t.Run(action, func(t *testing.T) {
			s, setup, _ := testSetup(t)
			op, key, err := s.beginBackup(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer s.end(op)
			defer clear(key)
			// A synthetic ciphertext stand-in isolates the publication boundary
			// after encryption, without timing an actual derivation or scheduler.
			ciphertext := bytes.Repeat([]byte{7}, 108)
			switch action {
			case "lock":
				s.Lock()
			case "cancel":
				op.cancel()
			}
			backup, err := s.publishBackup(op, ciphertext)
			if action == "publish" {
				if err != nil || !bytes.Equal(backup, ciphertext) || backup[0] != 7 {
					t.Fatal("live publication discarded ciphertext")
				}
				s.Lock()
				if backup[0] != 7 {
					t.Fatal("lock retracted already published ciphertext")
				}
			} else if backup != nil || !errors.Is(err, context.Canceled) || !bytes.Equal(ciphertext, make([]byte, 108)) {
				t.Fatal("cancelled publication retained ciphertext or returned output")
			}
			if action == "cancel" {
				request, err := s.Request(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				checkEnrollment(t, request, setup.PublicKey)
			} else {
				checkLocked(t, s)
			}
		})
	}
}

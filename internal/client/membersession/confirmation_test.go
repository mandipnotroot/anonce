// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

package membersession

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/mandipnotroot/anonce/internal/client/keystore"
	"github.com/mandipnotroot/anonce/internal/client/memberkey"
)

func TestMemberSessionConfirmation(t *testing.T) {
	for _, size := range []int{1, keystore.MaxPasswordSize} {
		password := bytes.Repeat([]byte{0xff, 0, '\r', '\n'}, keystore.MaxPasswordSize/4)[:size]
		confirmation := bytes.Clone(password)
		defer clear(password)
		defer clear(confirmation)
		s := new(Session)
		defer s.Lock()
		setup, err := s.CreateConfirmed(t.Context(), password, confirmation)
		if err != nil {
			t.Fatal(err)
		}
		checkEnrollment(t, &setup.Enrollment, setup.PublicKey)
		original, err := memberkey.Open(t.Context(), password, setup.Backup)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(original)
		password[0] ^= 1
		confirmation[0] ^= 1
		backup, err := s.BackupConfirmed(t.Context(), password, confirmation)
		if err != nil {
			t.Fatal(err)
		}
		restored, err := memberkey.Open(t.Context(), password, backup)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(restored)
		if !bytes.Equal(original, restored) || !bytes.Equal(password, confirmation) ||
			len(backup) != 108 || bytes.Equal(backup[12:28], setup.Backup[12:28]) ||
			bytes.Equal(backup[32:44], setup.Backup[32:44]) {
			t.Fatal("confirmed export changed inputs/key/profile or reused randomness")
		}
		s.Lock()
		if _, err := s.Unlock(t.Context(), password, backup, setup.PublicKey); err != nil {
			t.Fatal(err)
		}
	}
}

func TestMemberSessionRejectsConfirmation(t *testing.T) {
	s, setup, _ := testSetup(t)
	for _, tc := range []struct {
		name                   string
		password, confirmation []byte
		want                   error
	}{
		{"missing password", nil, []byte{1}, keystore.ErrInvalidInput},
		{"missing confirmation", []byte{1}, nil, keystore.ErrInvalidInput},
		{"long password", make([]byte, 1025), []byte{1}, keystore.ErrInvalidInput},
		{"long confirmation", []byte{1}, make([]byte, 1025), keystore.ErrInvalidInput},
		{"different length", []byte{1}, []byte{1, 1}, ErrPasswordMismatch},
		{"different first byte", []byte{1, 2}, []byte{0, 2}, ErrPasswordMismatch},
		{"different last byte", []byte{1, 2}, []byte{1, 3}, ErrPasswordMismatch},
		{"no trimming", []byte("synthetic password"), []byte("synthetic password "), ErrPasswordMismatch},
	} {
		t.Run(tc.name, func(t *testing.T) {
			password, confirmation := bytes.Clone(tc.password), bytes.Clone(tc.confirmation)
			defer clear(password)
			defer clear(confirmation)
			locked := new(Session)
			defer locked.Lock()
			created, createErr := locked.CreateConfirmed(t.Context(), password, confirmation)
			backup, backupErr := s.BackupConfirmed(t.Context(), password, confirmation)
			if created != nil || backup != nil || !errors.Is(createErr, tc.want) || !errors.Is(backupErr, tc.want) ||
				locked.pending != nil || s.pending != nil || !bytes.Equal(password, tc.password) || !bytes.Equal(confirmation, tc.confirmation) {
				t.Fatal("invalid confirmation produced output, changed inputs, or retained work")
			}
			if strings.Contains(createErr.Error(), "synthetic password") || strings.Contains(backupErr.Error(), "synthetic password") {
				t.Fatal("confirmation error reflected input")
			}
			checkLocked(t, locked)
			request, err := s.Request(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			checkEnrollment(t, request, setup.PublicKey)
		})
	}
}

func TestMemberSessionConfirmationStateAndCancellation(t *testing.T) {
	password := []byte("synthetic confirmed password")
	defer clear(password)
	s := new(Session)
	defer s.Lock()
	if backup, err := s.BackupConfirmed(t.Context(), password, password); backup != nil || !errors.Is(err, ErrState) {
		t.Fatal("confirmed backup admitted locked session")
	}
	op, err := s.begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer s.end(op)
	if setup, err := s.CreateConfirmed(t.Context(), password, password); setup != nil || !errors.Is(err, ErrState) {
		t.Fatal("confirmed setup admitted busy session")
	}
	for _, trigger := range []int{1, 3} {
		ctx, cancel := context.WithCancel(t.Context())
		checked := &cancelOnCheck{Context: ctx, cancel: cancel, trigger: trigger}
		setup, err := s.CreateConfirmed(checked, password, password)
		if setup != nil || !errors.Is(err, context.Canceled) {
			t.Fatal("confirmed setup ignored cancellation before or after confirmation")
		}
		cancel()
		ctx, cancel = context.WithCancel(t.Context())
		checked = &cancelOnCheck{Context: ctx, cancel: cancel, trigger: trigger}
		backup, err := s.BackupConfirmed(checked, password, password)
		if backup != nil || !errors.Is(err, context.Canceled) {
			t.Fatal("confirmed export ignored cancellation before or after confirmation")
		}
		cancel()
	}
}

func FuzzMemberSessionConfirmation(f *testing.F) {
	f.Add([]byte{0, 0xff}, []byte{0, 0xff})
	f.Add([]byte("synthetic password"), []byte("synthetic mismatch"))
	f.Add([]byte{}, make([]byte, 1025))
	f.Fuzz(func(t *testing.T, password, confirmation []byte) {
		if len(password) > 1025 || len(confirmation) > 1025 {
			return
		}
		var want error
		switch {
		case len(password) == 0 || len(password) > 1024 || len(confirmation) == 0 || len(confirmation) > 1024:
			want = keystore.ErrInvalidInput
		case !bytes.Equal(password, confirmation):
			want = ErrPasswordMismatch
		}
		if err := confirmPassword(t.Context(), password, confirmation); !errors.Is(err, want) {
			t.Fatal("incorrect bounded confirmation decision")
		}
	})
}

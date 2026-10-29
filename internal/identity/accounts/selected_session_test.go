// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

package accounts

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

func TestSelectedSessionAdmission(t *testing.T) {
	t.Parallel()
	for _, store := range []*Store{nil, {}} {
		for _, cancelled := range []bool{false, true} {
			for _, size := range []int{0, 1, TokenSize - 1, TokenSize, TokenSize + 1, 4096} {
				for _, target := range []SessionID{{}, {1}, {255}} {
					ctx, cancel := context.WithCancel(t.Context())
					if cancelled {
						cancel()
					}
					token := bytes.Repeat([]byte{'x'}, size)
					before := bytes.Clone(token)
					want := ErrUnavailable
					if target == (SessionID{}) {
						want = ErrInvalidInput
					} else if size == TokenSize && cancelled {
						want = context.Canceled
					}
					if removed, err := store.RevokeSession(ctx, token, target); removed || !errors.Is(err, want) || !bytes.Equal(before, token) {
						t.Fatal("selected revocation admission or input ownership differs")
					}
					cancel()
				}
			}
		}
	}
}

func FuzzSelectedSessionAdmission(f *testing.F) {
	f.Add(bytes.Repeat([]byte{'x'}, TokenSize), []byte{1})
	f.Add([]byte{}, []byte{})
	f.Add([]byte("synthetic-input"), bytes.Repeat([]byte{255}, len(SessionID{})))
	f.Fuzz(func(t *testing.T, token, rawTarget []byte) {
		if len(token) > TokenSize+1 || len(rawTarget) > len(SessionID{}) {
			return
		}
		var target SessionID
		copy(target[:], rawTarget)
		before, targetBefore := bytes.Clone(token), bytes.Clone(rawTarget)
		want := ErrUnavailable
		if target == (SessionID{}) {
			want = ErrInvalidInput
		}
		var store Store
		if removed, err := store.RevokeSession(t.Context(), token, target); removed || !errors.Is(err, want) || !bytes.Equal(before, token) || !bytes.Equal(targetBefore, rawTarget) {
			t.Fatal("selected revocation admission or input ownership differs")
		}
	})
}

// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

package accounts

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
)

func TestSessionDisableAdmission(t *testing.T) {
	t.Parallel()
	for _, store := range []*Store{nil, {}} {
		for _, cancelled := range []bool{false, true} {
			for _, size := range []int{0, 1, TokenSize - 1, TokenSize, TokenSize + 1, 4096} {
				ctx, cancel := context.WithCancel(t.Context())
				if cancelled {
					cancel()
				}
				token := bytes.Repeat([]byte{'x'}, size)
				before := bytes.Clone(token)
				want := ErrUnavailable
				if size == TokenSize && cancelled {
					want = context.Canceled
				}
				var wg sync.WaitGroup
				for range 4 {
					wg.Go(func() {
						if err := store.DisableForSession(ctx, token); !errors.Is(err, want) || !bytes.Equal(before, token) {
							t.Error("session-disable admission or input ownership differs")
						}
					})
				}
				wg.Wait()
				cancel()
			}
		}
	}
}

func FuzzSessionDisableAdmission(f *testing.F) {
	f.Add(bytes.Repeat([]byte{'x'}, TokenSize), false)
	f.Add([]byte{}, true)
	f.Add([]byte("synthetic-input"), false)
	f.Fuzz(func(t *testing.T, token []byte, cancelled bool) {
		if len(token) > TokenSize+1 {
			return
		}
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		if cancelled {
			cancel()
		}
		before := bytes.Clone(token)
		want := ErrUnavailable
		if len(token) == TokenSize && cancelled {
			want = context.Canceled
		}
		var store Store
		if err := store.DisableForSession(ctx, token); !errors.Is(err, want) || !bytes.Equal(before, token) {
			t.Fatal("session-disable admission or input ownership differs")
		}
	})
}

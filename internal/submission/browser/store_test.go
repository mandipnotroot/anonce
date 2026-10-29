// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

package browser

import (
	"context"
	"errors"
	"testing"
)

func TestUnavailableStore(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for _, store := range []*Store{nil, {}} {
		for _, ctx := range []context.Context{t.Context(), ctx} {
			for _, operation := range []func() error{
				func() error { return store.Publish(ctx, nil) },
				func() error {
					_, raw, err := store.Bulletin(ctx, make([]byte, 16))
					if raw != nil {
						t.Fatal("unexpected bulletin")
					}
					return err
				},
				func() error {
					out, err := store.Accept(ctx, nil, nil, nil, nil)
					if out != nil {
						t.Fatal("unexpected acceptance")
					}
					return err
				},
				func() error {
					out, err := store.Challenge(ctx, nil, nil, nil)
					if out != nil {
						t.Fatal("unexpected challenge")
					}
					return err
				},
				func() error {
					out, cursor, err := store.Read(ctx, nil, nil)
					if out != nil || cursor != nil {
						t.Fatal("unexpected ciphertexts")
					}
					return err
				},
			} {
				if err := operation(); !errors.Is(err, ErrDenied) || ctx.Err() != nil && !errors.Is(err, ctx.Err()) {
					t.Fatal("unavailable operation did not fail closed with cancellation")
				}
			}
		}
	}
}

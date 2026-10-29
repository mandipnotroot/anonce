// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

package browser

import (
	"context"
	"errors"
	"testing"

	"github.com/mandipnotroot/anonce/internal/identity/accounts"
)

func TestUnavailableStore(t *testing.T) {
	for _, store := range []*Store{nil, {}} {
		for _, ctx := range []context.Context{t.Context(), cancelledContext(t)} {
			for _, operation := range []func() error{
				func() error { _, err := store.User(ctx, "synthetic"); return err },
				func() error { return store.Register(ctx, User{}) },
				func() error { _, err := store.Login(ctx, "synthetic", nil); return err },
				func() error { return store.SaveCeremony(ctx, make([]byte, 32), "login", []byte("{}")) },
				func() error { _, err := store.TakeCeremony(ctx, make([]byte, 32), "login"); return err },
				func() error { _, err := store.Current(ctx, make([]byte, 32)); return err },
				func() error { _, err := store.Invite(ctx, make([]byte, 32)); return err },
			} {
				if err := operation(); !errors.Is(err, ErrDenied) || ctx.Err() != nil && !errors.Is(err, ctx.Err()) {
					t.Fatal("unavailable operation did not fail closed with cancellation")
				}
			}
		}
	}
}

func cancelledContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	return ctx
}

func TestUsernameAndCredentialAdmission(t *testing.T) {
	for _, tc := range []struct {
		name string
		want bool
	}{{"member_one", true}, {"ab", false}, {"MixedCase", false}, {"member.one", false}, {"member\x00", false}} {
		if ValidUsername(tc.name) != tc.want {
			t.Fatal("username profile mismatch")
		}
	}
	u := User{ID: accounts.ID{1}, Name: "synthetic"}
	if len(u.WebAuthnID()) != 16 || u.WebAuthnName() != u.Name || u.WebAuthnDisplayName() != u.Name || u.WebAuthnCredentials() != nil {
		t.Fatal("unregistered credential profile mismatch")
	}
}

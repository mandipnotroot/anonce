// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

package accounts

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestAccountAdmission(t *testing.T) {
	t.Parallel()
	var store Store
	id := ID{1}
	if got, err := New(t.Context(), nil); got != nil || !errors.Is(err, ErrInvalidInput) {
		t.Fatal("nil pool admitted")
	}
	for _, lifetime := range []time.Duration{-time.Second, 0, time.Nanosecond, time.Second - 1, time.Second + 1, MaxLifetime + time.Second} {
		if token, session, err := store.StartSession(t.Context(), id, lifetime); token != nil || session != (Session{}) || !errors.Is(err, ErrInvalidInput) {
			t.Fatal("invalid session lifetime admitted")
		}
	}
	for _, lifetime := range []time.Duration{time.Second, time.Minute, MaxLifetime - time.Second, MaxLifetime} {
		if token, session, err := store.StartSession(t.Context(), id, lifetime); token != nil || session != (Session{}) || !errors.Is(err, ErrUnavailable) {
			t.Fatal("valid lifetime did not reach store admission")
		}
	}
	if _, _, err := store.StartSession(t.Context(), ID{}, time.Second); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("zero account admitted")
	}
	for _, size := range []int{0, 1, TokenSize - 1, TokenSize + 1, 4096} {
		token := bytes.Repeat([]byte{'x'}, size)
		if fresh, session, err := store.RotateSession(t.Context(), id, token); fresh != nil || session != (Session{}) || !errors.Is(err, ErrUnavailable) {
			t.Fatal("invalid rotation token admitted")
		}
		if session, err := store.Resolve(t.Context(), token); session != (Session{}) || !errors.Is(err, ErrUnavailable) {
			t.Fatal("invalid token resolved")
		}
		if err := store.Revoke(t.Context(), token); !errors.Is(err, ErrInvalidInput) {
			t.Fatal("invalid revocation admitted")
		}
		if sessions, err := store.ListSessions(t.Context(), token); sessions != nil || !errors.Is(err, ErrUnavailable) {
			t.Fatal("invalid inventory bearer admitted")
		}
		if count, err := store.RevokeOtherSessions(t.Context(), token); count != 0 || !errors.Is(err, ErrUnavailable) {
			t.Fatal("invalid sibling-revocation bearer admitted")
		}
	}
	if fresh, session, err := store.RotateSession(t.Context(), ID{}, make([]byte, TokenSize)); fresh != nil || session != (Session{}) || !errors.Is(err, ErrInvalidInput) {
		t.Fatal("zero rotation account admitted")
	}
	for _, limit := range []int{-1, 0, 1001} {
		if count, err := store.PurgeExpired(t.Context(), limit); count != 0 || !errors.Is(err, ErrInvalidInput) {
			t.Fatal("invalid purge bound admitted")
		}
	}
	for _, invalidate := range []func(context.Context, ID) error{store.Disable, store.RevokeAll} {
		if err := invalidate(t.Context(), ID{}); !errors.Is(err, ErrInvalidInput) {
			t.Fatal("zero account invalidation admitted")
		}
	}
}

func TestAccountUnavailableAndCancellation(t *testing.T) {
	t.Parallel()
	for _, store := range []*Store{nil, {}} {
		for _, cancelled := range []bool{false, true} {
			ctx, cancel := context.WithCancel(t.Context())
			if cancelled {
				cancel()
			}
			want := ErrUnavailable
			if cancelled {
				want = context.Canceled
			}
			var wg sync.WaitGroup
			for range 4 {
				wg.Go(func() {
					if id, err := store.Create(ctx); id != (ID{}) || !errors.Is(err, want) {
						t.Error("create did not fail closed")
					}
					if token, session, err := store.StartSession(ctx, ID{1}, time.Second); token != nil || session != (Session{}) || !errors.Is(err, want) {
						t.Error("session did not fail closed")
					}
					if session, err := store.Resolve(ctx, make([]byte, TokenSize)); session != (Session{}) || !errors.Is(err, want) {
						t.Error("resolve did not fail closed")
					}
					if token, session, err := store.RotateSession(ctx, ID{1}, make([]byte, TokenSize)); token != nil || session != (Session{}) || !errors.Is(err, want) {
						t.Error("rotation did not fail closed")
					}
					if err := store.Revoke(ctx, make([]byte, TokenSize)); !errors.Is(err, want) {
						t.Error("revoke did not fail closed")
					}
					if sessions, err := store.ListSessions(ctx, make([]byte, TokenSize)); sessions != nil || !errors.Is(err, want) {
						t.Error("inventory did not fail closed")
					}
					if count, err := store.RevokeOtherSessions(ctx, make([]byte, TokenSize)); count != 0 || !errors.Is(err, want) {
						t.Error("sibling revocation did not fail closed")
					}
					if err := store.RevokeAll(ctx, ID{1}); !errors.Is(err, want) {
						t.Error("revoke-all did not fail closed")
					}
					if err := store.Disable(ctx, ID{1}); !errors.Is(err, want) {
						t.Error("disable did not fail closed")
					}
					if count, err := store.PurgeExpired(ctx, 1); count != 0 || !errors.Is(err, want) {
						t.Error("purge did not fail closed")
					}
				})
			}
			wg.Wait()
			cancel()
		}
	}
}

func TestAccountTokenDigest(t *testing.T) {
	t.Parallel()
	token := bytes.Repeat([]byte{'x'}, TokenSize)
	original := bytes.Clone(token)
	want := sha256.Sum256(token)
	got, ok := tokenDigest(token)
	if !ok || got != want || !bytes.Equal(token, original) {
		t.Fatal("digest or ownership differs")
	}
	for i := range token {
		token[i] ^= 1
		if other, ok := tokenDigest(token); !ok || other == got {
			t.Fatal("changed token matched")
		}
		token[i] ^= 1
	}
}

func FuzzAccountToken(f *testing.F) {
	f.Add([]byte("synthetic-input"))
	f.Add(bytes.Repeat([]byte{'x'}, TokenSize))
	f.Fuzz(func(t *testing.T, token []byte) {
		if len(token) > TokenSize+1 {
			return
		}
		before := bytes.Clone(token)
		digest, ok := tokenDigest(token)
		if ok != (len(token) == TokenSize) || !bytes.Equal(before, token) {
			t.Fatal("token admission or ownership differs")
		}
		if ok && digest != sha256.Sum256(token) || !ok && digest != ([sha256.Size]byte{}) {
			t.Fatal("wrong token verifier")
		}
		var store Store
		if fresh, session, err := store.RotateSession(t.Context(), ID{1}, token); fresh != nil || session != (Session{}) || !errors.Is(err, ErrUnavailable) || !bytes.Equal(before, token) {
			t.Fatal("rotation admission or ownership differs")
		}
		if sessions, err := store.ListSessions(t.Context(), token); sessions != nil || !errors.Is(err, ErrUnavailable) || !bytes.Equal(before, token) {
			t.Fatal("inventory admission or ownership differs")
		}
		if count, err := store.RevokeOtherSessions(t.Context(), token); count != 0 || !errors.Is(err, ErrUnavailable) || !bytes.Equal(before, token) {
			t.Fatal("sibling revocation admission or ownership differs")
		}
	})
}

func FuzzAccountSessionAdmission(f *testing.F) {
	for _, lifetime := range []time.Duration{-1, 0, time.Second - 1, time.Second, time.Second + 1, MaxLifetime, MaxLifetime + 1} {
		f.Add([]byte{1}, int64(lifetime))
	}
	f.Add([]byte{}, int64(time.Second))
	f.Fuzz(func(t *testing.T, rawID []byte, nanos int64) {
		if len(rawID) > len(ID{}) {
			return
		}
		before := bytes.Clone(rawID)
		var id ID
		copy(id[:], rawID)
		lifetime := time.Duration(nanos)
		want := ErrUnavailable
		if id == (ID{}) || lifetime < time.Second || lifetime > MaxLifetime || lifetime%time.Second != 0 {
			want = ErrInvalidInput
		}
		var store Store
		if token, session, err := store.StartSession(t.Context(), id, lifetime); token != nil || session != (Session{}) || !errors.Is(err, want) || !bytes.Equal(before, rawID) {
			t.Fatal("session admission did not fail closed or changed input")
		}
	})
}

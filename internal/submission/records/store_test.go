// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

package records

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func syntheticRound() Round {
	return Round{ID: ID{1}, BulletinDigest: [32]byte{2}, OpensAt: time.Unix(100, 0), ClosesAt: time.Unix(200, 0)}
}

func TestSubmissionAdmission(t *testing.T) {
	t.Parallel()
	if store, err := New(t.Context(), nil); store != nil || !errors.Is(err, ErrInvalidInput) {
		t.Fatal("nil pool admitted")
	}
	for _, test := range []struct {
		name   string
		change func(*Round)
	}{
		{"zero-id", func(r *Round) { r.ID = ID{} }},
		{"zero-opening", func(r *Round) { r.OpensAt = time.Time{} }},
		{"zero-closing", func(r *Round) { r.ClosesAt = time.Time{} }},
		{"equal", func(r *Round) { r.ClosesAt = r.OpensAt }},
		{"reversed", func(r *Round) { r.ClosesAt = r.OpensAt.Add(-time.Second) }},
		{"opening-precision", func(r *Round) { r.OpensAt = r.OpensAt.Add(time.Nanosecond) }},
		{"closing-precision", func(r *Round) { r.ClosesAt = r.ClosesAt.Add(time.Nanosecond) }},
		{"out-of-range", func(r *Round) { r.ClosesAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC) }},
		{"offset-overflow", func(r *Round) {
			r.ClosesAt = time.Date(9999, 12, 31, 23, 59, 59, 0, time.FixedZone("synthetic", -3600))
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			round := syntheticRound()
			test.change(&round)
			if err := (*Store)(nil).CreateRound(t.Context(), round); !errors.Is(err, ErrInvalidInput) {
				t.Fatal("invalid round admitted")
			}
		})
	}
	if err := (*Store)(nil).CancelRound(t.Context(), ID{}); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("zero cancellation ID admitted")
	}
	for _, test := range []struct {
		name       string
		round      ID
		bulletin   int
		spend      int
		ciphertext int
	}{
		{"zero-round", ID{}, 32, 32, 1},
		{"short-bulletin", ID{1}, 31, 32, 1},
		{"long-bulletin", ID{1}, 33, 32, 1},
		{"short-spend", ID{1}, 32, 31, 1},
		{"long-spend", ID{1}, 32, 33, 1},
		{"empty-ciphertext", ID{1}, 32, 32, 0},
		{"long-ciphertext", ID{1}, 32, 32, MaxCiphertextSize + 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := (*Store)(nil).Accept(t.Context(), test.round, make([]byte, test.bulletin), make([]byte, test.spend), make([]byte, test.ciphertext))
			if got != (Reference{}) || !errors.Is(err, ErrInvalidInput) {
				t.Fatal("invalid submission admitted or reference exposed")
			}
		})
	}
}

func TestSubmissionUnavailableAndCancellation(t *testing.T) {
	t.Parallel()
	var group sync.WaitGroup
	for _, store := range []*Store{nil, {}} {
		for _, cancelled := range []bool{false, true} {
			group.Go(func() {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				want := ErrUnavailable
				if cancelled {
					cancel()
					want = context.Canceled
				}
				round := syntheticRound()
				if err := store.CreateRound(ctx, round); !errors.Is(err, want) {
					t.Error("round creation did not fail closed")
				}
				if err := store.CancelRound(ctx, round.ID); !errors.Is(err, want) {
					t.Error("round cancellation did not fail closed")
				}
				for _, size := range []int{1, MaxCiphertextSize} {
					ciphertext := bytes.Repeat([]byte{3}, size)
					before := bytes.Clone(ciphertext)
					got, err := store.Accept(ctx, round.ID, round.BulletinDigest[:], make([]byte, 32), ciphertext)
					if got != (Reference{}) || !errors.Is(err, want) || !bytes.Equal(ciphertext, before) {
						t.Error("submission did not fail closed or changed input")
					}
				}
			})
		}
	}
	group.Wait()
}

func FuzzSubmissionAdmission(f *testing.F) {
	f.Add([]byte{1}, make([]byte, 32), make([]byte, 32), []byte{3})
	f.Add(make([]byte, 16), []byte{}, []byte{}, []byte{})
	f.Fuzz(func(t *testing.T, id, bulletin, spend, ciphertext []byte) {
		if len(id) > 17 || len(bulletin) > 33 || len(spend) > 33 || len(ciphertext) > MaxCiphertextSize+1 {
			return
		}
		var round ID
		copy(round[:], id)
		want := false
		for _, b := range round {
			want = want || b != 0
		}
		want = want && len(bulletin) == 32 && len(spend) == 32 && len(ciphertext) >= 1 && len(ciphertext) <= 65536
		if validSubmission(round, bulletin, spend, ciphertext) != want {
			t.Fatal("submission admission differs from bounds")
		}
		beforeID, beforeBulletin, beforeSpend, beforeCiphertext := bytes.Clone(id), bytes.Clone(bulletin), bytes.Clone(spend), bytes.Clone(ciphertext)
		got, err := (*Store)(nil).Accept(t.Context(), round, bulletin, spend, ciphertext)
		expected := ErrInvalidInput
		if want {
			expected = ErrUnavailable
		}
		if got != (Reference{}) || !errors.Is(err, expected) || !bytes.Equal(id, beforeID) ||
			!bytes.Equal(bulletin, beforeBulletin) || !bytes.Equal(spend, beforeSpend) || !bytes.Equal(ciphertext, beforeCiphertext) {
			t.Fatal("admission returned data, changed input, or returned wrong error")
		}
	})
}

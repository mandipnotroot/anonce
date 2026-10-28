// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

package memberbackup

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"math"
	"sync"
	"testing"

	"github.com/mandipnotroot/anonce/internal/identity/accounts"
)

// Public structure only, never a private key or an authenticated backup fixture.
func envelope() []byte {
	backup := make([]byte, BackupSize)
	copy(backup, "ANONCEKS")
	backup[8], backup[9], backup[10] = 1, 2, 1
	binary.BigEndian.PutUint32(backup[28:32], 76)
	return backup
}

func TestMemberBackupEnvelope(t *testing.T) {
	t.Parallel()
	valid := envelope()
	if !validBackup(valid) {
		t.Fatal("member envelope rejected")
	}
	for _, size := range []int{0, 1, 32, 60, BackupSize - 1, BackupSize + 1, 65596} {
		if validBackup(make([]byte, size)) {
			t.Fatal("invalid size admitted")
		}
	}
	for _, offset := range []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 28, 29, 30, 31} {
		for value := range 256 {
			changed := bytes.Clone(valid)
			changed[offset] = byte(value)
			if validBackup(changed) != (changed[offset] == valid[offset]) {
				t.Fatal("noncanonical member envelope admitted")
			}
		}
	}
	// Salt, nonce, and ciphertext are opaque. Admission cannot authenticate them.
	for _, offset := range []int{12, 27, 32, 43, 44, 107} {
		changed := bytes.Clone(valid)
		changed[offset] ^= 255
		if !validBackup(changed) {
			t.Fatal("storage attempted ciphertext authentication")
		}
	}
}

func TestMemberBackupAdmission(t *testing.T) {
	t.Parallel()
	var store Store
	owner, public, backup := accounts.ID{1}, make([]byte, 32), envelope()
	if got, err := New(t.Context(), nil); got != nil || !errors.Is(err, ErrInvalidInput) {
		t.Fatal("nil pool admitted")
	}
	for _, tc := range []struct {
		owner    accounts.ID
		revision int64
		public   []byte
		backup   []byte
	}{
		{accounts.ID{}, 0, public, backup},
		{owner, -1, public, backup},
		{owner, math.MaxInt64, public, backup},
		{owner, 0, nil, backup},
		{owner, 0, make([]byte, 31), backup},
		{owner, 0, make([]byte, 33), backup},
		{owner, 0, public, nil},
		{owner, 0, public, make([]byte, BackupSize)},
	} {
		if revision, err := store.Put(t.Context(), tc.owner, tc.revision, tc.public, tc.backup); revision != 0 || !errors.Is(err, ErrInvalidInput) {
			t.Fatal("invalid put admitted")
		}
	}
	for _, revision := range []int64{-1, 0, math.MaxInt64} {
		if got, err := store.Delete(t.Context(), owner, revision); got != 0 || !errors.Is(err, ErrInvalidInput) {
			t.Fatal("invalid delete revision admitted")
		}
	}
	if _, err := store.Delete(t.Context(), accounts.ID{}, 1); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("zero delete owner admitted")
	}
	if got, err := store.Get(t.Context(), accounts.ID{}); got.Backup != nil || got.Revision != 0 || !errors.Is(err, ErrInvalidInput) {
		t.Fatal("zero read owner admitted")
	}
}

func TestMemberBackupUnavailableAndCancellation(t *testing.T) {
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
					for _, revision := range []int64{0, 1, math.MaxInt64 - 1} {
						if got, err := store.Put(ctx, accounts.ID{1}, revision, make([]byte, 32), envelope()); got != 0 || !errors.Is(err, want) {
							t.Error("put did not fail closed")
						}
					}
					if got, err := store.Get(ctx, accounts.ID{1}); got.Backup != nil || got.Revision != 0 || !errors.Is(err, want) {
						t.Error("read did not fail closed")
					}
					if got, err := store.Delete(ctx, accounts.ID{1}, 1); got != 0 || !errors.Is(err, want) {
						t.Error("delete did not fail closed")
					}
				})
			}
			wg.Wait()
			cancel()
		}
	}
}

func FuzzMemberBackupAdmission(f *testing.F) {
	f.Add(int64(0), make([]byte, 32), envelope())
	f.Add(int64(-1), []byte{}, []byte("synthetic-input"))
	f.Add(int64(math.MaxInt64), make([]byte, 33), []byte{})
	f.Fuzz(func(t *testing.T, revision int64, public, backup []byte) {
		if len(public) > 33 || len(backup) > BackupSize+1 {
			return
		}
		before := bytes.Clone(backup)
		want := len(backup) == BackupSize && string(backup[:12]) == "ANONCEKS\x01\x02\x01\x00" &&
			bytes.Equal(backup[28:32], []byte{0, 0, 0, 76})
		if validBackup(backup) != want || !bytes.Equal(before, backup) {
			t.Fatal("envelope admission or ownership differs")
		}
		var store Store
		expected := ErrInvalidInput
		if revision >= 0 && revision < math.MaxInt64 && len(public) == 32 && want {
			expected = ErrUnavailable
		}
		if got, err := store.Put(t.Context(), accounts.ID{1}, revision, public, backup); got != 0 || !errors.Is(err, expected) {
			t.Fatal("put admission differs")
		}
	})
}

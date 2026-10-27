// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

package memberwasm

import (
	"errors"
	"sync"
	"testing"

	"github.com/mandipnotroot/anonce/internal/client/membersession"
)

func TestMemberWASMSizes(t *testing.T) {
	for _, tc := range []struct {
		name                       string
		password, backup, expected int
		unlock, want               bool
	}{
		{"create", 1, 0, 0, false, true},
		{"maximum password", 1024, 0, 0, false, true},
		{"empty password", 0, 0, 0, false, false},
		{"long password", 1025, 0, 0, false, false},
		{"unexpected backup", 1, 108, 0, false, false},
		{"unexpected key", 1, 0, 32, false, false},
		{"unlock", 1024, 108, 32, true, true},
		{"short backup", 1, 107, 32, true, false},
		{"long backup", 1, 109, 32, true, false},
		{"short key", 1, 108, 31, true, false},
		{"long key", 1, 108, 33, true, false},
		{"missing key", 1, 108, 0, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := validSizes(tc.password, tc.backup, tc.expected, tc.unlock); got != tc.want {
				t.Fatalf("validSizes = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestMemberWASMLifecycle(t *testing.T) {
	for _, closePending := range []bool{false, true} {
		t.Run(map[bool]string{false: "lock", true: "close"}[closePending], func(t *testing.T) {
			h := newHost()
			op := h.begin()
			if op == nil || h.begin() != nil || !h.accepted(op) {
				t.Fatal("admission did not reserve exactly one worker")
			}
			if closePending {
				h.close()
				h.close()
			} else {
				h.lock()
				h.lock()
			}
			if h.accepted(op) || h.begin() != nil {
				t.Fatal("cancelled work accepted or released admission too early")
			}
			select {
			case <-h.done:
				t.Fatal("shutdown before pending cleanup")
			default:
			}
			// Cancellation before the goroutine enters the shared session must
			// not permit a late installation, even though Session.Lock saw no work.
			if setup, err := h.session.Create(op.ctx, []byte("synthetic unlock input")); err == nil || setup != nil {
				t.Fatal("cancelled worker created a key")
			}
			h.finish(op)
			if _, err := h.session.Request(t.Context()); !errors.Is(err, membersession.ErrState) {
				t.Fatal("cancelled worker left an unlocked session")
			}
			if !closePending {
				next := h.begin()
				if next == nil {
					t.Fatal("lock prevented later admission")
				}
				h.finish(next)
				h.close()
			}
			<-h.done
			if h.begin() != nil {
				t.Fatal("closed host admitted work")
			}
		})
	}
}

func TestMemberWASMConcurrent(t *testing.T) {
	h := newHost()
	op := h.begin()
	var wg sync.WaitGroup
	for range 12 {
		wg.Go(func() {
			h.lock()
			if h.begin() != nil || h.accepted(op) {
				t.Error("concurrent lock released pending admission")
			}
			h.close()
		})
	}
	wg.Wait()
	h.finish(op)
	<-h.done
}

func FuzzMemberWASMSizes(f *testing.F) {
	f.Add(uint16(1), uint16(108), uint8(32), true)
	f.Add(uint16(1024), uint16(0), uint8(0), false)
	f.Fuzz(func(t *testing.T, password, backup uint16, expected uint8, unlock bool) {
		want := password >= 1 && password <= 1024
		if unlock {
			want = want && backup == 108 && expected == 32
		} else {
			want = want && backup == 0 && expected == 0
		}
		if validSizes(int(password), int(backup), int(expected), unlock) != want {
			t.Fatal("invalid admission decision")
		}
	})
}

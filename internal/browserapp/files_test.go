// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

package browserapp

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestStateFileAdmission(t *testing.T) {
	directory := t.TempDir()
	file := filepath.Join(directory, "synthetic")
	for _, tc := range []struct {
		name string
		data []byte
		mode os.FileMode
		want bool
	}{
		{"valid", []byte("synthetic"), 0o600, true},
		{"empty", nil, 0o600, false},
		{"oversized", make([]byte, 33), 0o600, false},
		{"public-permissions", []byte("synthetic"), 0o644, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(file, tc.data, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(file, tc.mode); err != nil {
				t.Fatal(err)
			}
			data, err := ReadFile(file, 32, true)
			if (err == nil) != tc.want || err == nil && !bytes.Equal(data, tc.data) {
				t.Fatal("incorrect state-file admission")
			}
		})
	}
	link := filepath.Join(directory, "link")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFile(link, 32, false); err == nil {
		t.Fatal("followed state-file symlink")
	}
}

func TestInitializationDoesNotReplace(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state")
	if err := Initialize(directory); err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(directory, "identity/administrator-invitation")
	before, err := ReadFile(name, 43, true)
	if err != nil || len(before) != 43 {
		t.Fatal("administrator invitation unavailable")
	}
	defer clear(before)
	if Initialize(directory) == nil {
		t.Fatal("reinitialized existing browser state")
	}
	after, err := ReadFile(name, 43, true)
	defer clear(after)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("existing administrator invitation changed")
	}
}

// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

package browserapp

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
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

func TestEmptyInitializationAdmission(t *testing.T) {
	for _, tc := range []string{"empty", "nonempty", "symlink", "public", "file"} {
		t.Run(tc, func(t *testing.T) {
			directory := filepath.Join(t.TempDir(), "state")
			if err := os.Mkdir(directory, 0o700); err != nil {
				t.Fatal(err)
			}
			switch tc {
			case "nonempty":
				if err := os.WriteFile(filepath.Join(directory, "existing"), []byte("synthetic"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				link := directory + "-link"
				if err := os.Symlink(directory, link); err != nil {
					t.Fatal(err)
				}
				directory = link
			case "public":
				if err := os.Chmod(directory, 0o755); err != nil {
					t.Fatal(err)
				}
			case "file":
				directory = filepath.Join(directory, "file")
				if err := os.WriteFile(directory, []byte("synthetic"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			err := InitializeEmpty(directory)
			if (err == nil) != (tc == "empty") {
				t.Fatal("incorrect existing-directory admission")
			}
			if tc == "empty" {
				if InitializeEmpty(directory) == nil {
					t.Fatal("reinitialized existing service keys")
				}
				for _, side := range []string{"identity", "submission"} {
					own, err := ReadFile(filepath.Join(directory, side, "local-root.crt"), 4096, false)
					root, rootErr := ReadFile(filepath.Join(directory, "local-root.crt"), 4096, false)
					if err != nil || rootErr != nil || !bytes.Equal(own, root) {
						t.Fatal("scoped root certificate differs")
					}
					leafPEM, err := ReadFile(filepath.Join(directory, side, "tls.crt"), 4096, false)
					if err != nil {
						t.Fatal(err)
					}
					block, _ := pem.Decode(leafPEM)
					if block == nil {
						t.Fatal("invalid generated certificate")
					}
					leaf, err := x509.ParseCertificate(block.Bytes)
					if err != nil || len(leaf.AuthorityKeyId) == 0 {
						t.Fatal("generated leaf lacks authority key identifier")
					}
				}
			}
		})
	}
}

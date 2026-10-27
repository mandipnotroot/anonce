// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

package clientcli

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/mandipnotroot/anonce/internal/client/keystore"
)

func TestClientRewrapPasswords(t *testing.T) {
	t.Parallel()
	maximum := strings.Repeat("x", keystore.MaxPasswordSize)
	for _, tc := range []struct {
		name, input, current, replacement string
	}{
		{"valid", "synthetic old\nsynthetic new\nsynthetic new\n", "synthetic old", "synthetic new"},
		{"unchanged", "synthetic\nsynthetic\nsynthetic\n", "synthetic", "synthetic"},
		{"opaque", " \x00\r\xff \n\xff\x00\r \n\xff\x00\r \n", " \x00\r\xff ", "\xff\x00\r "},
		{"maximum", maximum + "\n" + maximum + "\n" + maximum + "\n", maximum, maximum},
		{"empty", "", "", ""},
		{"empty current", "\nsynthetic\nsynthetic\n", "", ""},
		{"empty replacement", "synthetic\n\n\n", "", ""},
		{"missing current newline", "synthetic", "", ""},
		{"missing replacement", "synthetic\n", "", ""},
		{"missing confirmation", "synthetic\nnew\n", "", ""},
		{"unterminated confirmation", "synthetic\nnew\nnew", "", ""},
		{"mismatched confirmation", "synthetic\nnew\ndifferent\n", "", ""},
		{"extra line", "synthetic\nnew\nnew\nextra\n", "", ""},
		{"trailing byte", "synthetic\nnew\nnew\nx", "", ""},
		{"oversized current", maximum + "x\nnew\nnew\n", "", ""},
		{"oversized replacement", "synthetic\n" + maximum + "x\n" + maximum + "x\n", "", ""},
		{"oversized confirmation", "synthetic\n" + maximum + "\n" + maximum + "x\n", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			data, err := readPasswordInput(t.Context(), passwordFile(t, tc.input), 3)
			defer clear(data)
			if err != nil {
				t.Fatal(err)
			}
			current, replacement, err := parseRewrapPasswords(data)
			defer clear(current)
			defer clear(replacement)
			if tc.current == "" {
				if err == nil || current != nil || replacement != nil {
					t.Fatal("invalid framing returned passwords")
				}
				return
			}
			clear(data)
			if err != nil || !bytes.Equal(current, []byte(tc.current)) || !bytes.Equal(replacement, []byte(tc.replacement)) {
				t.Fatal("passwords changed or alias input")
			}
			current[0] ^= 1
			if !bytes.Equal(replacement, []byte(tc.replacement)) {
				t.Fatal("password outputs alias each other")
			}
		})
	}
	if data, err := readPasswordInput(t.Context(), passwordFile(t, strings.Repeat("x", 3076)), 3); err == nil || data != nil {
		t.Fatal("accepted oversized password input")
	}
}

func TestClientRewrapRoundTrip(t *testing.T) {
	for _, kind := range []string{"member", "reviewer"} {
		t.Run(kind, func(t *testing.T) {
			current, replacement := []byte("synthetic old"), []byte("synthetic new")
			defer clear(current)
			defer clear(replacement)
			backup, err := generate(t.Context(), kind, current)
			if err != nil {
				t.Fatal(err)
			}
			directory := privateDirectory(t)
			input, output := filepath.Join(directory, "old"), filepath.Join(directory, "new")
			if err := writeBackup(t.Context(), input, backup); err != nil {
				t.Fatal(err)
			}
			var stdout bytes.Buffer
			args := []string{"rewrap", "-kind", kind, "-in", input, "-out", output}
			if err := run(t.Context(), args, passwordFile(t, "synthetic old\nsynthetic new\nsynthetic new\n"), &stdout); err != nil {
				t.Fatal(err)
			}
			if stdout.Len() != 0 {
				t.Fatal("rewrap wrote to stdout")
			}
			sealed, err := readBackup(t.Context(), output)
			if err != nil {
				t.Fatal(err)
			}
			assertRewrappedKey(t, kind, current, replacement, backup, sealed)
			if _, err := inspect(t.Context(), kind, current, sealed); !errors.Is(err, keystore.ErrInvalidBackup) {
				t.Fatal("rewrapped backup accepted old password")
			}
			public, err := inspect(t.Context(), kind, current, backup)
			if err != nil {
				t.Fatal(err)
			}
			if err := run(t.Context(), []string{"inspect", "-kind", kind, "-in", output, "-expect-public-key", hex.EncodeToString(public)}, passwordFile(t, "synthetic new\n"), &stdout); err != nil {
				t.Fatal(err)
			}
			if stdout.String() != kind+":"+hex.EncodeToString(public)+"\n" {
				t.Fatal("rewrapped backup did not match the independently retained public key")
			}
			stdout.Reset()
			original, err := os.ReadFile(input)
			if err != nil || !bytes.Equal(original, backup) {
				t.Fatal("rewrap changed the input file")
			}
			info, err := os.Stat(output)
			if err != nil || info.Mode().Perm() != 0o600 {
				t.Fatal("rewrap did not publish owner-only output")
			}
			// Same-path and repeated writes must leave both existing files intact.
			for _, destination := range []string{input, output} {
				args[len(args)-1] = destination
				if err := run(t.Context(), args, passwordFile(t, "synthetic old\nsynthetic new\nsynthetic new\n"), &stdout); err == nil {
					t.Fatal("rewrap overwrote an existing file")
				}
			}
			for path, want := range map[string][]byte{input: backup, output: sealed} {
				got, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(got, want) {
					t.Fatal("failed publication changed an existing file")
				}
			}
			entries, err := os.ReadDir(directory)
			if err != nil || len(entries) != 2 || stdout.Len() != 0 {
				t.Fatal("rewrap left temporary files or stdout output")
			}
		})
	}
}

func assertRewrappedKey(t *testing.T, kind string, current, replacement, backup, sealed []byte) {
	t.Helper()
	if len(sealed) != 108 || bytes.Equal(backup[12:28], sealed[12:28]) || bytes.Equal(backup[32:44], sealed[32:44]) {
		t.Fatal("rewrap changed the profile size or reused salt/nonce")
	}
	purpose := keystore.MemberKey
	if kind == "reviewer" {
		purpose = keystore.ReviewerKey
	}
	before, err := keystore.Open(t.Context(), purpose, current, backup)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(before)
	after, err := keystore.Open(t.Context(), purpose, replacement, sealed)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(after)
	if !bytes.Equal(before, after) {
		t.Fatal("rewrap changed private key payload bytes")
	}
}

func TestClientRewrapExpectedKey(t *testing.T) {
	for _, kind := range []string{"member", "reviewer"} {
		t.Run(kind, func(t *testing.T) {
			current, replacement := []byte("synthetic old"), []byte("synthetic new")
			defer clear(current)
			defer clear(replacement)
			backup, err := generate(t.Context(), kind, current)
			if err != nil {
				t.Fatal(err)
			}
			public, err := inspect(t.Context(), kind, current, backup)
			if err != nil {
				t.Fatal(err)
			}
			encoded := hex.EncodeToString(public)
			for _, tc := range []struct {
				name, expected string
			}{
				{"lowercase", encoded},
				{"uppercase", strings.ToUpper(encoded)},
			} {
				t.Run(tc.name, func(t *testing.T) {
					directory := privateDirectory(t)
					input, output := filepath.Join(directory, "old"), filepath.Join(directory, "new")
					if err := writeBackup(t.Context(), input, backup); err != nil {
						t.Fatal(err)
					}
					args := []string{"rewrap", "-kind", kind, "-in", input, "-out", output, "-expect-public-key", tc.expected}
					var stdout bytes.Buffer
					if err := run(t.Context(), args, passwordFile(t, "synthetic old\nsynthetic new\nsynthetic new\n"), &stdout); err != nil {
						t.Fatal(err)
					}
					sealed, err := readBackup(t.Context(), output)
					if err != nil {
						t.Fatal(err)
					}
					assertRewrappedKey(t, kind, current, replacement, backup, sealed)
					// Matching a key must not bypass no-replace publication, even
					// when the destination is the source backup itself.
					for _, destination := range []string{input, output} {
						repeated := slices.Clone(args)
						repeated[6] = destination
						if err := run(t.Context(), repeated, passwordFile(t, "synthetic old\nsynthetic new\nsynthetic new\n"), &stdout); err == nil {
							t.Fatal("expected-key rewrap replaced an existing file")
						}
						got, err := os.ReadFile(destination)
						want := backup
						if destination == output {
							want = sealed
						}
						if err != nil || !bytes.Equal(got, want) {
							t.Fatal("expected-key rewrap changed an existing file")
						}
					}
					entries, err := os.ReadDir(directory)
					if err != nil || len(entries) != 2 || stdout.Len() != 0 {
						t.Fatal("expected-key rewrap left temporary files or stdout")
					}
				})
			}
			for _, index := range []int{0, len(public) / 2, len(public) - 1} {
				expected := bytes.Clone(public)
				expected[index] ^= 1
				directory := privateDirectory(t)
				input, output := filepath.Join(directory, "old"), filepath.Join(directory, "new")
				if err := writeBackup(t.Context(), input, backup); err != nil {
					t.Fatal(err)
				}
				var stdout bytes.Buffer
				mismatch := hex.EncodeToString(expected)
				err := run(t.Context(), []string{"rewrap", "-kind", kind, "-in", input, "-out", output, "-expect-public-key", mismatch}, passwordFile(t, "synthetic old\nsynthetic new\nsynthetic new\n"), &stdout)
				if err == nil || !strings.Contains(err.Error(), "public key does not match expected key") || stdout.Len() != 0 {
					t.Fatal("mismatched rewrap did not fail without stdout")
				}
				for _, value := range []string{input, output, encoded, mismatch, "synthetic"} {
					if strings.Contains(err.Error(), value) {
						t.Fatal("mismatched rewrap reflected input")
					}
				}
				entries, err := os.ReadDir(directory)
				if err != nil || len(entries) != 1 || entries[0].Name() != "old" {
					t.Fatal("mismatched rewrap created an output or temporary file")
				}
				original, err := os.ReadFile(input)
				if err != nil || !bytes.Equal(original, backup) {
					t.Fatal("mismatched rewrap changed the input")
				}
				// An invalid replacement password would fail Seal. A key mismatch
				// must take precedence, proving replacement derivation is not reached.
				sealed, err := rewrap(t.Context(), kind, current, nil, backup, expected)
				if err == nil || err.Error() != "public key does not match expected key" || sealed != nil {
					t.Fatal("mismatched rewrap reached replacement encryption")
				}
			}
		})
	}
}

func TestClientRewrapRejectsInvalidBackup(t *testing.T) {
	for _, kind := range []string{"member", "reviewer"} {
		t.Run(kind, func(t *testing.T) {
			password := []byte("synthetic old")
			defer clear(password)
			backup, err := generate(t.Context(), kind, password)
			if err != nil {
				t.Fatal(err)
			}
			purpose := keystore.MemberKey
			otherKind := "reviewer"
			if kind == "reviewer" {
				purpose, otherKind = keystore.ReviewerKey, "member"
			}
			nonKey, err := keystore.Seal(t.Context(), purpose, password, []byte("synthetic non-key payload"))
			if err != nil {
				t.Fatal(err)
			}
			tampered := bytes.Clone(backup)
			tampered[len(tampered)-1] ^= 1
			for _, tc := range []struct {
				name, kind, passwords string
				backup                []byte
			}{
				{"wrong password", kind, "synthetic wrong\nnew\nnew\n", backup},
				{"wrong purpose", otherKind, "synthetic old\nnew\nnew\n", backup},
				{"tampered", kind, "synthetic old\nnew\nnew\n", tampered},
				{"malformed", kind, "synthetic old\nnew\nnew\n", []byte("synthetic malformed backup")},
				{"authenticated non-key", kind, "synthetic old\nnew\nnew\n", nonKey},
			} {
				t.Run(tc.name, func(t *testing.T) {
					directory := privateDirectory(t)
					input, output := filepath.Join(directory, "old"), filepath.Join(directory, "new")
					if err := writeBackup(t.Context(), input, tc.backup); err != nil {
						t.Fatal(err)
					}
					var stdout bytes.Buffer
					for _, flags := range [][]string{nil, {"-expect-public-key", strings.Repeat("ab", 32)}} {
						args := append([]string{"rewrap", "-kind", tc.kind, "-in", input, "-out", output}, flags...)
						err := run(t.Context(), args, passwordFile(t, tc.passwords), &stdout)
						if !errors.Is(err, keystore.ErrInvalidBackup) || stdout.Len() != 0 {
							t.Fatal("invalid backup returned output or wrong error")
						}
						if strings.Contains(err.Error(), directory) || strings.Contains(err.Error(), "synthetic") {
							t.Fatal("rewrap failure reflected sensitive input")
						}
					}
					entries, err := os.ReadDir(directory)
					if err != nil || len(entries) != 1 || entries[0].Name() != "old" {
						t.Fatal("invalid backup created an output or temporary file")
					}
					original, err := os.ReadFile(input)
					if err != nil || !bytes.Equal(original, tc.backup) {
						t.Fatal("rejected import changed the input")
					}
				})
			}
		})
	}
}

func TestClientRewrapCancellation(t *testing.T) {
	for _, kind := range []string{"member", "reviewer"} {
		t.Run(kind, func(t *testing.T) {
			password := []byte("synthetic")
			defer clear(password)
			backup, err := generate(t.Context(), kind, password)
			if err != nil {
				t.Fatal(err)
			}
			public, err := inspect(t.Context(), kind, password, backup)
			if err != nil {
				t.Fatal(err)
			}
			// Entry, typed Seal after successful Open, and final encrypted output.
			for _, expected := range [][]byte{nil, public} {
				for _, at := range []int{1, 6, 10} {
					ctx := &cancelAtCheck{Context: t.Context(), at: at}
					sealed, err := rewrap(ctx, kind, password, password, backup, expected)
					if !errors.Is(err, context.Canceled) || sealed != nil {
						t.Fatal("cancelled rewrap returned output or wrong error")
					}
				}
			}
		})
	}
	if sealed, err := rewrap(t.Context(), "unsupported", nil, nil, nil, nil); !errors.Is(err, errArguments) || sealed != nil {
		t.Fatal("unsupported rewrap kind selected an algorithm")
	}
}

func TestClientRewrapFailsClosed(t *testing.T) {
	t.Parallel()
	directory := privateDirectory(t)
	input, output := filepath.Join(directory, "missing"), filepath.Join(directory, "new")
	args := []string{"rewrap", "-kind", "member", "-in", input, "-out", output}
	var stdout bytes.Buffer
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := run(ctx, args, nil, &stdout); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled rewrap read stdin")
	}
	for _, framing := range []string{"synthetic\nnew\ndifferent\n", "synthetic\nnew\nnew\n"} {
		if err := run(t.Context(), args, passwordFile(t, framing), &stdout); err == nil {
			t.Fatal("rewrap accepted mismatched confirmation or missing input")
		}
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 0 || stdout.Len() != 0 {
		t.Fatal("failed rewrap created output")
	}
}

func TestClientRewrapConcurrent(t *testing.T) {
	for _, kind := range []string{"member", "reviewer"} {
		t.Run(kind, func(t *testing.T) {
			password := []byte("synthetic")
			defer clear(password)
			backup, err := generate(t.Context(), kind, password)
			if err != nil {
				t.Fatal(err)
			}
			original := bytes.Clone(backup)
			public, err := inspect(t.Context(), kind, password, backup)
			if err != nil {
				t.Fatal(err)
			}
			results := make(chan []byte, 2)
			var group sync.WaitGroup
			for range 2 {
				group.Go(func() {
					sealed, err := rewrap(t.Context(), kind, password, password, backup, public)
					if err != nil {
						t.Error(err)
						return
					}
					results <- sealed
				})
			}
			group.Wait()
			close(results)
			for sealed := range results {
				assertRewrappedKey(t, kind, password, password, backup, sealed)
			}
			if !bytes.Equal(backup, original) || !bytes.Equal(password, []byte("synthetic")) {
				t.Fatal("rewrap mutated caller-owned inputs")
			}
		})
	}
}

func FuzzClientRewrapPasswords(f *testing.F) {
	f.Add([]byte("synthetic old\nsynthetic new\nsynthetic new\n"))
	f.Add([]byte("synthetic\nsynthetic\nsynthetic\n"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 3*(keystore.MaxPasswordSize+1)+1 {
			return
		}
		current, replacement, err := parseRewrapPasswords(data)
		defer clear(current)
		defer clear(replacement)
		if err != nil {
			if current != nil || replacement != nil {
				t.Fatal("failed parse returned passwords")
			}
			return
		}
		if len(current) == 0 || len(current) > keystore.MaxPasswordSize ||
			len(replacement) == 0 || len(replacement) > keystore.MaxPasswordSize ||
			bytes.ContainsRune(current, '\n') || bytes.ContainsRune(replacement, '\n') {
			t.Fatal("parser returned unsupported passwords")
		}
		framed := make([]byte, 0, len(data))
		defer func() { clear(framed) }()
		framed = append(framed, current...)
		framed = append(framed, '\n')
		framed = append(framed, replacement...)
		framed = append(framed, '\n')
		framed = append(framed, replacement...)
		framed = append(framed, '\n')
		if !bytes.Equal(framed, data) {
			t.Fatal("parser changed password bytes or accepted trailing data")
		}
	})
}

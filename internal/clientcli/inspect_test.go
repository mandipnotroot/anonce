// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

package clientcli

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/mandipnotroot/anonce/internal/client/keystore"
)

func TestClientInspectExpectedKey(t *testing.T) {
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
			directory := privateDirectory(t)
			path := filepath.Join(directory, "backup")
			if err := writeBackup(t.Context(), path, backup); err != nil {
				t.Fatal(err)
			}
			// Check both ends and the middle of the full public key. Each call
			// uses the real backup profile, including its full KDF cost.
			for _, index := range []int{0, len(public) / 2, len(public) - 1} {
				expected := bytes.Clone(public)
				expected[index] ^= 1
				encoded := hex.EncodeToString(expected)
				var stdout bytes.Buffer
				err := run(t.Context(), []string{"inspect", "-kind", kind, "-in", path, "-expect-public-key", encoded}, passwordFile(t, "synthetic\n"), &stdout)
				if err == nil || errors.Is(err, keystore.ErrInvalidBackup) || stdout.Len() != 0 {
					t.Fatal("mismatched expected key did not fail without output after validation")
				}
				for _, value := range []string{path, encoded, hex.EncodeToString(public), "synthetic"} {
					if strings.Contains(err.Error(), value) {
						t.Fatal("mismatch reflected input")
					}
				}
			}
			args := []string{"inspect", "-kind", kind, "-in", path, "-expect-public-key", hex.EncodeToString(public)}
			for _, writer := range []io.Writer{failingWriter{}, shortWriter{}} {
				if err := run(t.Context(), args, passwordFile(t, "synthetic\n"), writer); err == nil || strings.Contains(err.Error(), path) {
					t.Fatal("inspection lost an output failure or reflected input")
				}
			}
			// Count the context checks in a complete invocation to cover the
			// final pre-output guard without coupling to KDF implementation steps.
			observed := &cancelAtCheck{Context: t.Context(), at: maxArgumentBytes}
			if err := run(observed, args, passwordFile(t, "synthetic\n"), io.Discard); err != nil {
				t.Fatal(err)
			}
			for _, at := range []int{1, observed.calls} {
				var stdout bytes.Buffer
				ctx := &cancelAtCheck{Context: t.Context(), at: at}
				if err := run(ctx, args, passwordFile(t, "synthetic\n"), &stdout); !errors.Is(err, context.Canceled) || stdout.Len() != 0 {
					t.Fatal("cancelled inspection returned public output or lost cancellation")
				}
			}
			original, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(original, backup) {
				t.Fatal("inspection changed the backup")
			}
			entries, err := os.ReadDir(directory)
			if err != nil || len(entries) != 1 {
				t.Fatal("inspection created a file")
			}
			for range 2 {
				t.Run("concurrent match", func(t *testing.T) {
					t.Parallel()
					var stdout bytes.Buffer
					if err := run(t.Context(), args, passwordFile(t, "synthetic\n"), &stdout); err != nil {
						t.Fatal(err)
					}
					if stdout.String() != kind+":"+hex.EncodeToString(public)+"\n" {
						t.Fatal("concurrent inspection changed public output")
					}
				})
			}
		})
	}
}

func TestClientInspectExpectedKeyRejectsInvalidPayload(t *testing.T) {
	for _, kind := range []string{"member", "reviewer"} {
		t.Run(kind, func(t *testing.T) {
			password := []byte("synthetic")
			defer clear(password)
			purpose := keystore.MemberKey
			if kind == "reviewer" {
				purpose = keystore.ReviewerKey
			}
			backup, err := keystore.Seal(t.Context(), purpose, password, []byte("synthetic non-key payload"))
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(privateDirectory(t), "backup")
			if err := writeBackup(t.Context(), path, backup); err != nil {
				t.Fatal(err)
			}
			base := []string{"inspect", "-kind", kind, "-in", path}
			for _, flags := range [][]string{nil, {"-expect-public-key", strings.Repeat("ab", 32)}} {
				var stdout bytes.Buffer
				err := run(t.Context(), append(slices.Clone(base), flags...), passwordFile(t, "synthetic\n"), &stdout)
				if !errors.Is(err, keystore.ErrInvalidBackup) || stdout.Len() != 0 {
					t.Fatal("authenticated non-key payload bypassed typed validation")
				}
			}
		})
	}
}

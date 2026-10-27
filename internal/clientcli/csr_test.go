// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

package clientcli

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mandipnotroot/anonce/internal/client/keystore"
	"github.com/mandipnotroot/anonce/internal/client/membercsr"
	"github.com/mandipnotroot/anonce/internal/client/memberkey"
)

func TestClientCSRRoundTrip(t *testing.T) {
	password := []byte("synthetic")
	defer clear(password)
	key, err := memberkey.Generate(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	backup, err := memberkey.Seal(t.Context(), password, key)
	if err != nil {
		t.Fatal(err)
	}
	directory := privateDirectory(t)
	path := filepath.Join(directory, "backup")
	if err := writeBackup(t.Context(), path, backup); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	args := []string{"csr", "-kind", "member", "-in", path}
	if err := run(t.Context(), args, passwordFile(t, "synthetic\n"), &stdout); err != nil {
		t.Fatal(err)
	}
	public, err := membercsr.Parse(stdout.Bytes())
	if err != nil || !bytes.Equal(public, key[32:]) || stdout.Len() != membercsr.DERSize {
		t.Fatal("CLI did not output exactly the matching public DER request")
	}
	original, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(original, backup) {
		t.Fatal("CSR changed the input backup")
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 1 {
		t.Fatal("CSR created a file")
	}
	for _, writer := range []io.Writer{failingWriter{}, shortWriter{}} {
		if err := writeCSR(t.Context(), password, backup, writer); err == nil || strings.Contains(err.Error(), "synthetic") {
			t.Fatal("CSR did not report a secret-free output failure")
		}
	}
	// Entry, request creation after successful import, and the final write guard.
	for _, at := range []int{1, 6, 8} {
		stdout.Reset()
		ctx := &cancelAtCheck{Context: t.Context(), at: at}
		if err := writeCSR(ctx, password, backup, &stdout); !errors.Is(err, context.Canceled) || stdout.Len() != 0 {
			t.Fatal("cancelled CSR wrote public output or lost cancellation")
		}
	}
}

type shortWriter struct{}

func (shortWriter) Write(data []byte) (int, error) { return len(data) - 1, nil }

func TestClientCSRRejectsInvalidBackup(t *testing.T) {
	password := []byte("synthetic")
	defer clear(password)
	backup, err := generate(t.Context(), "member", password)
	if err != nil {
		t.Fatal(err)
	}
	reviewer, err := generate(t.Context(), "reviewer", password)
	if err != nil {
		t.Fatal(err)
	}
	nonKey, err := keystore.Seal(t.Context(), keystore.MemberKey, password, []byte("synthetic non-key"))
	if err != nil {
		t.Fatal(err)
	}
	tampered := bytes.Clone(backup)
	tampered[len(tampered)-1] ^= 1
	for _, tc := range []struct {
		name, framing string
		backup        []byte
	}{
		{"wrong password", "different\n", backup},
		{"reviewer purpose", "synthetic\n", reviewer},
		{"authenticated non-key", "synthetic\n", nonKey},
		{"tampered", "synthetic\n", tampered},
		{"malformed", "synthetic\n", []byte("synthetic malformed backup")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(privateDirectory(t), "backup")
			if err := writeBackup(t.Context(), path, tc.backup); err != nil {
				t.Fatal(err)
			}
			var stdout bytes.Buffer
			err := run(t.Context(), []string{"csr", "-kind=member", "-in", path}, passwordFile(t, tc.framing), &stdout)
			if !errors.Is(err, keystore.ErrInvalidBackup) || stdout.Len() != 0 {
				t.Fatal("invalid backup produced a request")
			}
			if strings.Contains(err.Error(), path) || strings.Contains(err.Error(), "synthetic") || strings.Contains(err.Error(), "different") {
				t.Fatal("failure reflected input")
			}
		})
	}
}

func TestClientCSRFailsClosed(t *testing.T) {
	t.Parallel()
	var stdout bytes.Buffer
	if err := run(t.Context(), []string{"csr", "-help"}, nil, &stdout); !errors.Is(err, flag.ErrHelp) {
		t.Fatal("CSR help read stdin")
	}
	stdout.Reset()
	if err := run(t.Context(), []string{"csr", "-kind=reviewer", "-in=synthetic"}, nil, &stdout); !errors.Is(err, errArguments) {
		t.Fatal("CSR accepted a reviewer kind or read stdin")
	}
	args := []string{"csr", "-kind=member", "-in", filepath.Join(privateDirectory(t), "missing")}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := run(ctx, args, nil, &stdout); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled CSR read stdin")
	}
	for _, framing := range []string{"synthetic\nextra\n", "synthetic\n", ""} {
		if err := run(t.Context(), args, passwordFile(t, framing), &stdout); err == nil {
			t.Fatal("CSR accepted invalid framing or a missing file")
		}
	}
	if stdout.Len() != 0 {
		t.Fatal("failed CSR wrote stdout")
	}
}

// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

package clientcli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mandipnotroot/anonce/internal/client/membercsr"
	"github.com/mandipnotroot/anonce/internal/client/memberkey"
)

func TestClientVerifyCSRRoundTrip(t *testing.T) {
	t.Parallel()
	key, err := memberkey.Generate(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	der, err := membercsr.Create(t.Context(), key)
	if err != nil {
		t.Fatal(err)
	}
	directory := privateDirectory(t)
	path := filepath.Join(directory, "request")
	if err := os.WriteFile(path, der, 0o600); err != nil {
		t.Fatal(err)
	}
	want := "member:" + hex.EncodeToString(key[32:]) + "\n"
	// Concurrent verification shares only public input and never accesses stdin.
	for _, pin := range []string{"", hex.EncodeToString(key[32:]), strings.ToUpper(hex.EncodeToString(key[32:]))} {
		for range 4 {
			t.Run("verify", func(t *testing.T) {
				t.Parallel()
				var stdout bytes.Buffer
				args := []string{"verify-csr", "-kind=member", "-in", path}
				if pin != "" {
					args = append(args, "-expect-public-key", pin)
				}
				if err := run(t.Context(), args, nil, &stdout); err != nil {
					t.Fatal(err)
				}
				if stdout.String() != want {
					t.Fatal("verification did not output exactly the matching public key")
				}
				original, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(original, der) {
					t.Fatal("verification changed the request")
				}
				entries, err := os.ReadDir(directory)
				if err != nil || len(entries) != 1 {
					t.Fatal("verification created a file")
				}
			})
		}
	}
}

func TestClientVerifyCSRExpectedKey(t *testing.T) {
	t.Parallel()
	key, err := memberkey.Generate(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	der, err := membercsr.Create(t.Context(), key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(privateDirectory(t), "request")
	if err := os.WriteFile(path, der, 0o600); err != nil {
		t.Fatal(err)
	}
	public := bytes.Clone(key[ed25519.SeedSize:])
	// Every byte of the complete key must match, not only a prefix or suffix.
	for i := range ed25519.PublicKeySize {
		t.Run("mismatch", func(t *testing.T) {
			t.Parallel()
			expected := bytes.Clone(public)
			expected[i] ^= 1
			encoded := hex.EncodeToString(expected)
			var stdout bytes.Buffer
			err := run(t.Context(), []string{"verify-csr", "-kind=member", "-in", path, "-expect-public-key=" + encoded}, nil, &stdout)
			if err == nil || stdout.Len() != 0 || errors.Is(err, membercsr.ErrInvalidRequest) {
				t.Fatal("valid request with mismatched expected key was not rejected without output")
			}
			for _, value := range []string{path, encoded, hex.EncodeToString(public)} {
				if strings.Contains(err.Error(), value) {
					t.Fatal("mismatch reflected a path or public key")
				}
			}
			original, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(original, der) {
				t.Fatal("mismatch changed the request")
			}
		})
	}
}

func TestClientVerifyCSRRejectsInvalidRequests(t *testing.T) {
	t.Parallel()
	key, err := memberkey.Generate(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	der, err := membercsr.Create(t.Context(), key)
	if err != nil {
		t.Fatal(err)
	}
	tampered := bytes.Clone(der)
	tampered[len(tampered)-1] ^= 1
	claimed, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "synthetic"},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	expected := hex.EncodeToString(key[ed25519.SeedSize:])
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"invalid signature", tampered},
		{"extra identity claim", claimed},
		{"malformed", bytes.Repeat([]byte{0xff}, membercsr.DERSize)},
		{"empty", nil},
		{"truncated", der[:len(der)-1]},
		{"trailing byte", append(bytes.Clone(der), 0)},
		{"concatenated", append(bytes.Clone(der), der...)},
		{"pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(privateDirectory(t), "synthetic-request")
			if err := os.WriteFile(path, tc.data, 0o600); err != nil {
				t.Fatal(err)
			}
			for _, pin := range []string{"", expected} {
				var stdout bytes.Buffer
				args := []string{"verify-csr", "-kind=member", "-in", path}
				if pin != "" {
					args = append(args, "-expect-public-key", pin)
				}
				err := run(t.Context(), args, nil, &stdout)
				if err == nil || stdout.Len() != 0 {
					t.Fatal("invalid request produced output")
				}
				if len(tc.data) > 0 && len(tc.data) <= membercsr.DERSize && !errors.Is(err, membercsr.ErrInvalidRequest) {
					t.Fatal("invalid profile did not reach the shared validator")
				}
				if strings.Contains(err.Error(), path) || strings.Contains(err.Error(), "synthetic") {
					t.Fatal("failure reflected request input")
				}
				args = append(args, "-out", filepath.Join(filepath.Dir(path), "public"))
				if err := run(t.Context(), args, nil, &stdout); err == nil || stdout.Len() != 0 {
					t.Fatal("invalid request produced a public-key file or stdout")
				}
				assertPublicKeyFiles(t, filepath.Dir(path), 1)
			}
		})
	}
}

func TestClientVerifyCSRRejectsUnsafeFiles(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"missing", "symlink", "dangling", "directory", "public file", "public parent", "oversized"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dir := privateDirectory(t)
			path := filepath.Join(dir, "synthetic-request")
			data := bytes.Repeat([]byte{0}, membercsr.DERSize)
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			var err error
			switch name {
			case "missing":
				path = filepath.Join(dir, "missing")
			case "symlink", "dangling":
				target := "synthetic-request"
				if name == "dangling" {
					target = "missing"
				}
				path = filepath.Join(dir, "link")
				err = os.Symlink(target, path)
			case "directory":
				path = dir
			case "public file":
				err = os.Chmod(path, 0o644)
			case "public parent":
				err = os.Chmod(dir, 0o755)
			case "oversized":
				err = os.WriteFile(path, append(data, 0), 0o600)
			}
			if err != nil {
				t.Fatal(err)
			}
			var stdout bytes.Buffer
			err = run(t.Context(), []string{"verify-csr", "-kind=member", "-in", path}, nil, &stdout)
			if err == nil || errors.Is(err, membercsr.ErrInvalidRequest) || stdout.Len() != 0 {
				t.Fatal("unsafe input was not rejected before profile parsing")
			}
			if strings.Contains(err.Error(), path) {
				t.Fatal("file failure reflected input path")
			}
		})
	}
}

func TestClientVerifyCSRFailsClosed(t *testing.T) {
	t.Parallel()
	var stdout bytes.Buffer
	if err := run(t.Context(), []string{"verify-csr", "-help"}, nil, &stdout); !errors.Is(err, flag.ErrHelp) || !strings.Contains(stdout.String(), "verify-csr") {
		t.Fatal("verification help failed or read stdin")
	}
	key, err := memberkey.Generate(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	der, err := membercsr.Create(t.Context(), key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(privateDirectory(t), "request")
	if err := os.WriteFile(path, der, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, pin := range []string{"", hex.EncodeToString(key[32:])} {
		args := []string{"verify-csr", "-kind=member", "-in", path}
		if pin != "" {
			args = append(args, "-expect-public-key", pin)
		}
		// Command entry, read entry, read completion, and final output guard.
		for _, at := range []int{1, 2, 3, 4} {
			stdout.Reset()
			ctx := &cancelAtCheck{Context: t.Context(), at: at}
			if err := run(ctx, args, nil, &stdout); !errors.Is(err, context.Canceled) || stdout.Len() != 0 {
				t.Fatal("cancelled verification wrote public output or lost cancellation")
			}
		}
		for _, writer := range []io.Writer{failingWriter{}, shortWriter{}} {
			if err := run(t.Context(), args, nil, writer); err == nil || strings.Contains(err.Error(), path) {
				t.Fatal("verification lost an output failure or reflected input")
			}
		}
	}
}

// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

package clientcli

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/hex"
	"errors"
	"flag"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mandipnotroot/anonce/internal/client/keystore"
	"github.com/mandipnotroot/anonce/internal/client/memberkey"
	"github.com/mandipnotroot/anonce/internal/client/reviewerkey"
)

func TestClientArguments(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		args []string
		want error
	}{
		{"generate member", []string{"generate", "-kind", "member", "-out", "backup"}, nil},
		{"inspect reviewer", []string{"inspect", "-kind=reviewer", "-in=backup"}, nil},
		{"rewrap member", []string{"rewrap", "-kind", "member", "-in", "old", "-out", "new"}, nil},
		{"rewrap reviewer", []string{"rewrap", "-kind=reviewer", "-in=old", "-out=new"}, nil},
		{"rewrap help", []string{"rewrap", "-help"}, flag.ErrHelp},
		{"csr member", []string{"csr", "-kind=member", "-in=backup"}, nil},
		{"csr help", []string{"csr", "-help"}, flag.ErrHelp},
		{"verify csr member", []string{"verify-csr", "-kind=member", "-in=request"}, nil},
		{"verify csr help", []string{"verify-csr", "-help"}, flag.ErrHelp},
		{"verify csr missing input", []string{"verify-csr", "-kind=member"}, errArguments},
		{"verify csr missing kind", []string{"verify-csr", "-in=request"}, errArguments},
		{"verify csr reviewer", []string{"verify-csr", "-kind=reviewer", "-in=request"}, errArguments},
		{"verify csr output flag", []string{"verify-csr", "-kind=member", "-in=request", "-out=result"}, errArguments},
		{"verify csr password flag", []string{"verify-csr", "-password=synthetic"}, errArguments},
		{"verify csr positional", []string{"verify-csr", "-kind=member", "-in=request", "extra"}, errArguments},
		{"verify csr empty path", []string{"verify-csr", "-kind=member", "-in="}, errArguments},
		{"verify csr null path", []string{"verify-csr", "-kind=member", "-in=a\x00b"}, errArguments},
		{"csr missing input", []string{"csr", "-kind=member"}, errArguments},
		{"csr missing kind", []string{"csr", "-in=backup"}, errArguments},
		{"csr reviewer", []string{"csr", "-kind=reviewer", "-in=backup"}, errArguments},
		{"csr output flag", []string{"csr", "-kind=member", "-in=backup", "-out=result"}, errArguments},
		{"csr subject flag", []string{"csr", "-kind=member", "-in=backup", "-subject=synthetic"}, errArguments},
		{"help", []string{"-help"}, flag.ErrHelp},
		{"operation help", []string{"generate", "-h"}, flag.ErrHelp},
		{"empty", nil, errArguments},
		{"unknown operation", []string{"sign"}, errArguments},
		{"missing kind", []string{"generate", "-out", "backup"}, errArguments},
		{"unknown kind", []string{"generate", "-kind", "ca", "-out", "backup"}, errArguments},
		{"missing output", []string{"generate", "-kind", "member"}, errArguments},
		{"missing input", []string{"inspect", "-kind", "reviewer"}, errArguments},
		{"rewrap missing input", []string{"rewrap", "-kind", "member", "-out", "new"}, errArguments},
		{"rewrap missing output", []string{"rewrap", "-kind", "reviewer", "-in", "old"}, errArguments},
		{"rewrap unknown kind", []string{"rewrap", "-kind", "ca", "-in", "old", "-out", "new"}, errArguments},
		{"rewrap password flag", []string{"rewrap", "-password=synthetic-input"}, errArguments},
		{"input on generate", []string{"generate", "-kind", "member", "-out", "b", "-in", "a"}, errArguments},
		{"output on inspect", []string{"inspect", "-kind", "member", "-in", "a", "-out", "b"}, errArguments},
		{"empty input on generate", []string{"generate", "-kind", "member", "-out", "b", "-in="}, errArguments},
		{"empty output on inspect", []string{"inspect", "-kind", "member", "-in", "a", "-out="}, errArguments},
		{"unknown flag", []string{"generate", "-password=synthetic-input"}, errArguments},
		{"missing value", []string{"generate", "-kind"}, errArguments},
		{"positional", []string{"generate", "-kind", "member", "-out", "b", "extra"}, errArguments},
		{"null path", []string{"inspect", "-kind", "member", "-in", "a\x00b"}, errArguments},
		{"oversized", []string{strings.Repeat("x", maxArgumentBytes)}, errArguments},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg, err := parse(tc.args)
			if !errors.Is(err, tc.want) {
				t.Fatalf("parse error = %v; want %v", err, tc.want)
			}
			if err == nil && (cfg.kind == "" || cfg.operation != tc.args[0]) {
				t.Fatal("missing parsed configuration")
			}
		})
	}
}

func TestClientPasswordInput(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		input   string
		confirm bool
		want    string
	}{
		{"single", "synthetic\n", false, "synthetic"},
		{"confirmation", "synthetic\nsynthetic\n", true, "synthetic"},
		{"opaque", " \x00\r\xff \n", false, " \x00\r\xff "},
		{"maximum", strings.Repeat("x", keystore.MaxPasswordSize) + "\n", false, strings.Repeat("x", keystore.MaxPasswordSize)},
		{"empty", "\n", false, ""},
		{"no input", "", false, ""},
		{"missing newline", "synthetic", false, ""},
		{"missing confirmation", "synthetic\n", true, ""},
		{"mismatch", "synthetic\ndifferent\n", true, ""},
		{"extra line", "synthetic\nextra\n", false, ""},
		{"trailing data", "synthetic\nsynthetic\nx", true, ""},
		{"oversized", strings.Repeat("x", keystore.MaxPasswordSize+1) + "\n", false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			file := passwordFile(t, tc.input)
			password, err := readPassword(t.Context(), file, tc.confirm)
			defer clear(password)
			if tc.want == "" {
				if err == nil || password != nil {
					t.Fatal("accepted malformed password framing")
				}
			} else if err != nil || !bytes.Equal(password, []byte(tc.want)) {
				t.Fatal("password bytes were not preserved")
			}
		})
	}
	device, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = device.Close() }()
	if password, err := readPassword(t.Context(), device, false); err == nil || password != nil {
		t.Fatal("accepted a character device as password input")
	}
	closed := passwordFile(t, "synthetic\n")
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := readPassword(t.Context(), closed, false); err == nil {
		t.Fatal("accepted closed input")
	}
}

func TestClientPasswordPipeCancellation(t *testing.T) {
	t.Parallel()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reader.Close() }()
	defer func() { _ = writer.Close() }()
	parent, cancel := context.WithCancel(t.Context())
	defer cancel()
	ctx := &observedContext{Context: parent, subscribed: make(chan struct{})}
	finished := make(chan error, 1)
	go func() {
		password, err := readPassword(ctx, reader, true)
		clear(password)
		finished <- err
	}()
	select {
	case <-ctx.subscribed:
		cancel()
	case <-time.After(5 * time.Second):
		t.Fatal("password reader did not subscribe to cancellation")
	}
	select {
	case err := <-finished:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation error = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled password read did not finish")
	}
}

type observedContext struct {
	context.Context
	subscribed chan struct{}
	once       sync.Once
}

func (c *observedContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.subscribed) })
	return c.Context.Done()
}

func TestClientPasswordPipe(t *testing.T) {
	t.Parallel()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reader.Close() }()
	defer func() { _ = writer.Close() }()
	if _, err := io.WriteString(writer, "synthetic\nsynthetic\n"); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	password, err := readPassword(t.Context(), reader, true)
	defer clear(password)
	if err != nil || !bytes.Equal(password, []byte("synthetic")) {
		t.Fatal("pipe password framing did not round trip")
	}
}

func TestClientInheritedPipeCancellation(t *testing.T) {
	if os.Getenv("ANONCE_TEST_INHERITED_PIPE") == "1" {
		ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
		defer cancel()
		password, err := readPassword(ctx, os.Stdin, true)
		clear(password)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("inherited pipe did not observe cancellation")
		}
		return
	}
	t.Parallel()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reader.Close() }()
	defer func() { _ = writer.Close() }()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestClientInheritedPipeCancellation$")
	command.Env = append(os.Environ(), "ANONCE_TEST_INHERITED_PIPE=1")
	command.Stdin = reader
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("inherited-pipe regression: %v; %s", err, output)
	}
}

func TestClientRoundTrip(t *testing.T) {
	for _, kind := range []string{"member", "reviewer"} {
		t.Run(kind, func(t *testing.T) {
			password := []byte("synthetic test password")
			defer clear(password)
			path := filepath.Join(privateDirectory(t), "backup")
			var output bytes.Buffer
			if err := run(t.Context(), []string{"generate", "-kind", kind, "-out", path},
				passwordFile(t, "synthetic test password\nsynthetic test password\n"), &output); err != nil {
				t.Fatal(err)
			}
			if output.Len() != 0 {
				t.Fatal("generation unexpectedly wrote to stdout")
			}
			backup, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if len(backup) != 108 {
				t.Fatal("generation did not preserve the existing backup profile")
			}
			var public []byte
			if kind == "member" {
				key, err := memberkey.Open(t.Context(), password, backup)
				if err != nil {
					t.Fatal(err)
				}
				public = bytes.Clone(key[32:])
				clear(key)
			} else {
				key, err := reviewerkey.Open(t.Context(), password, backup)
				if err != nil {
					t.Fatal(err)
				}
				private, err := ecdh.X25519().NewPrivateKey(key)
				clear(key)
				if err != nil {
					t.Fatal(err)
				}
				public = private.PublicKey().Bytes()
			}
			args := []string{"inspect", "-kind", kind, "-in", path}
			if err := run(t.Context(), args, passwordFile(t, "synthetic test password\n"), &output); err != nil {
				t.Fatal(err)
			}
			if output.String() != kind+":"+hex.EncodeToString(public)+"\n" {
				t.Fatal("inspect did not return exactly the expected public key")
			}
			for _, tc := range []struct {
				name     string
				kind     string
				password string
				tamper   bool
			}{
				{"wrong password", kind, "different synthetic password\n", false},
				{"wrong purpose", map[string]string{"member": "reviewer", "reviewer": "member"}[kind], "synthetic test password\n", false},
				{"tampered ciphertext", kind, "synthetic test password\n", true},
			} {
				t.Run(tc.name, func(t *testing.T) {
					if tc.tamper {
						backup[len(backup)-1] ^= 1
						if err := os.WriteFile(path, backup, 0o600); err != nil {
							t.Fatal(err)
						}
					}
					output.Reset()
					err := run(t.Context(), []string{"inspect", "-kind", tc.kind, "-in", path}, passwordFile(t, tc.password), &output)
					if !errors.Is(err, keystore.ErrInvalidBackup) || output.Len() != 0 {
						t.Fatal("invalid backup produced public output or wrong error")
					}
				})
			}
		})
	}
}

func TestClientFailsClosed(t *testing.T) {
	t.Parallel()
	var output bytes.Buffer
	if err := run(t.Context(), []string{"-help"}, nil, &output); !errors.Is(err, flag.ErrHelp) || !strings.Contains(output.String(), "Development-only") {
		t.Fatal("help missing or read stdin")
	}
	output.Reset()
	err := run(t.Context(), []string{"generate", "-password=synthetic-input"}, nil, &output)
	if !errors.Is(err, errArguments) || output.Len() != 0 || strings.Contains(err.Error(), "synthetic-input") {
		t.Fatal("argument error read stdin or reflected input")
	}
	path := filepath.Join(t.TempDir(), "backup")
	if err := run(t.Context(), []string{"generate", "-kind", "member", "-out", path}, passwordFile(t, "synthetic\ndifferent\n"), &output); err == nil {
		t.Fatal("generated a backup without password confirmation")
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed generation created output")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := run(ctx, []string{"generate", "-kind", "member", "-out", path}, nil, &output); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled command read stdin")
	}
	if _, err := generate(ctx, "member", []byte("synthetic")); !errors.Is(err, context.Canceled) {
		t.Fatal("member generation ignored cancellation")
	}
	if _, err := generate(ctx, "reviewer", []byte("synthetic")); !errors.Is(err, context.Canceled) {
		t.Fatal("reviewer generation ignored cancellation")
	}
	if key, err := generate(t.Context(), "unsupported", nil); !errors.Is(err, errArguments) || key != nil {
		t.Fatal("unsupported generation kind selected a key algorithm")
	}
	if key, err := inspect(t.Context(), "unsupported", nil, nil); !errors.Is(err, errArguments) || key != nil {
		t.Fatal("unsupported inspection kind selected a key algorithm")
	}
	if err := run(t.Context(), []string{"-help"}, nil, failingWriter{}); err == nil || errors.Is(err, flag.ErrHelp) {
		t.Fatal("help write failure was lost")
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func passwordFile(t *testing.T, data string) *os.File {
	t.Helper()
	file, err := os.CreateTemp(t.TempDir(), "password-input-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close() })
	if _, err := io.WriteString(file, data); err != nil {
		t.Fatal(err)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	return file
}

func FuzzClientArguments(f *testing.F) {
	f.Add("generate\x00-kind\x00member\x00-out\x00backup")
	f.Add("inspect\x00-kind=reviewer\x00-in=backup")
	f.Add("rewrap\x00-kind=member\x00-in=old\x00-out=new")
	f.Add("csr\x00-kind=member\x00-in=backup")
	f.Add("verify-csr\x00-kind=member\x00-in=request")
	f.Add("verify-csr\x00-kind=reviewer\x00-in=request")
	f.Add("-help")
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > maxArgumentBytes+1 {
			return
		}
		cfg, err := parse(strings.Split(input, "\x00"))
		if err == nil && (cfg.kind != "member" && cfg.kind != "reviewer" ||
			cfg.operation != "generate" && cfg.operation != "inspect" && cfg.operation != "rewrap" && cfg.operation != "csr" && cfg.operation != "verify-csr" ||
			(cfg.operation == "csr" || cfg.operation == "verify-csr") && cfg.kind != "member" ||
			cfg.operation != "generate" && cfg.input == "" ||
			(cfg.operation == "generate" || cfg.operation == "rewrap") && cfg.output == "") {
			t.Fatal("parser accepted unsupported configuration")
		}
	})
}

func FuzzClientPassword(f *testing.F) {
	f.Add([]byte("synthetic\nsynthetic\n"), true)
	f.Add([]byte("synthetic\n"), false)
	f.Add([]byte{}, false)
	f.Fuzz(func(t *testing.T, data []byte, confirm bool) {
		if len(data) > 2*(keystore.MaxPasswordSize+1)+1 {
			return
		}
		password, err := parsePassword(data, confirm)
		defer clear(password)
		if err != nil {
			if password != nil {
				t.Fatal("failed password parse returned output")
			}
			return
		}
		if len(password) == 0 || len(password) > keystore.MaxPasswordSize || bytes.ContainsRune(password, '\n') {
			t.Fatal("parser returned unsupported password")
		}
		if bytes.IndexByte(data, '\n') != len(password) || !bytes.Equal(password, data[:len(password)]) {
			t.Fatal("parser changed password bytes")
		}
	})
}

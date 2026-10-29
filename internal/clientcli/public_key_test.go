// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

package clientcli

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/mandipnotroot/anonce/internal/client/membercsr"
	"github.com/mandipnotroot/anonce/internal/client/memberkey"
)

func TestClientPublicKeyFileArguments(t *testing.T) {
	t.Parallel()
	for _, base := range [][]string{
		{"inspect", "-kind=member", "-in=backup"},
		{"inspect", "-kind=reviewer", "-in=backup"},
		{"verify-csr", "-kind=member", "-in=request"},
	} {
		for _, tc := range []struct {
			name  string
			flags []string
			valid bool
		}{
			{"omitted", nil, true},
			{"equals", []string{"-out=public"}, true},
			{"split", []string{"-out", "public"}, true},
			{"empty", []string{"-out="}, false},
			{"empty split", []string{"-out", ""}, false},
			{"missing value", []string{"-out"}, false},
			{"null", []string{"-out=a\x00b"}, false},
		} {
			t.Run(base[0]+base[1]+"/"+tc.name, func(t *testing.T) {
				t.Parallel()
				args := append(slices.Clone(base), tc.flags...)
				cfg, err := parse(args)
				if tc.valid {
					if err != nil || (len(tc.flags) != 0 && cfg.output != "public") {
						t.Fatal("valid public-key output arguments rejected or changed")
					}
					return
				}
				var stdout bytes.Buffer
				if !errors.Is(err, errArguments) || !errors.Is(run(t.Context(), args, nil, &stdout), errArguments) || stdout.Len() != 0 {
					t.Fatal("invalid output arguments did not fail before stdin or file access")
				}
			})
		}
	}
}

func TestClientPublicKeyFile(t *testing.T) {
	for _, command := range []string{"inspect member", "inspect reviewer", "verify-csr member"} {
		t.Run(command, func(t *testing.T) {
			args, public, source := publicKeyFixture(t, command)
			input := args[4]
			dir := filepath.Dir(input)
			want := args[2] + ":" + hex.EncodeToString(public) + "\n"
			for i, pin := range []string{"", hex.EncodeToString(public), strings.ToUpper(hex.EncodeToString(public))} {
				path := filepath.Join(dir, fmt.Sprintf("public-%d", i))
				flags := append(slices.Clone(args), "-out", path)
				if pin != "" {
					flags = append(flags, "-expect-public-key", pin)
				}
				// A failing stdout writer must be unused when file output is selected.
				if err := run(t.Context(), flags, publicKeyPassword(t, command), failingWriter{}); err != nil {
					t.Fatal(err)
				}
				data, err := os.ReadFile(path)
				if err != nil || string(data) != want {
					t.Fatal("file did not contain exactly the public-key line")
				}
				info, err := os.Stat(path)
				if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
					t.Fatal("public-key file is not owner-only and regular")
				}
				var stdout bytes.Buffer
				if err := run(t.Context(), flags, publicKeyPassword(t, command), &stdout); err == nil || stdout.Len() != 0 {
					t.Fatal("existing public-key file replaced or failure fell back to stdout")
				}
			}
			data, err := os.ReadFile(input)
			if err != nil || !bytes.Equal(data, source) {
				t.Fatal("public-key export changed its input")
			}
			assertPublicKeyFiles(t, dir, 4)
		})
	}
}

func TestClientPublicKeyFileValidation(t *testing.T) {
	for _, command := range []string{"inspect member", "inspect reviewer", "verify-csr member"} {
		t.Run(command, func(t *testing.T) {
			args, public, source := publicKeyFixture(t, command)
			input := args[4]
			dir := filepath.Dir(input)
			path := filepath.Join(dir, "public")
			base := append(slices.Clone(args), "-out", path)
			mismatch := bytes.Clone(public)
			mismatch[len(mismatch)-1] ^= 1
			for _, name := range []string{"mismatch", "tampered", "wrong password", "wrong purpose"} {
				if args[0] == "verify-csr" && (name == "wrong password" || name == "wrong purpose") {
					continue
				}
				t.Run(name, func(t *testing.T) {
					flags := slices.Clone(base)
					stdin := publicKeyPassword(t, command)
					switch name {
					case "mismatch":
						flags = append(flags, "-expect-public-key", hex.EncodeToString(mismatch))
					case "tampered":
						tampered := bytes.Clone(source)
						tampered[len(tampered)-1] ^= 1
						if err := os.WriteFile(input, tampered, 0o600); err != nil {
							t.Fatal(err)
						}
						defer func() {
							if err := os.WriteFile(input, source, 0o600); err != nil {
								t.Error(err)
							}
						}()
						flags = append(flags, "-expect-public-key", hex.EncodeToString(public))
					case "wrong password":
						stdin = passwordFile(t, "different\n")
					case "wrong purpose":
						flags[2] = "reviewer"
						if args[2] == "reviewer" {
							flags[2] = "member"
						}
					}
					var stdout bytes.Buffer
					err := run(t.Context(), flags, stdin, &stdout)
					if err == nil || stdout.Len() != 0 {
						t.Fatal("failed validation returned public output")
					}
					for _, value := range []string{input, path, hex.EncodeToString(public), hex.EncodeToString(mismatch), "synthetic"} {
						if strings.Contains(err.Error(), value) {
							t.Fatal("validation failure reflected input")
						}
					}
					assertPublicKeyFiles(t, dir, 1)
				})
			}
		})
	}
}

func TestClientPublicKeyFileRejectsUnsafePaths(t *testing.T) {
	for _, command := range []string{"inspect member", "inspect reviewer", "verify-csr member"} {
		t.Run(command, func(t *testing.T) {
			args, _, source := publicKeyFixture(t, command)
			input := args[4]
			dir := filepath.Dir(input)
			for _, name := range []string{"input", "existing", "symlink", "dangling", "directory", "public parent", "missing parent"} {
				t.Run(name, func(t *testing.T) {
					parent := privateDirectory(t)
					path := filepath.Join(parent, "public")
					switch name {
					case "input":
						path = input
					case "existing":
						if err := os.WriteFile(path, []byte("existing public record"), 0o600); err != nil {
							t.Fatal(err)
						}
					case "symlink", "dangling":
						target := input
						if name == "dangling" {
							target = filepath.Join(parent, "missing")
						}
						if err := os.Symlink(target, path); err != nil {
							t.Fatal(err)
						}
					case "directory":
						path = parent
					case "public parent":
						if err := os.Chmod(parent, 0o755); err != nil {
							t.Fatal(err)
						}
					case "missing parent":
						path = filepath.Join(parent, "missing", "public")
					}
					checkDestination := unchangedPath(t, path)
					var stdout bytes.Buffer
					flags := append(slices.Clone(args), "-out", path)
					if err := run(t.Context(), flags, publicKeyPassword(t, command), &stdout); err == nil || stdout.Len() != 0 || strings.Contains(err.Error(), path) {
						t.Fatal("unsafe publication succeeded, wrote stdout, or reflected a path")
					}
					checkDestination()
					if _, err := os.Lstat(filepath.Join(parent, "missing")); !errors.Is(err, os.ErrNotExist) {
						t.Fatal("publication created a missing parent or symlink target")
					}
					if err := filepath.WalkDir(parent, func(path string, entry os.DirEntry, err error) error {
						if err == nil && strings.HasPrefix(entry.Name(), ".anonce-public-key-") {
							t.Error("failed publication left a temporary file")
						}
						return err
					}); err != nil {
						t.Fatal(err)
					}
				})
			}
			data, err := os.ReadFile(input)
			if err != nil || !bytes.Equal(data, source) {
				t.Fatal("failed publication changed the source")
			}
			assertPublicKeyFiles(t, dir, 1)
		})
	}
}

func TestClientPublicKeyFileCancellation(t *testing.T) {
	for _, command := range []string{"inspect member", "inspect reviewer", "verify-csr member"} {
		t.Run(command, func(t *testing.T) {
			args, public, _ := publicKeyFixture(t, command)
			observed := &cancelAtCheck{Context: t.Context(), at: maxArgumentBytes}
			path := filepath.Join(privateDirectory(t), "public")
			base := append(slices.Clone(args), "-expect-public-key", hex.EncodeToString(public), "-out")
			if err := run(observed, append(slices.Clone(base), path), publicKeyPassword(t, command), failingWriter{}); err != nil {
				t.Fatal(err)
			}
			// Cover entry, file entry, pre-publication, and post-publication checks.
			for _, at := range []int{1, observed.calls - 2, observed.calls - 1, observed.calls} {
				dir := privateDirectory(t)
				path := filepath.Join(dir, "public")
				ctx := &cancelAtCheck{Context: t.Context(), at: at}
				var stdout bytes.Buffer
				err := run(ctx, append(slices.Clone(base), path), publicKeyPassword(t, command), &stdout)
				if !errors.Is(err, context.Canceled) || stdout.Len() != 0 {
					t.Fatal("file export lost cancellation or wrote stdout")
				}
				if at == observed.calls {
					data, err := os.ReadFile(path)
					if err != nil || string(data) != args[2]+":"+hex.EncodeToString(public)+"\n" {
						t.Fatal("post-publication cancellation lost the complete public key")
					}
					assertPublicKeyFiles(t, dir, 1)
				} else {
					assertPublicKeyFiles(t, dir, 0)
				}
			}
		})
	}
}

func TestClientPublicKeyFileConcurrentPublication(t *testing.T) {
	for _, command := range []string{"inspect member", "inspect reviewer", "verify-csr member"} {
		t.Run(command, func(t *testing.T) {
			args, public, _ := publicKeyFixture(t, command)
			dir := privateDirectory(t)
			path := filepath.Join(dir, "public")
			flags := append(slices.Clone(args), "-expect-public-key", hex.EncodeToString(public), "-out", path)
			var successes atomic.Int32
			var group sync.WaitGroup
			for range 4 {
				stdin := publicKeyPassword(t, command)
				group.Go(func() {
					var stdout bytes.Buffer
					if err := run(t.Context(), flags, stdin, &stdout); err == nil {
						successes.Add(1)
					}
					if stdout.Len() != 0 {
						t.Error("concurrent file export wrote stdout")
					}
				})
			}
			group.Wait()
			data, err := os.ReadFile(path)
			if successes.Load() != 1 || err != nil || string(data) != args[2]+":"+hex.EncodeToString(public)+"\n" {
				t.Fatal("concurrent publication did not produce exactly one complete winner")
			}
			assertPublicKeyFiles(t, dir, 1)
		})
	}
}

func publicKeyFixture(t *testing.T, command string) ([]string, []byte, []byte) {
	t.Helper()
	operation, kind, _ := strings.Cut(command, " ")
	password := []byte("synthetic")
	defer clear(password)
	var data, public []byte
	if operation == "verify-csr" {
		key, err := memberkey.Generate(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer clear(key)
		data, err = membercsr.Create(t.Context(), key)
		if err != nil {
			t.Fatal(err)
		}
		public = bytes.Clone(key[32:])
	} else {
		var err error
		data, err = generate(t.Context(), kind, password)
		if err != nil {
			t.Fatal(err)
		}
		public, err = inspect(t.Context(), kind, password, data)
		if err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(privateDirectory(t), "input")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return []string{operation, "-kind", kind, "-in", path}, public, data
}

func publicKeyPassword(t *testing.T, command string) *os.File {
	t.Helper()
	if strings.HasPrefix(command, "verify-csr ") {
		return nil
	}
	return passwordFile(t, "synthetic\n")
}

func assertPublicKeyFiles(t *testing.T, dir string, count int) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != count {
		t.Fatal("unexpected files after public-key export")
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".anonce-public-key-") {
			t.Fatal("public-key export left a temporary file")
		}
	}
}

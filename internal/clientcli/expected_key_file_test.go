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
	"testing"

	"github.com/mandipnotroot/anonce/internal/client/membercsr"
)

func TestClientExpectedKeyFileArguments(t *testing.T) {
	t.Parallel()
	for _, command := range []string{"inspect member", "inspect reviewer", "rewrap member", "rewrap reviewer", "csr member", "verify-csr member", "generate member", "generate reviewer"} {
		operation, kind, _ := strings.Cut(command, " ")
		base := []string{operation, "-kind", kind}
		if operation != "generate" {
			base = append(base, "-in=missing")
		}
		if operation == "generate" || operation == "rewrap" {
			base = append(base, "-out=missing-output")
		}
		for _, tc := range []struct {
			name  string
			flags []string
			valid bool
		}{
			{"equals", []string{"-expect-public-key-file=trusted"}, true},
			{"split", []string{"-expect-public-key-file", "trusted"}, true},
			{"empty", []string{"-expect-public-key-file="}, false},
			{"empty split", []string{"-expect-public-key-file", ""}, false},
			{"missing", []string{"-expect-public-key-file"}, false},
			{"null", []string{"-expect-public-key-file=a\x00b"}, false},
			{"oversized", []string{"-expect-public-key-file=" + strings.Repeat("x", maxArgumentBytes)}, false},
			{"repeated", []string{"-expect-public-key-file=trusted", "-expect-public-key-file=trusted"}, false},
			{"repeated empty", []string{"-expect-public-key-file=trusted", "-expect-public-key-file="}, false},
			{"file then hex", []string{"-expect-public-key-file=trusted", "-expect-public-key=" + strings.Repeat("ab", 32)}, false},
			{"hex then file", []string{"-expect-public-key=" + strings.Repeat("ab", 32), "-expect-public-key-file=trusted"}, false},
		} {
			t.Run(command+"/"+tc.name, func(t *testing.T) {
				t.Parallel()
				args := append(slices.Clone(base), tc.flags...)
				cfg, err := parse(args)
				if tc.valid && operation != "generate" {
					if err != nil || cfg.expectedKeyFile != "trusted" || cfg.expectedPublicKey != nil {
						t.Fatal("expected-key file argument rejected or changed")
					}
					return
				}
				var stdout bytes.Buffer
				if !errors.Is(err, errArguments) || cfg.operation != "" ||
					!errors.Is(run(t.Context(), args, nil, &stdout), errArguments) || stdout.Len() != 0 {
					t.Fatal("invalid expected-key file flag did not fail before file/stdin access")
				}
			})
		}
	}
}

func TestClientPublicKeyLine(t *testing.T) {
	t.Parallel()
	encoded := strings.Repeat("ab", 32) // Synthetic public parser input only.
	for _, kind := range []string{"member", "reviewer"} {
		line := kind + ":" + encoded + "\n"
		for _, tc := range []struct {
			name string
			data string
		}{
			{"valid", line},
			{"empty", ""},
			{"bare hex", encoded},
			{"uppercase hex", kind + ":" + strings.ToUpper(encoded) + "\n"},
			{"uppercase kind", strings.ToUpper(kind) + ":" + encoded + "\n"},
			{"wrong kind", "unknown:" + encoded + "\n"},
			{"missing LF", strings.TrimSuffix(line, "\n")},
			{"CRLF", strings.TrimSuffix(line, "\n") + "\r\n"},
			{"trailing", line + "x"},
			{"extra line", line + line},
			{"space", " " + line[1:]},
			{"separator", kind + ";" + encoded + "\n"},
			{"not hex", kind + ":" + encoded[:63] + "z\n"},
			{"null", kind + ":" + encoded[:63] + "\x00\n"},
			{"non ASCII", kind + ":" + encoded[:62] + "é\n"},
			{"oversized", strings.Repeat("x", maxArgumentBytes)},
		} {
			t.Run(kind+"/"+tc.name, func(t *testing.T) {
				t.Parallel()
				data := []byte(tc.data)
				public, err := parsePublicKeyLine(kind, data)
				if tc.name == "valid" {
					if err != nil || hex.EncodeToString(public) != encoded {
						t.Fatal("canonical public record rejected or changed")
					}
					clear(data)
					if hex.EncodeToString(public) != encoded {
						t.Fatal("parsed key aliases input")
					}
				} else if err == nil || public != nil || strings.Contains(err.Error(), encoded) {
					t.Fatal("malformed public record returned output or reflected input")
				}
			})
		}
	}
	for _, kind := range []string{"", "unknown"} {
		if public, err := parsePublicKeyLine(kind, []byte(kind+":"+encoded+"\n")); err == nil || public != nil {
			t.Fatal("unknown kind accepted")
		}
	}
}

func TestClientExpectedKeyFile(t *testing.T) {
	for _, command := range []string{"inspect member", "inspect reviewer", "rewrap member", "rewrap reviewer", "csr member", "verify-csr member"} {
		t.Run(command, func(t *testing.T) {
			args, public, source := publicKeyFixture(t, command)
			input, kind := args[4], args[2]
			dir := filepath.Dir(input)
			pin := filepath.Join(dir, "trusted")
			line := fmt.Sprintf("%s:%x\n", kind, public)
			// Use the real export path so these tests cover direct file reuse.
			if err := outputPublicKey(t.Context(), kind, public, pin, failingWriter{}); err != nil {
				t.Fatal(err)
			}
			base := append(slices.Clone(args), "-expect-public-key-file", pin)
			for _, fileOutput := range []bool{false, true} {
				if args[0] == "rewrap" && !fileOutput {
					continue
				}
				flags := slices.Clone(base)
				destination := filepath.Join(dir, "output")
				if fileOutput {
					flags = append(flags, "-out", destination)
				}
				var stdout bytes.Buffer
				if err := run(t.Context(), flags, expectedKeyPassword(t, command), &stdout); err != nil {
					t.Fatal(err)
				}
				result := stdout.Bytes()
				if fileOutput {
					var err error
					result, err = os.ReadFile(destination)
					if err != nil || stdout.Len() != 0 {
						t.Fatal("expected-key file operation lost output or wrote stdout")
					}
				}
				switch args[0] {
				case "csr":
					key, err := membercsr.Parse(result)
					if err != nil || !bytes.Equal(key, public) {
						t.Fatal("expected-key file changed request profile/key")
					}
				case "rewrap":
					key, err := inspect(t.Context(), kind, []byte("replacement"), result)
					if err != nil || !bytes.Equal(key, public) || bytes.Equal(result, source) {
						t.Fatal("expected-key file did not preserve rewrapped key with fresh encryption")
					}
				default:
					if string(result) != line {
						t.Fatal("expected-key file changed public output")
					}
				}
			}
			// No-replace publication must also protect the trusted record itself.
			flags := append(slices.Clone(base), "-out", pin)
			var stdout bytes.Buffer
			if err := run(t.Context(), flags, expectedKeyPassword(t, command), &stdout); err == nil || stdout.Len() != 0 {
				t.Fatal("expected-key file was replaced or failure wrote stdout")
			}
			for path, want := range map[string][]byte{input: source, pin: []byte(line)} {
				data, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(data, want) {
					t.Fatal("operation modified a source file")
				}
			}
			assertPublicKeyFiles(t, dir, 3)
		})
	}
}

func TestClientExpectedKeyFileValidation(t *testing.T) {
	for _, command := range []string{"inspect member", "inspect reviewer", "rewrap member", "rewrap reviewer", "csr member", "verify-csr member"} {
		t.Run(command, func(t *testing.T) {
			args, public, source := publicKeyFixture(t, command)
			input, kind := args[4], args[2]
			dir := filepath.Dir(input)
			pin, destination := filepath.Join(dir, "trusted"), filepath.Join(dir, "output")
			for _, name := range []string{"mismatch", "wrong kind", "malformed", "tampered", "wrong password"} {
				if name == "wrong password" && args[0] == "verify-csr" {
					continue
				}
				t.Run(name, func(t *testing.T) {
					key := bytes.Clone(public)
					tag := kind
					if name == "mismatch" {
						key[len(key)-1] ^= 1
					}
					if name == "wrong kind" {
						tag = map[string]string{"member": "reviewer", "reviewer": "member"}[kind]
					}
					line := fmt.Sprintf("%s:%x\n", tag, key)
					if name == "malformed" {
						line = strings.TrimSuffix(line, "\n")
					}
					if err := os.WriteFile(pin, []byte(line), 0o600); err != nil {
						t.Fatal(err)
					}
					if name == "tampered" {
						data := bytes.Clone(source)
						data[len(data)-1] ^= 1
						if err := os.WriteFile(input, data, 0o600); err != nil {
							t.Fatal(err)
						}
						defer func() {
							if err := os.WriteFile(input, source, 0o600); err != nil {
								t.Error(err)
							}
						}()
					}
					stdin := expectedKeyPassword(t, command)
					if name == "wrong password" {
						stdin = passwordFile(t, "wrong\n")
						if args[0] == "rewrap" {
							stdin = passwordFile(t, "wrong\nreplacement\nreplacement\n")
						}
					}
					if name == "malformed" || name == "wrong kind" {
						stdin = nil // The expected file must fail before password access.
					}
					flags := append(slices.Clone(args), "-expect-public-key-file", pin, "-out", destination)
					var stdout bytes.Buffer
					err := run(t.Context(), flags, stdin, &stdout)
					if err == nil || stdout.Len() != 0 {
						t.Fatal("invalid pinned operation returned output")
					}
					for _, value := range []string{pin, input, destination, hex.EncodeToString(public), hex.EncodeToString(key), "synthetic", "replacement"} {
						if strings.Contains(err.Error(), value) {
							t.Fatal("error reflected input")
						}
					}
					data, readErr := os.ReadFile(pin)
					if readErr != nil || string(data) != line {
						t.Fatal("failed operation changed trusted record")
					}
					assertPublicKeyFiles(t, dir, 2)
				})
			}
			data, err := os.ReadFile(input)
			if err != nil || !bytes.Equal(data, source) {
				t.Fatal("failed operation changed input")
			}
		})
	}
}

func TestClientExpectedKeyFileRejectsUnsafePaths(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"missing", "empty", "oversized", "public file", "public parent", "symlink", "dangling", "directory", "device"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dir := privateDirectory(t)
			path := filepath.Join(dir, "trusted")
			line := "member:" + strings.Repeat("ab", 32) + "\n"
			switch name {
			case "missing":
			case "symlink", "dangling":
				target := filepath.Join(dir, "target")
				if name == "symlink" {
					if err := os.WriteFile(target, []byte(line), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			case "directory":
				path = dir
			case "device":
				path = os.DevNull
			default:
				data := line
				switch name {
				case "empty":
					data = ""
				case "oversized":
					data += "x"
				}
				if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
					t.Fatal(err)
				}
				if name == "public file" {
					if err := os.Chmod(path, 0o644); err != nil {
						t.Fatal(err)
					}
					info, err := os.Stat(path)
					if err != nil || info.Mode().Perm() != 0o644 {
						t.Fatal("unsafe expected-key fixture has incorrect permissions")
					}
				}
				if name == "public parent" {
					if err := os.Chmod(dir, 0o755); err != nil {
						t.Fatal(err)
					}
				}
			}
			var stdout bytes.Buffer
			args := []string{"inspect", "-kind=member", "-in=missing", "-expect-public-key-file", path}
			if err := run(t.Context(), args, nil, &stdout); err == nil || stdout.Len() != 0 || strings.Contains(err.Error(), path) {
				t.Fatal("unsafe expected-key file did not fail before stdin without output/reflection")
			}
		})
	}
}

func TestClientExpectedKeyFileCancellation(t *testing.T) {
	t.Parallel()
	path := filepath.Join(privateDirectory(t), "trusted")
	if err := os.WriteFile(path, []byte("member:"+strings.Repeat("ab", 32)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Entry, expected-file entry, and post-read cancellation must precede stdin.
	for _, at := range []int{1, 2, 3} {
		ctx := &cancelAtCheck{Context: t.Context(), at: at}
		var stdout bytes.Buffer
		err := run(ctx, []string{"inspect", "-kind=member", "-in=missing", "-expect-public-key-file", path}, nil, &stdout)
		if !errors.Is(err, context.Canceled) || stdout.Len() != 0 {
			t.Fatal("expected-key file lost cancellation or returned output")
		}
	}
}

func TestClientExpectedKeyFileConcurrent(t *testing.T) {
	t.Parallel()
	args, public, _ := publicKeyFixture(t, "verify-csr member")
	path := filepath.Join(filepath.Dir(args[4]), "trusted")
	if err := outputPublicKey(t.Context(), "member", public, path, failingWriter{}); err != nil {
		t.Fatal(err)
	}
	flags := append(slices.Clone(args), "-expect-public-key-file", path)
	var group sync.WaitGroup
	for range 4 {
		group.Go(func() {
			var stdout bytes.Buffer
			if err := run(t.Context(), flags, nil, &stdout); err != nil || stdout.String() != fmt.Sprintf("member:%x\n", public) {
				t.Error("concurrent expected-key file verification failed")
			}
		})
	}
	group.Wait()
}

func expectedKeyPassword(t *testing.T, command string) *os.File {
	t.Helper()
	if strings.HasPrefix(command, "rewrap ") {
		return passwordFile(t, "synthetic\nreplacement\nreplacement\n")
	}
	return publicKeyPassword(t, command)
}

func FuzzClientPublicKeyLine(f *testing.F) {
	for _, kind := range []string{"member", "reviewer", "unknown"} {
		f.Add(kind, []byte(kind+":"+strings.Repeat("ab", 32)+"\n"))
		f.Add(kind, []byte(kind+":"+strings.Repeat("AB", 32)+"\n"))
		f.Add(kind, []byte{})
	}
	f.Fuzz(func(t *testing.T, kind string, data []byte) {
		if len(kind) > 9 || len(data) > 75 {
			return
		}
		public, err := parsePublicKeyLine(kind, data)
		if err != nil {
			if public != nil {
				t.Fatal("failed parser returned a key")
			}
			return
		}
		if (kind != "member" && kind != "reviewer") || len(public) != 32 ||
			!bytes.Equal(data, fmt.Appendf(nil, "%s:%x\n", kind, public)) {
			t.Fatal("parser accepted a noncanonical record")
		}
	})
}

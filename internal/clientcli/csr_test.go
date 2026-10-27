// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

package clientcli

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
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
	requestPath := filepath.Join(privateDirectory(t), "request")
	fileArgs := append([]string{"csr", "-kind=member", "-in", path}, "-out", requestPath)
	if err := run(t.Context(), fileArgs, passwordFile(t, "synthetic\n"), failingWriter{}); err != nil {
		t.Fatal(err)
	}
	request, err := os.ReadFile(requestPath)
	if err != nil || !bytes.Equal(request, stdout.Bytes()) {
		t.Fatal("file export differed from stdout DER")
	}
	info, err := os.Stat(requestPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() != membercsr.DERSize {
		t.Fatal("request was not a bounded owner-only regular file")
	}
	entries, err := os.ReadDir(filepath.Dir(requestPath))
	if err != nil || len(entries) != 1 {
		t.Fatal("request export left a temporary file")
	}
	stdout.Reset()
	if err := run(t.Context(), []string{"verify-csr", "-kind=member", "-in", requestPath}, nil, &stdout); err != nil {
		t.Fatal(err)
	}
	var inspected bytes.Buffer
	if err := run(t.Context(), []string{"inspect", "-kind=member", "-in", path}, passwordFile(t, "synthetic\n"), &inspected); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stdout.Bytes(), inspected.Bytes()) {
		t.Fatal("request verification disagreed with backup inspection")
	}
	original, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(original, backup) {
		t.Fatal("CSR changed the input backup")
	}
	entries, err = os.ReadDir(directory)
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
			for _, fileOutput := range []bool{false, true} {
				outputPath := filepath.Join(privateDirectory(t), "request")
				args := []string{"csr", "-kind=member", "-in", path}
				if fileOutput {
					args = append(args, "-out", outputPath)
				}
				var stdout bytes.Buffer
				err := run(t.Context(), args, passwordFile(t, tc.framing), &stdout)
				if !errors.Is(err, keystore.ErrInvalidBackup) || stdout.Len() != 0 {
					t.Fatal("invalid backup produced a request")
				}
				if strings.Contains(err.Error(), path) || strings.Contains(err.Error(), "synthetic") || strings.Contains(err.Error(), "different") {
					t.Fatal("failure reflected input")
				}
				entries, err := os.ReadDir(filepath.Dir(outputPath))
				if err != nil || len(entries) != 0 {
					t.Fatal("invalid backup created an output file")
				}
			}
		})
	}
}

func TestClientCSRFileRejectsUnsafePaths(t *testing.T) {
	password := []byte("synthetic")
	defer clear(password)
	backup, err := generate(t.Context(), "member", password)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		setup func(*testing.T, string, string) string
	}{
		{"existing file", func(t *testing.T, dir, input string) string {
			path := filepath.Join(dir, "request")
			if err := os.WriteFile(path, []byte("synthetic existing request"), 0o600); err != nil {
				t.Fatal(err)
			}
			return path
		}},
		{"input backup", func(t *testing.T, dir, input string) string { return input }},
		{"symlink to backup", func(t *testing.T, dir, input string) string {
			path := filepath.Join(dir, "request")
			if err := os.Symlink(input, path); err != nil {
				t.Fatal(err)
			}
			return path
		}},
		{"dangling symlink", func(t *testing.T, dir, input string) string {
			path := filepath.Join(dir, "request")
			if err := os.Symlink("missing", path); err != nil {
				t.Fatal(err)
			}
			return path
		}},
		{"directory", func(t *testing.T, dir, input string) string { return dir }},
		{"public parent", func(t *testing.T, dir, input string) string {
			parent := filepath.Join(dir, "public")
			if err := os.Mkdir(parent, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(parent, 0o755); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(parent, "request")
		}},
		{"missing parent", func(t *testing.T, dir, input string) string {
			return filepath.Join(dir, "missing", "request")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := privateDirectory(t)
			input := filepath.Join(dir, "backup")
			if err := writeBackup(t.Context(), input, backup); err != nil {
				t.Fatal(err)
			}
			path := tc.setup(t, dir, input)
			before, statErr := os.Lstat(path)
			var existing []byte
			if statErr == nil && before.Mode().IsRegular() {
				existing, err = os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
			}
			var stdout bytes.Buffer
			err := run(t.Context(), []string{"csr", "-kind=member", "-in", input, "-out", path}, passwordFile(t, "synthetic\n"), &stdout)
			if err == nil || stdout.Len() != 0 {
				t.Fatal("unsafe request destination succeeded or wrote stdout")
			}
			if strings.Contains(err.Error(), path) || strings.Contains(err.Error(), "synthetic") {
				t.Fatal("publication failure reflected input")
			}
			after, err := os.Lstat(path)
			if statErr == nil {
				if err != nil || !os.SameFile(before, after) {
					t.Fatal("existing destination was replaced")
				}
				if existing != nil {
					data, err := os.ReadFile(path)
					if err != nil || !bytes.Equal(data, existing) {
						t.Fatal("existing destination contents changed")
					}
				}
			} else if !errors.Is(err, os.ErrNotExist) {
				t.Fatal("failed request created a destination")
			}
			data, err := os.ReadFile(input)
			if err != nil || !bytes.Equal(data, backup) {
				t.Fatal("failed request export changed the backup")
			}
			if _, err := os.Lstat(filepath.Join(dir, "missing")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("failed publication created a missing path or symlink target")
			}
			if err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if strings.HasPrefix(entry.Name(), ".anonce-request-") {
					t.Error("failed publication left a temporary request")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestClientCSRFileCancellation(t *testing.T) {
	password := []byte("synthetic")
	defer clear(password)
	backup, err := generate(t.Context(), "member", password)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name      string
		at        int
		published bool
	}{
		{"entry", 1, false},
		{"request creation", 6, false},
		{"file entry", 8, false},
		{"before publication", 9, false},
		{"after publication", 10, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := privateDirectory(t)
			path := filepath.Join(dir, "request")
			ctx := &cancelAtCheck{Context: t.Context(), at: tc.at}
			if err := writeCSRFile(ctx, password, backup, path); !errors.Is(err, context.Canceled) {
				t.Fatal("file export lost cancellation")
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			if !tc.published {
				if len(entries) != 0 {
					t.Fatal("cancelled export left a file before publication")
				}
				return
			}
			data, err := os.ReadFile(path)
			if err != nil || len(entries) != 1 {
				t.Fatal("post-publication cancellation lost the request or left a temporary file")
			}
			if _, err := membercsr.Parse(data); err != nil {
				t.Fatal("post-publication cancellation left an invalid request")
			}
		})
	}
}

func TestClientCSRFileConcurrentPublication(t *testing.T) {
	password := []byte("synthetic")
	defer clear(password)
	backup, err := generate(t.Context(), "member", password)
	if err != nil {
		t.Fatal(err)
	}
	dir := privateDirectory(t)
	path := filepath.Join(dir, "request")
	var successes atomic.Int32
	var group sync.WaitGroup
	for range 4 {
		group.Go(func() {
			if err := writeCSRFile(t.Context(), password, backup, path); err == nil {
				successes.Add(1)
			}
		})
	}
	group.Wait()
	if successes.Load() != 1 {
		t.Fatal("request publication did not have exactly one winner")
	}
	var stdout bytes.Buffer
	if err := verifyCSR(t.Context(), path, &stdout); err != nil {
		t.Fatal(err)
	}
	public, err := inspect(t.Context(), "member", password, backup)
	if err != nil || stdout.String() != fmt.Sprintf("member:%x\n", public) {
		t.Fatal("concurrent export did not preserve the membership public key")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatal("concurrent exports left temporary files")
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

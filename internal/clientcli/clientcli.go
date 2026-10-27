// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

// Package clientcli connects local device-key packages to a bounded, offline CLI.
// It provides neither enrollment nor reviewer round binding.
package clientcli

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"

	"github.com/mandipnotroot/anonce/internal/client/keystore"
	"github.com/mandipnotroot/anonce/internal/client/memberkey"
	"github.com/mandipnotroot/anonce/internal/client/reviewerkey"
)

const usage = `Development-only local keys; independent review is required before real use.
Usage:
  client generate -kind member|reviewer -out PATH
  client inspect -kind member|reviewer -in PATH [-out PATH] [EXPECTED-KEY]
  client rewrap -kind member|reviewer -in PATH -out PATH [EXPECTED-KEY]
  client csr -kind member -in PATH [-out PATH] [EXPECTED-KEY]
  client verify-csr -kind member -in PATH [-out PATH] [EXPECTED-KEY]
  client -help

EXPECTED-KEY: -expect-public-key HEX or -expect-public-key-file PATH, never both.
Backup passwords come only from a pipe or regular file on stdin, never a terminal.
Generate requires two matching LF-terminated password lines and EOF.
Inspect requires one LF-terminated password line and EOF.
CSR requires one LF-terminated password line and EOF.
Rewrap requires current, replacement, and matching replacement password lines and EOF.
Each password is 1-1024 bytes, excluding LF; no trimming is performed.
Use a trusted password manager, not literal passwords in shell commands.
Backup parents must already exist with owner-only permissions.
Generate publishes an encrypted backup without overwriting any existing path.
Rewrap preserves the key in a new backup; it neither replaces nor revokes old copies.
Inspect validates the backup and prints only its public key, not authorization.
Inspect and verify-csr -out publish the public-key line in a new owner-only file,
without stdout or overwriting an existing path. Public keys are linkable, not encrypted.
CSR prints a signed identity-free DER request, not a certificate or enrollment.
CSR -out publishes the public request in a new owner-only file without stdout.
Request publication never overwrites a path; requests are public, not encrypted.
Verify-csr checks a request and prints only its public key; it never reads stdin.
Inspect, rewrap, csr, and verify-csr accept -expect-public-key with an independently trusted
64-character hex public key for the selected kind.
Alternatively, -expect-public-key-file reads an independently trusted owner-only export
before password or backup/request access. It requires the exact lowercase kind:hex line
with LF, as emitted by inspect/verify-csr; malformed or wrong-kind records fail closed.
Empty, malformed, or repeated expected-key flags fail; mismatches print nothing.
Rewrap checks the key before re-encryption or output-file creation.
CSR checks the key before request signing or output-file creation.
Public keys in arguments remain linkable and may appear in process listings/history.
Expected-key file paths are also visible; file permissions do not establish trust.
Request inputs require owner-only files and parents, just like backup inputs.
Request verification establishes neither certificate trust nor enrollment authority.
No enrollment, round binding, expiry enforcement, or network operations exist.
`

const maxArgumentBytes = 8192

var errArguments = errors.New("configure client: invalid arguments; use -help")

type config struct {
	operation         string
	kind              string
	input             string
	output            string
	expectedPublicKey []byte
	expectedKeyFile   string
}

// Main returns the process exit code after signal-aware execution.
func Main() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdin, os.Stdout); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

func parse(args []string) (config, error) {
	remaining := maxArgumentBytes
	for _, arg := range args {
		if len(arg)+1 > remaining {
			return config{}, errArguments
		}
		remaining -= len(arg) + 1
	}
	if len(args) == 1 && (args[0] == "-help" || args[0] == "-h") {
		return config{}, flag.ErrHelp
	}
	if len(args) == 0 || !slices.Contains([]string{"generate", "inspect", "rewrap", "csr", "verify-csr"}, args[0]) {
		return config{}, errArguments
	}
	cfg := config{operation: args[0]}
	flags := flag.NewFlagSet("client", flag.ContinueOnError)
	// The flag package's errors can reflect arbitrary argument contents.
	flags.SetOutput(io.Discard)
	flags.StringVar(&cfg.kind, "kind", "", "key kind")
	if cfg.operation == "generate" || cfg.operation == "rewrap" {
		flags.StringVar(&cfg.output, "out", "", "new encrypted backup output")
	}
	if cfg.operation == "csr" {
		flags.StringVar(&cfg.output, "out", "", "new public request output instead of stdout")
	}
	if cfg.operation == "inspect" || cfg.operation == "verify-csr" {
		flags.StringVar(&cfg.output, "out", "", "new public key output instead of stdout")
	}
	if cfg.operation != "generate" {
		flags.StringVar(&cfg.input, "in", "", "input file")
	}
	if cfg.operation != "generate" {
		// Both supported key kinds have exactly 32 public bytes.
		flags.Func("expect-public-key", "expected public key in hexadecimal", func(value string) error {
			if cfg.expectedPublicKey != nil || cfg.expectedKeyFile != "" || len(value) != 2*ed25519.PublicKeySize {
				return errArguments
			}
			public, err := hex.DecodeString(value)
			if err != nil {
				return errArguments
			}
			cfg.expectedPublicKey = public
			return nil
		})
		flags.Func("expect-public-key-file", "independently trusted public key file", func(value string) error {
			if value == "" || strings.ContainsRune(value, 0) || cfg.expectedKeyFile != "" || cfg.expectedPublicKey != nil {
				return errArguments
			}
			cfg.expectedKeyFile = value
			return nil
		})
	}
	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return config{}, flag.ErrHelp
		}
		return config{}, errArguments
	}
	if flags.NArg() != 0 || (cfg.kind != "member" && cfg.kind != "reviewer") ||
		((cfg.operation == "csr" || cfg.operation == "verify-csr") && cfg.kind != "member") ||
		strings.ContainsRune(cfg.input+cfg.output, 0) {
		return config{}, errArguments
	}
	if (cfg.operation == "generate" || cfg.operation == "rewrap") && cfg.output == "" ||
		cfg.operation != "generate" && cfg.input == "" {
		return config{}, errArguments
	}
	if cfg.output == "" {
		var emptyOutput bool
		flags.Visit(func(f *flag.Flag) {
			if f.Name == "out" {
				emptyOutput = true
			}
		})
		if emptyOutput {
			return config{}, errArguments
		}
	}
	return cfg, nil
}

func run(ctx context.Context, args []string, input *os.File, output io.Writer) error {
	cfg, err := parse(args)
	if errors.Is(err, flag.ErrHelp) {
		if _, writeErr := io.WriteString(output, usage); writeErr != nil {
			return errors.New("client: write help")
		}
		return flag.ErrHelp
	}
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("client: %w", err)
	}
	if cfg.expectedKeyFile != "" {
		cfg.expectedPublicKey, err = readExpectedPublicKey(ctx, cfg.kind, cfg.expectedKeyFile)
		if err != nil {
			return err
		}
	}
	if cfg.operation == "verify-csr" {
		return verifyCSR(ctx, cfg.input, cfg.expectedPublicKey, cfg.output, output)
	}
	if cfg.operation == "rewrap" {
		return runRewrap(ctx, cfg, input)
	}
	password, err := readPassword(ctx, input, cfg.operation == "generate")
	if err != nil {
		return err
	}
	defer clear(password)
	if cfg.operation == "generate" {
		backup, err := generate(ctx, cfg.kind, password)
		if err != nil {
			return fmt.Errorf("generate backup: %w", err)
		}
		defer clear(backup)
		return writeBackup(ctx, cfg.output, backup)
	}
	backup, err := readBackup(ctx, cfg.input)
	if err != nil {
		return err
	}
	defer clear(backup)
	if cfg.operation == "csr" {
		if cfg.output != "" {
			return writeCSRFile(ctx, password, backup, cfg.expectedPublicKey, cfg.output)
		}
		return writeCSR(ctx, password, backup, cfg.expectedPublicKey, output)
	}
	public, err := inspect(ctx, cfg.kind, password, backup)
	if err != nil {
		return fmt.Errorf("inspect backup: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("inspect backup: %w", err)
	}
	// Compare only after typed authentication and payload validation. Both values
	// are public; matching cannot authorize a malformed or wrong-purpose backup.
	if cfg.expectedPublicKey != nil && !bytes.Equal(public, cfg.expectedPublicKey) {
		return errors.New("inspect backup: public key does not match expected key")
	}
	if err := outputPublicKey(ctx, cfg.kind, public, cfg.output, output); err != nil {
		return fmt.Errorf("inspect backup: %w", err)
	}
	return nil
}

func readPassword(ctx context.Context, input *os.File, confirm bool) ([]byte, error) {
	lines := 1
	if confirm {
		lines = 2
	}
	data, err := readPasswordInput(ctx, input, lines)
	if err != nil {
		return nil, err
	}
	defer clear(data)
	return parsePassword(data, confirm)
}

// readPasswordInput returns caller-owned bounded input, which must be cleared.
// Closing the supplied input on cancellation unblocks pipe reads; callers must
// not reuse it. Only fixed, operation-specific line counts are used.
func readPasswordInput(ctx context.Context, input *os.File, lines int) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("read password: %w", err)
	}
	info, err := input.Stat()
	if err != nil || (!info.Mode().IsRegular() && info.Mode()&os.ModeNamedPipe == 0) {
		return nil, errors.New("read password: stdin must be a pipe or regular file")
	}
	if info.Mode()&os.ModeNamedPipe != 0 {
		reader, err := passwordPipe(input)
		if err != nil {
			return nil, err
		}
		defer func() { _ = reader.Close() }()
		input = reader
	}
	stop := context.AfterFunc(ctx, func() { _ = input.Close() })
	defer stop()
	limit := lines * (keystore.MaxPasswordSize + 1)
	// Allocate the entire destination up front so failed reads can be cleared.
	data := make([]byte, limit+1)
	n, err := io.ReadFull(input, data)
	if ctx.Err() != nil {
		clear(data)
		return nil, fmt.Errorf("read password: %w", ctx.Err())
	}
	if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		clear(data)
		return nil, errors.New("read password: invalid or oversized input")
	}
	return data[:n], nil
}

func parsePassword(data []byte, confirm bool) ([]byte, error) {
	invalid := errors.New("read password: expected bounded LF-terminated password lines and EOF")
	password, rest, ok := bytes.Cut(data, []byte{'\n'})
	if !ok || len(password) == 0 || len(password) > keystore.MaxPasswordSize {
		return nil, invalid
	}
	if confirm {
		confirmation, trailing, ok := bytes.Cut(rest, []byte{'\n'})
		if !ok || len(trailing) != 0 || subtle.ConstantTimeCompare(password, confirmation) != 1 {
			return nil, invalid
		}
	} else if len(rest) != 0 {
		return nil, invalid
	}
	return bytes.Clone(password), nil
}

func generate(ctx context.Context, kind string, password []byte) ([]byte, error) {
	if kind != "member" && kind != "reviewer" {
		return nil, errArguments
	}
	if kind == "member" {
		key, err := memberkey.Generate(ctx)
		if err != nil {
			return nil, err
		}
		defer clear(key)
		return memberkey.Seal(ctx, password, key)
	}
	key, err := reviewerkey.Generate(ctx)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	return reviewerkey.Seal(ctx, password, key)
}

func inspect(ctx context.Context, kind string, password, backup []byte) ([]byte, error) {
	if kind != "member" && kind != "reviewer" {
		return nil, errArguments
	}
	if kind == "member" {
		key, err := memberkey.Open(ctx, password, backup)
		if err != nil {
			return nil, err
		}
		defer clear(key)
		return bytes.Clone(key[ed25519.SeedSize:]), nil
	}
	key, err := reviewerkey.Open(ctx, password, backup)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	private, err := ecdh.X25519().NewPrivateKey(key)
	if err != nil {
		return nil, errors.New("invalid reviewer key")
	}
	return private.PublicKey().Bytes(), nil
}

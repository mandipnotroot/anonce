// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

package browserapp

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"flag"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/mandipnotroot/anonce/internal/browserhttp"
	"github.com/mandipnotroot/anonce/internal/service"
	web "github.com/mandipnotroot/anonce/web/browser"
)

func ReadFile(name string, max int, private bool) ([]byte, error) {
	root, err := os.OpenRoot(filepath.Dir(name))
	if err != nil {
		return nil, errors.New("open browser state directory")
	}
	defer func() { _ = root.Close() }()
	base := filepath.Base(name)
	info, err := root.Lstat(base)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > int64(max) || private && info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("invalid browser state file")
	}
	f, err := root.OpenFile(base, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errors.New("open browser state file")
	}
	defer func() { _ = f.Close() }()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) || !opened.Mode().IsRegular() || private && opened.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("browser state file changed")
	}
	b, err := io.ReadAll(io.LimitReader(f, int64(max+1)))
	if err != nil || len(b) > max {
		return nil, errors.New("read browser state file")
	}
	return b, nil
}

func Seed(directory, name string) (ed25519.PrivateKey, error) {
	b, err := ReadFile(filepath.Join(directory, name+".seed"), 32, true)
	if err != nil || len(b) != 32 {
		return nil, errors.New("invalid signing seed")
	}
	defer clear(b)
	return ed25519.NewKeyFromSeed(b), nil
}

type LocalConfig struct {
	Directory, Origin, Peer string
	Assets                  http.Handler
}
type Factory func(context.Context, *pgxpool.Pool, LocalConfig) (http.Handler, error)

// Command starts exactly one database boundary. No process opens both pools.
func Command(side string, args []string, factory Factory) error {
	flags := flag.NewFlagSet("browser-"+side, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	port, dbport, own, other := "8443", "55431", "https://identity.localhost:8443", "https://submit.localhost:8444"
	if side == "submission" {
		port, dbport, own, other = "8444", "55432", other, own
	}
	listen := flags.String("listen", "127.0.0.1:"+port, "loopback TLS listener")
	origin := flags.String("origin", own, "exact HTTPS origin")
	peer := flags.String("peer-origin", other, "exact other HTTPS origin")
	directory := flags.String("state", ".browser/"+side, "this service's state directory")
	database := flags.String("database", "postgres://anonce_runtime@127.0.0.1:"+dbport+"/"+side+"?sslmode=disable&connect_timeout=5", "local runtime database, without password")
	passwordFile := flags.String("password-file", ".secrets/"+side+"_runtime", "runtime password file")
	source := flags.String("source-url", "", "exact HTTPS corresponding-source location")
	runtime := flags.String("runtime", "bin", "generated WASM parent directory")
	if flags.Parse(args) != nil || flags.NArg() != 0 {
		return errors.New("invalid browser command flags")
	}
	role := service.Issuer
	if side == "submission" {
		role = service.Submission
	}
	cfg := service.Config{Role: role, Listen: *listen, SourceURL: *source}
	if err := cfg.Validate(); err != nil {
		return err
	}
	if !browserhttp.IsOrigin(*origin) || !browserhttp.IsOrigin(*peer) {
		return errors.New("invalid browser origins")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	poolConfig, err := pgxpool.ParseConfig(*database)
	if err != nil || poolConfig.ConnConfig.Database != side || poolConfig.ConnConfig.User != "anonce_runtime" || poolConfig.ConnConfig.Password != "" || poolConfig.ConnConfig.Host != "127.0.0.1" {
		return errors.New("invalid local runtime database")
	}
	password, err := ReadFile(*passwordFile, 64, false)
	if err != nil || len(password) != 64 {
		return errors.New("runtime password unavailable")
	}
	defer clear(password)
	poolConfig.ConnConfig.Password = string(password)
	poolConfig.ConnConfig.RuntimeParams = map[string]string{"search_path": "pg_catalog,anonce", "statement_timeout": "5000", "idle_in_transaction_session_timeout": "30000"}
	poolConfig.MaxConns = 8
	poolConfig.MinConns = 0
	poolConfig.ConnConfig.ConnectTimeout = 5 * time.Second
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return errors.New("runtime pool unavailable")
	}
	defer pool.Close()
	assets, err := web.New(side == "identity", *peer, *source, os.DirFS(filepath.Join(*runtime, "memberwasm")), os.DirFS(filepath.Join(*runtime, "reviewwasm")))
	if err != nil {
		return errors.New("browser assets unavailable")
	}
	if factory == nil {
		return errors.New("browser handler unavailable")
	}
	handler, err := factory(ctx, pool, LocalConfig{*directory, *origin, *peer, assets})
	if err != nil {
		return errors.New("browser initialization failed")
	}
	certificate, err := tls.LoadX509KeyPair(filepath.Join(*directory, "tls.crt"), filepath.Join(*directory, "tls.key"))
	if err != nil {
		return errors.New("TLS certificate unavailable")
	}
	return service.RunTLS(ctx, cfg, handler, certificate)
}

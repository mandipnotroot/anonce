//go:build browsermvp

// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

package browserjourney

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/mandipnotroot/anonce/internal/browserapp"
	"github.com/mandipnotroot/anonce/internal/browserhttp"
	"github.com/mandipnotroot/anonce/internal/browseridentity"
	"github.com/mandipnotroot/anonce/internal/browsersubmission"
	"github.com/mandipnotroot/anonce/internal/client/membersession"
	"github.com/mandipnotroot/anonce/internal/identity/accounts"
	identity "github.com/mandipnotroot/anonce/internal/identity/browser"
	"github.com/mandipnotroot/anonce/internal/identity/memberbackup"
	"github.com/mandipnotroot/anonce/internal/reviewprofile"
	"github.com/mandipnotroot/anonce/internal/service"
	submission "github.com/mandipnotroot/anonce/internal/submission/browser"
	"github.com/mandipnotroot/anonce/migrations"
	"github.com/pressly/goose/v3"
)

// This target requires an OS-isolated, disposable environment. It initializes two
// real PostgreSQL clusters, not mocks or existing databases. Trust authentication
// applies only to synthetic loopback fixtures, never the documented local startup.
func postgres(t *testing.T, side string, port int) *pgxpool.Pool {
	t.Helper()
	bin := os.Getenv("BROWSER_TEST_PG")
	if bin == "" {
		t.Fatal("BROWSER_TEST_PG must name PostgreSQL 18.6 bin directory in an isolated test environment")
	}
	dir := t.TempDir()
	data := filepath.Join(dir, "data")
	ctx := context.Background()
	init := exec.CommandContext(ctx, filepath.Join(bin, "initdb"), "-D", data, "--username=browser_fixture", "--no-locale", "--encoding=UTF8", "--auth=trust", "--no-instructions")
	init.Stdout = io.Discard
	init.Stderr = io.Discard
	if init.Run() != nil {
		t.Fatal("initialize disposable PostgreSQL cluster")
	}
	command := exec.CommandContext(ctx, filepath.Join(bin, "postgres"), "-D", data, "-p", fmt.Sprint(port), "-h", "127.0.0.1", "-k", dir, "-c", "shared_buffers=16MB", "-c", "max_connections=30", "-c", "log_min_messages=panic", "-c", "log_min_error_statement=panic", "-c", "log_statement=none")
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if command.Start() != nil {
		t.Fatal("start disposable PostgreSQL")
	}
	t.Cleanup(func() {
		_ = command.Process.Signal(os.Interrupt)
		done := make(chan struct{})
		go func() { _ = command.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = command.Process.Kill()
			<-done
		}
	})
	adminDSN := fmt.Sprintf("postgres://browser_fixture@127.0.0.1:%d/postgres?sslmode=disable", port)
	var admin *pgx.Conn
	var err error
	for range 100 {
		admin, err = pgx.Connect(ctx, adminDSN)
		if err == nil {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if err != nil {
		t.Fatal("connect disposable PostgreSQL")
	}
	defer func() { _ = admin.Close(ctx) }()
	_, err = admin.Exec(ctx, `CREATE ROLE anonce_owner NOLOGIN; CREATE ROLE anonce_migrator LOGIN NOINHERIT; CREATE ROLE anonce_runtime LOGIN NOINHERIT; GRANT anonce_owner TO anonce_migrator WITH INHERIT FALSE`)
	if err != nil {
		t.Fatal("prepare test roles")
	}
	if _, err = admin.Exec(ctx, `CREATE DATABASE `+side+` OWNER anonce_owner`); err != nil {
		t.Fatal("prepare test database")
	}
	ownerCfg, err := pgx.ParseConfig(fmt.Sprintf("postgres://anonce_migrator@127.0.0.1:%d/%s?sslmode=disable", port, side))
	if err != nil {
		t.Fatal("configure test migration")
	}
	connection, err := pgx.ConnectConfig(ctx, ownerCfg)
	if err != nil {
		t.Fatal("connect test migrator")
	}
	_, err = connection.Exec(ctx, `SET ROLE anonce_owner; REVOKE ALL ON DATABASE `+side+` FROM PUBLIC; GRANT CONNECT ON DATABASE `+side+` TO anonce_runtime,anonce_migrator; REVOKE ALL ON SCHEMA public FROM PUBLIC; CREATE SCHEMA anonce AUTHORIZATION anonce_owner; GRANT USAGE ON SCHEMA anonce TO anonce_runtime; ALTER DEFAULT PRIVILEGES FOR ROLE anonce_owner REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC`)
	_ = connection.Close(ctx)
	if err != nil {
		t.Fatal("prepare owned test schema")
	}
	db := stdlib.OpenDB(*ownerCfg, stdlib.OptionAfterConnect(func(ctx context.Context, c *pgx.Conn) error {
		_, err := c.Exec(ctx, "SET ROLE anonce_owner")
		return err
	}))
	defer func() { _ = db.Close() }()
	files, err := migrations.Files(side)
	if err != nil {
		t.Fatal(err)
	}
	provider, err := goose.NewProvider(goose.DialectPostgres, db, files, goose.WithTableName("anonce."+side+"_schema_version"), goose.WithDisableGlobalRegistry(true))
	if err != nil {
		t.Fatal("configure migration provider")
	}
	if _, err = provider.Up(ctx); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	pool, err := pgxpool.New(ctx, fmt.Sprintf("postgres://anonce_runtime@127.0.0.1:%d/%s?sslmode=disable", port, side))
	if err != nil {
		t.Fatal("connect test runtime")
	}
	t.Cleanup(pool.Close)
	return pool
}

func TestBrowserMVP(t *testing.T) {
	identityPool := postgres(t, "identity", 15431)
	submissionPool := postgres(t, "submission", 15432)
	ctx := context.Background()
	state := filepath.Join(t.TempDir(), "state")
	if browserapp.Initialize(state) != nil {
		t.Fatal("initialize local test state")
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	var pins []string
	rootPEM, err := os.ReadFile(filepath.Join(state, "local-root.crt"))
	if err != nil {
		t.Fatal("read test trust root")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootPEM) {
		t.Fatal("parse test trust root")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: time.Second}
	for _, side := range []string{"identity", "submission"} {
		dir := filepath.Join(state, side)
		certificate, err := tls.LoadX509KeyPair(filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key"))
		if err != nil {
			t.Fatal("load test TLS")
		}
		leaf, err := x509.ParseCertificate(certificate.Certificate[0])
		if err != nil {
			t.Fatal("parse test TLS")
		}
		digest := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
		pins = append(pins, base64.StdEncoding.EncodeToString(digest[:]))
		origin, peer, port := "https://identity.localhost:8443", "https://submit.localhost:8444", "8443"
		pool := identityPool
		factory := browseridentity.FromState
		if side == "submission" {
			origin, peer, port = peer, origin, "8444"
			pool = submissionPool
			factory = browsersubmission.FromState
		}
		assets, err := newAssets(side == "identity", peer, root)
		if err != nil {
			t.Fatal("load test assets")
		}
		handler, err := factory(ctx, pool, browserapp.LocalConfig{Directory: dir, Origin: origin, Peer: peer, Assets: assets})
		if err != nil {
			t.Fatal("construct test browser service")
		}
		role := service.Issuer
		if side == "submission" {
			role = service.Submission
		}
		serverCtx, stop := context.WithCancel(ctx)
		result := make(chan error, 1)
		go func() {
			result <- service.RunTLS(serverCtx, service.Config{Role: role, Listen: "127.0.0.1:" + port, SourceURL: "https://example.invalid/synthetic-source"}, handler, certificate)
		}()
		t.Cleanup(func() {
			stop()
			select {
			case err := <-result:
				if err != nil {
					t.Error("browser service shutdown failed")
				}
			case <-time.After(10 * time.Second):
				t.Error("browser service shutdown timed out")
			}
		})
		ready := false
		for range 100 {
			response, err := client.Get(origin + "/api/browser/config")
			if err == nil {
				_, _ = io.Copy(io.Discard, response.Body)
				_ = response.Body.Close()
				if response.StatusCode == 200 {
					ready = true
					break
				}
			}
			time.Sleep(25 * time.Millisecond)
		}
		if !ready {
			t.Fatal("browser TLS host did not start with verified trust and request metadata")
		}
	}
	invitation, err := os.ReadFile(filepath.Join(state, "identity/administrator-invitation"))
	if err != nil {
		t.Fatal("load synthetic administrator invitation")
	}
	fixture, err := json.Marshal(map[string]string{"bootstrap": string(invitation), "pins": strings.Join(pins, ",")})
	clear(invitation)
	if err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(ctx, "node", filepath.Join(root, "scripts/browser_journey_test.mjs"))
	command.Stdin = bytes.NewReader(fixture)
	var out bytes.Buffer
	command.Stdout = &out
	command.Stderr = &out
	if err := command.Run(); err != nil {
		var active, administrators, sessions int
		_ = identityPool.QueryRow(ctx, `SELECT count(*),count(*) FILTER(WHERE administrator) FROM anonce.browser_credentials`).Scan(&active, &administrators)
		_ = identityPool.QueryRow(ctx, `SELECT count(*) FROM anonce.account_sessions WHERE expires_at>statement_timestamp()`).Scan(&sessions)
		t.Logf("persisted browser accounts=%d administrators=%d live sessions=%d", active, administrators, sessions)
		t.Fatalf("browser journey failed: %s", out.String())
	}
	clear(fixture)
	t.Log(out.String())
	t.Run("runtime-isolation-and-grants", func(t *testing.T) {
		for _, pool := range []*pgxpool.Pool{identityPool, submissionPool} {
			var ok bool
			if pool.QueryRow(ctx, `SELECT NOT has_schema_privilege(current_user,'anonce','CREATE') AND NOT pg_has_role(current_user,'anonce_owner','MEMBER')`).Scan(&ok) != nil || !ok {
				t.Fatal("runtime ownership isolation")
			}
		}
		if _, err := accounts.New(ctx, submissionPool); err == nil {
			t.Fatal("identity store admitted submission DB")
		}
		if _, err := submission.New(ctx, identityPool, make([]byte, 32)); err == nil {
			t.Fatal("submission store admitted identity DB")
		}
		if _, err := submissionPool.Exec(ctx, `UPDATE anonce.submission_records SET ciphertext=ciphertext`); err == nil {
			t.Fatal("runtime can mutate immutable ciphertext")
		}
	})
	t.Run("enrollment-and-quota-races", func(t *testing.T) {
		store, err := identity.New(ctx, identityPool)
		if err != nil {
			t.Fatal(err)
		}
		accountStore, err := accounts.New(ctx, identityPool)
		if err != nil {
			t.Fatal(err)
		}
		admin, err := store.User(ctx, "administrator")
		if err != nil {
			t.Fatal("browser administrator did not persist")
		}
		adminToken, _, err := accountStore.StartSession(ctx, admin.ID, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(adminToken)
		member, err := store.User(ctx, "member_one")
		if err != nil {
			t.Fatal("browser member did not persist")
		}
		token, _, err := accountStore.StartSession(ctx, member.ID, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(token)
		var round, raw []byte
		if identityPool.QueryRow(ctx, `SELECT id,bulletin FROM anonce.browser_rounds WHERE bulletin IS NOT NULL LIMIT 1`).Scan(&round, &raw) != nil {
			t.Fatal("published round missing")
		}
		publication, err := os.ReadFile(filepath.Join(state, "submission/bulletin.pub"))
		if err != nil {
			t.Fatal(err)
		}
		b, err := reviewprofile.ParseBulletin(raw, publication)
		if err != nil {
			t.Fatal(err)
		}
		blinded, _, err := reviewprofile.Prepare(b, raw)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.Challenge(ctx, token, round, blinded); err == nil {
			t.Fatal("browser issuance quota reset by a new session")
		}
		// An eligible invitation is raced by two independently authenticated accounts.
		code, err := store.Invite(ctx, adminToken)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(code)
		caDER, _ := os.ReadFile(filepath.Join(state, "identity/membership.der"))
		ca, err := x509.ParseCertificate(caDER)
		if err != nil {
			t.Fatal(err)
		}
		caKey, err := browserapp.Seed(filepath.Join(state, "identity"), "membership")
		if err != nil {
			t.Fatal(err)
		}
		defer clear(caKey)
		backupStore, err := memberbackup.New(ctx, identityPool)
		if err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		var wins atomic.Int32
		var winnerMu sync.Mutex
		var winnerSession *membersession.Session
		var winnerToken []byte
		start := make(chan struct{})
		for range 2 {
			id, err := accountStore.Create(ctx)
			if err != nil {
				t.Fatal(err)
			}
			// This storage race intentionally uses trusted sessions, separately from
			// the real browser authentication checks above. No fake HTTP login exists.
			session, _, err := accountStore.StartSession(ctx, id, time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			// The workflow store requires a credential row for session admission.
			credential := admin.Credential
			credential.ID = browserhttp.Random()
			name := "race_" + browserhttp.Encode(id[:])[:10]
			name = strings.ToLower(strings.ReplaceAll(name, "-", "_"))
			data, _ := json.Marshal(credential)
			if _, err := identityPool.Exec(ctx, `INSERT INTO anonce.browser_credentials(account_id,username,credential_id,credential) VALUES($1,$2,$3,$4)`, id[:], name, credential.ID, data); err != nil {
				t.Fatal("prepare bounded credential metadata")
			}
			local := new(membersession.Session)
			defer local.Lock()
			setup, err := local.CreateConfirmed(ctx, []byte("synthetic race unlock"), []byte("synthetic race unlock"))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := backupStore.PutForSession(ctx, session, 0, setup.PublicKey, setup.Backup); err != nil {
				t.Fatal(err)
			}
			wg.Go(func() {
				defer clear(session)
				<-start
				if _, err := store.Enroll(ctx, session, code, setup.CSR, ca, caKey); err == nil {
					wins.Add(1)
					winnerMu.Lock()
					winnerSession = local
					winnerToken = bytes.Clone(session)
					winnerMu.Unlock()
				}
			})
		}
		close(start)
		wg.Wait()
		if wins.Load() != 1 {
			t.Fatalf("single-use enrollment winners=%d", wins.Load())
		}
		defer clear(winnerToken)
		quotaRace(t, identityPool, submissionPool, state, store, accountStore, adminToken, winnerToken, winnerSession, ca)
	})
	// A freshly constructed store/pool observes browser-persisted ciphertext.
	t.Run("persistence", func(t *testing.T) {
		fresh, err := pgxpool.NewWithConfig(ctx, submissionPool.Config())
		if err != nil {
			t.Fatal("open independent persistence connection pool")
		}
		defer fresh.Close()
		var count int
		if fresh.QueryRow(ctx, `SELECT count(*) FROM anonce.submission_records`).Scan(&count) != nil || count != 2 {
			t.Fatal("one browser response and one quota-race response must persist")
		}
	})
}

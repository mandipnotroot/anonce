//go:build browsermvp

// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

package browserjourney

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/mandipnotroot/anonce/internal/browserhttp"
	"github.com/mandipnotroot/anonce/internal/identity/accounts"
	identity "github.com/mandipnotroot/anonce/internal/identity/browser"
)

func testSessionHTTP(t *testing.T, pool *pgxpool.Pool, client *http.Client) {
	t.Helper()
	ctx := context.Background()
	store, err := accounts.New(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := store.Create(ctx)
	if err != nil {
		t.Fatal(err)
	}
	other, err := store.Create(ctx)
	if err != nil {
		t.Fatal(err)
	}
	start := func(id accounts.ID) []byte {
		t.Helper()
		token, _, err := store.StartSession(ctx, id, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { clear(token) })
		return token
	}
	current, sibling, foreign := start(owner), start(owner), start(other)
	request := func(method, path, body string, token []byte, csrf bool, status int) []byte {
		t.Helper()
		r, err := http.NewRequestWithContext(ctx, method, "https://identity.localhost:8443/api/browser"+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if token != nil {
			r.AddCookie(&http.Cookie{Name: "__Host-anonce-session", Value: browserhttp.Encode(token)})
		}
		r.Header.Set("Content-Type", "application/json")
		if csrf {
			r.Header.Set("Origin", "https://identity.localhost:8443")
			r.Header.Set("Sec-Fetch-Site", "same-origin")
			r.Header.Set("X-Anonce-CSRF", "1")
		}
		response, err := client.Do(r)
		if err != nil {
			t.Fatal("session HTTP request failed")
		}
		defer func() { _ = response.Body.Close() }()
		out, err := io.ReadAll(io.LimitReader(response.Body, 16384))
		if err != nil || response.StatusCode != status || response.Header.Get("Cache-Control") != "no-store" {
			t.Fatalf("%s %s: status %d, want %d", method, path, response.StatusCode, status)
		}
		if path == "/logout-all" && status == 200 {
			cookies := response.Cookies()
			if len(cookies) != 1 || cookies[0].MaxAge != -1 || !cookies[0].Secure || !cookies[0].HttpOnly {
				t.Fatal("sign-out did not expire protected cookie")
			}
		}
		return out
	}
	list := func(token []byte) []map[string]any {
		t.Helper()
		var result []map[string]any
		if json.Unmarshal(request("GET", "/sessions", "", token, true, 200), &result) != nil {
			t.Fatal("inventory JSON")
		}
		for _, s := range result {
			if len(s) != 4 || s["created_at"] == nil || s["expires_at"] == nil || s["current"] == nil || s["id"] == nil {
				t.Fatal("inventory exposed unexpected metadata")
			}
		}
		return result
	}
	selector := func(token []byte) string {
		t.Helper()
		for _, s := range list(token) {
			if s["current"] == true {
				return s["id"].(string)
			}
		}
		t.Fatal("current session missing")
		return ""
	}
	if len(list(current)) != 2 {
		t.Fatal("session inventory scope")
	}
	request("GET", "/sessions", "", nil, true, 401)
	request("POST", "/sessions/revoke", `{}`, current, false, 403)
	for _, target := range []string{selector(current), selector(foreign), browserhttp.Encode(make([]byte, 16))} {
		status := 200
		if target == browserhttp.Encode(make([]byte, 16)) {
			status = 400
		}
		out := request("POST", "/sessions/revoke", `{"id":"`+target+`"}`, current, true, status)
		if status == 200 && !strings.Contains(string(out), `"removed":false`) {
			t.Fatal("current or foreign selector changed a session")
		}
	}
	target := selector(sibling)
	out := request("POST", "/sessions/revoke", `{"id":"`+target+`"}`, current, true, 200)
	if !strings.Contains(string(out), `"removed":true`) || len(list(current)) != 1 {
		t.Fatal("selected revocation did not commit")
	}
	request("GET", "/sessions", "", sibling, true, 401)
	request("POST", "/sessions/revoke", `{"id":"`+target+`"}`, current, true, 200)
	// Test-only historical admission uses real runtime INSERT grants, not a clock
	// bypass in the service. No concurrent writer uses this synthetic account.
	old := make([]byte, 32)
	rand.Read(old)
	defer clear(old)
	digest := sha256.Sum256(old)
	if _, err := pool.Exec(ctx, `INSERT INTO anonce.account_sessions(token_digest,account_id,created_at,expires_at) VALUES($1,$2,statement_timestamp()-interval '6 minutes',statement_timestamp()+interval '40 minutes')`, digest[:], owner[:]); err != nil {
		t.Fatal("historical session fixture")
	}
	request("GET", "/sessions", "", old, true, 200)
	request("POST", "/sessions/revoke", `{"id":"`+selector(current)+`"}`, old, true, 403)
	request("POST", "/logout-all", `{}`, old, true, 403)
	if len(list(current)) != 2 {
		t.Fatal("stale authentication changed sessions")
	}
	request("POST", "/logout-all", `{}`, current, true, 200)
	request("GET", "/sessions", "", current, true, 401)
	request("GET", "/sessions", "", old, true, 401)
	if len(list(foreign)) != 1 {
		t.Fatal("sign-out everywhere crossed account boundary")
	}
	if len(list(start(owner))) != 1 {
		t.Fatal("later independently admitted session unavailable")
	}
	t.Run("reauthentication-binding-and-consumption", func(t *testing.T) { testReauthenticationHTTP(t, pool, client) })
}

func testReauthenticationHTTP(t *testing.T, pool *pgxpool.Pool, client *http.Client) {
	t.Helper()
	ctx := context.Background()
	store, err := accounts.New(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	users, err := identity.New(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	// Keep these native negative tests independent of the browser driver's account
	// rate budget. Assertions still use the production parser and verifier path.
	var user identity.User
	rand.Read(user.ID[:])
	user.Name = "session_negative"
	user.Credential.ID = []byte("synthetic-credential-selector")
	if users.Register(ctx, user) != nil {
		t.Fatal("register synthetic negative-test account")
	}
	start := func() []byte {
		t.Helper()
		token, _, err := store.StartSession(ctx, user.ID, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { clear(token) })
		return token
	}
	first, second := start(), start()
	call := func(path, body string, token []byte, ceremony *http.Cookie, want int) []*http.Cookie {
		t.Helper()
		r, err := http.NewRequestWithContext(ctx, "POST", "https://identity.localhost:8443/api/browser/auth/"+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", "https://identity.localhost:8443")
		r.Header.Set("Sec-Fetch-Site", "same-origin")
		r.Header.Set("X-Anonce-CSRF", "1")
		if token != nil {
			r.AddCookie(&http.Cookie{Name: "__Host-anonce-session", Value: browserhttp.Encode(token)})
		}
		if ceremony != nil {
			r.AddCookie(ceremony)
		}
		response, err := client.Do(r)
		if err != nil {
			t.Fatal("reauthentication HTTP failed")
		}
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
		if response.StatusCode != want {
			t.Fatalf("%s: status %d, want %d", path, response.StatusCode, want)
		}
		return response.Cookies()
	}
	begin := func(token []byte) *http.Cookie {
		t.Helper()
		cookies := call("reauthenticate/begin", `{}`, token, nil, 200)
		if len(cookies) != 1 || cookies[0].Name != "__Host-anonce-ceremony" || cookies[0].MaxAge != 120 {
			t.Fatal("reauthentication ceremony cookie")
		}
		return cookies[0]
	}
	for _, body := range []string{`null`, `{"name":"session_negative"}`, `{"name":""}`, `{"bootstrap":""}`, `{"recent":true}`} {
		call("reauthenticate/begin", body, first, nil, 400)
	}
	call("reauthenticate/begin", `{}`, nil, nil, 401)
	// Even another live bearer belonging to the same account cannot finish this
	// ceremony. The failed attempt consumes it before any assertion parsing.
	ceremony := begin(first)
	call("reauthenticate/finish", `{}`, second, ceremony, 401)
	call("reauthenticate/finish", `{}`, first, ceremony, 403)
	ceremony = begin(first)
	call("login/finish", `{}`, first, ceremony, 403)
	call("reauthenticate/finish", `{}`, first, ceremony, 403)
	ceremony = begin(first)
	call("reauthenticate/finish", `{}`, first, ceremony, 403)
	call("reauthenticate/finish", `{}`, first, ceremony, 403)
	doomed := start()
	ceremony = begin(doomed)
	if store.Revoke(ctx, doomed) != nil {
		t.Fatal("revoke during ceremony")
	}
	call("reauthenticate/finish", `{}`, doomed, ceremony, 401)
	list, err := store.ListSessions(ctx, second)
	if err != nil || len(list) != 2 {
		t.Fatal("failed reauthentication created, rotated or removed a session")
	}
}

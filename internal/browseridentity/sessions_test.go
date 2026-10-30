// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

package browseridentity

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mandipnotroot/anonce/internal/browserhttp"
	"github.com/mandipnotroot/anonce/internal/identity/accounts"
)

func TestSessionHTTPAdmission(t *testing.T) {
	t.Parallel()
	h := &handler{accounts: new(accounts.Store)}
	for _, tc := range []struct {
		name, path, method, body string
		status                   int
	}{
		{"list-write", "/sessions", "POST", `{}`, 405},
		{"revoke-read", "/sessions/revoke", "GET", ``, 405},
		{"all-read", "/logout-all", "GET", ``, 405},
		{"missing", "/sessions/revoke", "POST", `{}`, 400},
		{"null", "/sessions/revoke", "POST", `null`, 400},
		{"malformed", "/sessions/revoke", "POST", `{"id":"bad"}`, 400},
		{"zero", "/sessions/revoke", "POST", `{"id":"AAAAAAAAAAAAAAAAAAAAAA"}`, 400},
		{"unknown", "/sessions/revoke", "POST", `{"id":"AQEBAQEBAQEBAQEBAQEBAQ","owner":"other"}`, 400},
		{"duplicate", "/sessions/revoke", "POST", `{"id":"AQEBAQEBAQEBAQEBAQEBAQ","id":"AQEBAQEBAQEBAQEBAQEBAQ"}`, 400},
		{"trailing", "/logout-all", "POST", `{} {}`, 400},
		{"null-all", "/logout-all", "POST", `null`, 400},
		{"owner", "/logout-all", "POST", `{"owner":"other"}`, 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, "https://identity.localhost/api/browser"+tc.path, strings.NewReader(tc.body))
			r.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			h.manageSessions(w, r, make([]byte, 32))
			if w.Code != tc.status {
				t.Fatalf("status = %d, want %d", w.Code, tc.status)
			}
		})
	}
}

func TestReauthenticationInputAdmission(t *testing.T) {
	t.Parallel()
	h := new(handler)
	for _, body := range []string{`null`, `{"name":""}`, `{"bootstrap":""}`, `{"recent":true}`, `{} {}`, `[]`} {
		t.Run(body, func(t *testing.T) {
			r := httptest.NewRequest("POST", "https://identity.localhost/api/browser/auth/reauthenticate/begin", strings.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			h.authenticate(w, r)
			if w.Code != 400 {
				t.Fatalf("reauthentication input status = %d, want 400", w.Code)
			}
		})
	}
}

func FuzzSessionSelectorHTTP(f *testing.F) {
	f.Add("AQEBAQEBAQEBAQEBAQEBAQ")
	f.Add("bad")
	f.Fuzz(func(t *testing.T, selector string) {
		if len(selector) > 23 {
			return
		}
		id, ok := browserhttp.Decode(selector, 16)
		if ok && (len(id) != 16 || browserhttp.Encode(id) != selector) {
			t.Fatal("noncanonical selector admitted")
		}
		body, err := json.Marshal(map[string]string{"id": selector})
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest("POST", "https://identity.localhost/api/browser/sessions/revoke", strings.NewReader(string(body)))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h := &handler{accounts: new(accounts.Store)}
		h.manageSessions(w, r, make([]byte, 32))
		want := 400
		if ok && accounts.SessionID(id) != (accounts.SessionID{}) {
			want = 401
		}
		if w.Code != want {
			t.Fatalf("selector admission status = %d, want %d", w.Code, want)
		}
	})
}

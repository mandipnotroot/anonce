// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

package browserhttp

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestJSONAdmission(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
		valid      bool
	}{
		{"valid", `{"code":"synthetic"}`, 200, true},
		{"unknown", `{"other":"synthetic"}`, 400, false},
		{"duplicate", `{"code":"one","code":"two"}`, 400, false},
		{"trailing", `{"code":"one"}{}`, 400, false},
		{"nested", strings.Repeat("[", 20) + strings.Repeat("]", 20), 400, false},
		{"oversized", strings.Repeat(" ", MaxBody+1), 413, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "https://identity.localhost/", strings.NewReader(tc.body))
			r.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			var in struct {
				Code string `json:"code"`
			}
			if got := Read(w, r, &in); got != tc.valid {
				t.Fatal("wrong parser admission")
			}
			if w.Code != tc.status {
				t.Fatalf("status %d, want %d", w.Code, tc.status)
			}
		})
	}
}

func FuzzBrowserJSONAdmission(f *testing.F) {
	f.Add(`{"code":"synthetic"}`)
	f.Add(`{"code":0,"code":1}`)
	f.Fuzz(func(t *testing.T, body string) {
		if len(body) > MaxBody+1 {
			return
		}
		r := httptest.NewRequest("POST", "https://identity.localhost/", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		var in struct {
			Code string `json:"code"`
		}
		_ = Read(httptest.NewRecorder(), r, &in)
	})
}

func TestIdentityGate(t *testing.T) {
	for _, tc := range []struct {
		name, host, origin, site, csrf string
		tls                            bool
		want                           int
	}{{"valid", "identity.localhost:8443", "https://identity.localhost:8443", "same-origin", "1", true, 204}, {"foreign-origin", "identity.localhost:8443", "https://submit.localhost:8444", "same-site", "1", true, 403}, {"no-csrf", "identity.localhost:8443", "https://identity.localhost:8443", "same-origin", "", true, 403}, {"bad-host", "attacker.localhost", "https://identity.localhost:8443", "same-origin", "1", true, 403}, {"no-tls", "identity.localhost:8443", "https://identity.localhost:8443", "same-origin", "1", false, 403}} {
		t.Run(tc.name, func(t *testing.T) {
			handler := NewGate("https://identity.localhost:8443", true).Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
			r := httptest.NewRequest("POST", "https://"+tc.host+"/api/browser/logout", strings.NewReader("{}"))
			r.Host = tc.host
			r.Header.Set("Origin", tc.origin)
			r.Header.Set("Sec-Fetch-Site", tc.site)
			r.Header.Set("X-Anonce-CSRF", tc.csrf)
			if tc.tls {
				r.TLS = &tls.ConnectionState{}
			} else {
				r.TLS = nil
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code != tc.want {
				t.Fatalf("status %d, want %d", w.Code, tc.want)
			}
			if w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("missing no-store")
			}
		})
	}
}

func TestCookieEncoding(t *testing.T) {
	secret := Random()
	defer clear(secret)
	w := httptest.NewRecorder()
	Cookie(w, "session", Encode(secret), 3600)
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].Domain != "" || cookies[0].Path != "/" || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatal("cookie controls")
	}
	r := httptest.NewRequest("GET", "https://identity.localhost/", nil)
	r.AddCookie(cookies[0])
	if len(Token(r, "session")) != 32 {
		t.Fatal("cookie not resolved")
	}
	r.AddCookie(cookies[0])
	if Token(r, "session") != nil {
		t.Fatal("ambiguous cookie accepted")
	}
}

func TestAuthenticationLimiter(t *testing.T) {
	var l Limiter
	for i := 0; i < 10; i++ {
		if !l.Allow("synthetic") {
			t.Fatal("early rate limit")
		}
	}
	if l.Allow("synthetic") {
		t.Fatal("limit bypass")
	}
}

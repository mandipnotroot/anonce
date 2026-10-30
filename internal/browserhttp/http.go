// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

// Package browserhttp supplies bounded transport controls for the browser
// services. It contains no database or device-key custody.
package browserhttp

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const MaxBody = 32768

func Encode(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
func Decode(s string, n int) ([]byte, bool) {
	if len(s) != base64.RawURLEncoding.EncodedLen(n) {
		return nil, false
	}
	b, e := base64.RawURLEncoding.Strict().DecodeString(s)
	return b, e == nil && len(b) == n && Encode(b) == s
}

func JSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func Error(w http.ResponseWriter, status int) {
	JSON(w, status, map[string]string{"code": http.StatusText(status), "message": "The operation could not be completed. Sign in again or check the round and try explicitly."})
}

func Read(w http.ResponseWriter, r *http.Request, v any) bool {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		Error(w, 415)
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, MaxBody)
	defer func() { _ = r.Body.Close() }()
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		var oversized *http.MaxBytesError
		if errors.As(err, &oversized) {
			Error(w, 413)
		} else {
			Error(w, 400)
		}
		return false
	}
	defer clear(raw)
	if !utf8.Valid(raw) || !uniqueJSON(raw) {
		Error(w, 400)
		return false
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil || d.Decode(new(any)) != io.EOF {
		Error(w, 400)
		return false
	}
	return true
}

// uniqueJSON rejects ambiguous object keys and deeply nested inputs before typed
// decoding. The byte budget is enforced before this bounded standard-library walk.
func uniqueJSON(raw []byte) bool {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var walk func(int) bool
	walk = func(depth int) bool {
		if depth > 16 {
			return false
		}
		token, err := d.Token()
		if err != nil {
			return false
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return true
		}
		switch delim {
		case '{':
			seen := make(map[string]bool)
			for d.More() {
				key, err := d.Token()
				name, ok := key.(string)
				if err != nil || !ok || seen[name] {
					return false
				}
				seen[name] = true
				if !walk(depth + 1) {
					return false
				}
			}
			end, err := d.Token()
			return err == nil && end == json.Delim('}')
		case '[':
			for d.More() {
				if !walk(depth + 1) {
					return false
				}
			}
			end, err := d.Token()
			return err == nil && end == json.Delim(']')
		default:
			return false
		}
	}
	if !walk(0) {
		return false
	}
	_, err := d.Token()
	return err == io.EOF
}

func Cookie(w http.ResponseWriter, name, value string, age int) {
	http.SetCookie(w, &http.Cookie{Name: "__Host-anonce-" + name, Value: value, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: age})
}

func Token(r *http.Request, name string) []byte {
	// Duplicate cookie names are ambiguous and rejected, not resolved by order.
	var found []byte
	count := 0
	for _, c := range r.Cookies() {
		if c.Name == "__Host-anonce-"+name {
			count++
			found, _ = Decode(c.Value, 32)
		}
	}
	if count != 1 {
		return nil
	}
	return found
}

// Gate enforces an exact HTTPS host, fetch origin/CSRF checks, deadlines and fixed
// global request admission. No client IP, forwarding header or user agent is read.
type Gate struct {
	Origin   string
	Identity bool
	slots    chan struct{}
	mu       sync.Mutex
	start    time.Time
	count    int
}

func NewGate(origin string, identity bool) *Gate {
	return &Gate{Origin: origin, Identity: identity, slots: make(chan struct{}, 32)}
}

func (g *Gate) Wrap(next http.Handler) http.Handler {
	u, _ := url.Parse(g.Origin)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), publickey-credentials-get=(self), publickey-credentials-create=(self)")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; worker-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
		if u == nil || u.Scheme != "https" || r.Host != u.Host || r.TLS == nil {
			Error(w, 403)
			return
		}
		if r.Method != "GET" && r.Method != "HEAD" && r.Method != "POST" && (g.Identity || r.Method != "OPTIONS") {
			w.Header().Set("Allow", "GET, HEAD, POST")
			Error(w, 405)
			return
		}
		if g.Identity && r.Method == "POST" && (r.Header.Get("Origin") != g.Origin || r.Header.Get("X-Anonce-CSRF") != "1" || r.Header.Get("Sec-Fetch-Site") != "same-origin") {
			Error(w, 403)
			return
		}
		if g.Identity && r.Method != "POST" && r.Header.Get("Origin") != "" && r.Header.Get("Origin") != g.Origin {
			Error(w, 403)
			return
		}
		select {
		case g.slots <- struct{}{}:
			defer func() { <-g.slots }()
		default:
			Error(w, 503)
			return
		}
		if r.Method == "POST" {
			g.mu.Lock()
			now := time.Now()
			if now.Sub(g.start) >= time.Minute {
				g.start = now
				g.count = 0
			}
			g.count++
			allowed := g.count <= 120
			g.mu.Unlock()
			if !allowed {
				w.Header().Set("Retry-After", "60")
				Error(w, 429)
				return
			}
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

type Limiter struct {
	mu      sync.Mutex
	entries map[string]limit
}
type limit struct {
	until time.Time
	count int
}

func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if l.entries == nil {
		l.entries = make(map[string]limit)
	}
	for k, v := range l.entries {
		if !now.Before(v.until) {
			delete(l.entries, k)
		}
	}
	v, ok := l.entries[key]
	if !ok {
		if len(l.entries) >= 1024 {
			return false
		}
		v.until = now.Add(5 * time.Minute)
	}
	v.count++
	l.entries[key] = v
	return v.count <= 10
}

func Random() []byte { b := make([]byte, 32); rand.Read(b); return b }
func IsOrigin(s string) bool {
	u, e := url.Parse(s)
	return e == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.RawQuery == "" && u.Fragment == "" && u.Path == "" && u.Opaque == "" && !strings.Contains(u.Hostname(), ":")
}

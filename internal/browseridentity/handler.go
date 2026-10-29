// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

// Package browseridentity connects verified WebAuthn authentication and the
// identity-only browser/vault workflow. It imports no submission persistence.
package browseridentity

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/mandipnotroot/anonce/internal/browserhttp"
	"github.com/mandipnotroot/anonce/internal/identity/accounts"
	"github.com/mandipnotroot/anonce/internal/identity/browser"
	"github.com/mandipnotroot/anonce/internal/identity/memberbackup"
)

type Config struct {
	Origin, SubmissionOrigin string
	BootstrapDigest          [32]byte
	CA                       *x509.Certificate
	CAKey, BulletinKey       ed25519.PrivateKey
	ReceiptKey               ed25519.PublicKey
	Assets                   http.Handler
}
type handler struct {
	cfg      Config
	auth     *webauthn.WebAuthn
	state    *browser.Store
	accounts *accounts.Store
	backups  *memberbackup.Store
	attempts browserhttp.Limiter
}
type ceremony struct {
	User    browser.User
	Session webauthn.SessionData
	Kind    string
	Bearer  [32]byte
}

func New(ctx context.Context, pool *pgxpool.Pool, cfg Config) (http.Handler, error) {
	if !browserhttp.IsOrigin(cfg.Origin) || !browserhttp.IsOrigin(cfg.SubmissionOrigin) || cfg.Origin == cfg.SubmissionOrigin || cfg.CA == nil || len(cfg.CAKey) != 64 || len(cfg.BulletinKey) != 64 || len(cfg.ReceiptKey) != 32 || cfg.Assets == nil {
		return nil, browser.ErrDenied
	}
	u, _ := url.Parse(cfg.Origin)
	other, _ := url.Parse(cfg.SubmissionOrigin)
	if u.Hostname() == other.Hostname() {
		return nil, browser.ErrDenied
	}
	timeout := webauthn.TimeoutConfig{Enforce: true, Timeout: 2 * time.Minute, TimeoutUVD: 2 * time.Minute}
	auth, err := webauthn.New(&webauthn.Config{RPID: u.Hostname(), RPDisplayName: "Anonce", RPOrigins: []string{cfg.Origin}, AuthenticatorSelection: protocol.AuthenticatorSelection{UserVerification: protocol.VerificationRequired}, AttestationPreference: protocol.PreferNoAttestation, Timeouts: webauthn.TimeoutsConfig{Login: timeout, Registration: timeout}})
	if err != nil {
		return nil, browser.ErrDenied
	}
	state, err := browser.New(ctx, pool)
	if err != nil {
		return nil, err
	}
	accountStore, err := accounts.New(ctx, pool)
	if err != nil {
		return nil, err
	}
	backups, err := memberbackup.New(ctx, pool)
	if err != nil {
		return nil, err
	}
	h := &handler{cfg: cfg, auth: auth, state: state, accounts: accountStore, backups: backups}
	return browserhttp.NewGate(cfg.Origin, true).Wrap(h), nil
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if !strings.HasPrefix(path, "/api/browser/") {
		h.cfg.Assets.ServeHTTP(w, r)
		return
	}
	if path == "/api/browser/config" && r.Method == "GET" {
		browserhttp.JSON(w, 200, map[string]any{"submission_origin": h.cfg.SubmissionOrigin, "bulletin_key": browserhttp.Encode(h.cfg.BulletinKey[32:])})
		return
	}
	if strings.HasPrefix(path, "/api/browser/auth/") {
		h.authenticate(w, r)
		return
	}
	token := browserhttp.Token(r, "session")
	defer clear(token)
	if path == "/api/browser/sessions" || path == "/api/browser/sessions/revoke" || path == "/api/browser/logout-all" {
		h.manageSessions(w, r, token)
		return
	}
	user, err := h.state.Current(r.Context(), token)
	if err != nil {
		browserhttp.Error(w, 401)
		return
	}
	if path == "/api/browser/me" && r.Method == "GET" {
		browserhttp.JSON(w, 200, map[string]any{"name": user.Name, "administrator": user.Admin})
		return
	}
	if path == "/api/browser/rounds" && r.Method == "GET" {
		rounds, err := h.state.Rounds(r.Context(), token)
		if err != nil {
			browserhttp.Error(w, 503)
			return
		}
		out := make([]map[string]any, 0, len(rounds))
		for _, r := range rounds {
			out = append(out, map[string]any{"id": browserhttp.Encode(r.ID), "question": r.Question, "reviewer": r.ReviewerName, "opens": r.Opens, "closes": r.Closes, "review_until": r.ReviewUntil, "response_limit": r.ResponseLimit, "reviewer_key": browserhttp.Encode(r.ReviewerKey), "bulletin": browserhttp.Encode(r.Bulletin), "assigned": r.Assigned})
		}
		browserhttp.JSON(w, 200, out)
		return
	}
	if path == "/api/browser/backup" && r.Method == "GET" {
		record, err := h.backups.GetForSession(r.Context(), token)
		if err != nil {
			browserhttp.Error(w, 404)
			return
		}
		browserhttp.JSON(w, 200, map[string]any{"public_key": browserhttp.Encode(record.PublicKey[:]), "backup": browserhttp.Encode(record.Backup), "revision": record.Revision})
		return
	}
	if r.Method != "POST" {
		browserhttp.Error(w, 405)
		return
	}
	switch path {
	case "/api/browser/logout":
		var in *struct{}
		if !browserhttp.Read(w, r, &in) {
			return
		}
		if in == nil {
			browserhttp.Error(w, 400)
			return
		}
		if h.accounts.Revoke(r.Context(), token) != nil {
			browserhttp.Error(w, 503)
			return
		}
		browserhttp.Cookie(w, "session", "", -1)
		browserhttp.JSON(w, 200, map[string]bool{"signed_out": true})
	case "/api/browser/backup":
		var in struct {
			PublicKey string `json:"public_key"`
			Backup    string `json:"backup"`
			Revision  int64  `json:"revision"`
		}
		if !browserhttp.Read(w, r, &in) {
			return
		}
		public, ok := browserhttp.Decode(in.PublicKey, 32)
		backup, ok2 := browserhttp.Decode(in.Backup, 108)
		if !ok || !ok2 {
			browserhttp.Error(w, 400)
			return
		}
		revision, err := h.backups.PutForSession(r.Context(), token, in.Revision, public, backup)
		if err != nil {
			browserhttp.Error(w, 409)
			return
		}
		browserhttp.JSON(w, 200, map[string]int64{"revision": revision})
	case "/api/browser/invitations":
		var in struct{}
		if !browserhttp.Read(w, r, &in) {
			return
		}
		code, err := h.state.Invite(r.Context(), token)
		if err != nil {
			browserhttp.Error(w, 403)
			return
		}
		defer clear(code)
		browserhttp.JSON(w, 201, map[string]string{"code": browserhttp.Encode(code), "expires": "24 hours"})
	case "/api/browser/enroll":
		var in struct {
			Code string `json:"code"`
			CSR  string `json:"csr"`
		}
		if !browserhttp.Read(w, r, &in) {
			return
		}
		code, ok := browserhttp.Decode(in.Code, 32)
		defer clear(code)
		csr, ok2 := browserhttp.Decode(in.CSR, 129)
		if !ok || !ok2 {
			browserhttp.Error(w, 400)
			return
		}
		cert, err := h.state.Enroll(r.Context(), token, code, csr, h.cfg.CA, h.cfg.CAKey)
		if err != nil {
			browserhttp.Error(w, 403)
			return
		}
		browserhttp.JSON(w, 201, map[string]string{"certificate": browserhttp.Encode(cert)})
	case "/api/browser/rounds":
		var in struct {
			Question      string    `json:"question"`
			Reviewer      string    `json:"reviewer"`
			Opens         time.Time `json:"opens"`
			Closes        time.Time `json:"closes"`
			ReviewUntil   time.Time `json:"review_until"`
			ResponseLimit int       `json:"response_limit"`
		}
		if !browserhttp.Read(w, r, &in) {
			return
		}
		id, err := h.state.CreateRound(r.Context(), token, browser.Round{Question: in.Question, ReviewerName: in.Reviewer, Opens: in.Opens, Closes: in.Closes, ReviewUntil: in.ReviewUntil, ResponseLimit: in.ResponseLimit})
		if err != nil {
			browserhttp.Error(w, 403)
			return
		}
		browserhttp.JSON(w, 201, map[string]string{"id": browserhttp.Encode(id)})
	case "/api/browser/reviewer":
		var in struct {
			Round     string `json:"round"`
			PublicKey string `json:"public_key"`
		}
		if !browserhttp.Read(w, r, &in) {
			return
		}
		id, ok := browserhttp.Decode(in.Round, 16)
		public, ok2 := browserhttp.Decode(in.PublicKey, 32)
		if !ok || !ok2 {
			browserhttp.Error(w, 400)
			return
		}
		if h.state.PrepareReviewer(r.Context(), token, id, public) != nil {
			browserhttp.Error(w, 403)
			return
		}
		browserhttp.JSON(w, 200, map[string]bool{"prepared": true})
	case "/api/browser/publish":
		var in struct {
			Round string `json:"round"`
			Limit int    `json:"response_limit"`
		}
		if !browserhttp.Read(w, r, &in) {
			return
		}
		id, ok := browserhttp.Decode(in.Round, 16)
		if !ok {
			browserhttp.Error(w, 400)
			return
		}
		raw, err := h.state.Publish(r.Context(), token, id, in.Limit, h.cfg.BulletinKey, h.cfg.ReceiptKey)
		if err != nil {
			browserhttp.Error(w, 403)
			return
		}
		browserhttp.JSON(w, 201, map[string]string{"bulletin": browserhttp.Encode(raw)})
	case "/api/browser/challenge":
		var in struct {
			Round   string `json:"round"`
			Blinded string `json:"blinded"`
		}
		if !browserhttp.Read(w, r, &in) {
			return
		}
		id, ok := browserhttp.Decode(in.Round, 16)
		blinded, ok2 := browserhttp.Decode(in.Blinded, 384)
		if !ok || !ok2 {
			browserhttp.Error(w, 400)
			return
		}
		raw, err := h.state.Challenge(r.Context(), token, id, blinded)
		if err != nil {
			browserhttp.Error(w, 409)
			return
		}
		browserhttp.JSON(w, 200, map[string]string{"challenge": browserhttp.Encode(raw)})
	case "/api/browser/issue":
		var in struct {
			Challenge string `json:"challenge"`
			Signature string `json:"signature"`
			Blinded   string `json:"blinded"`
		}
		if !browserhttp.Read(w, r, &in) {
			return
		}
		challenge, ok := browserhttp.Decode(in.Challenge, 113)
		sig, ok2 := browserhttp.Decode(in.Signature, 64)
		blinded, ok3 := browserhttp.Decode(in.Blinded, 384)
		if !ok || !ok2 || !ok3 {
			browserhttp.Error(w, 400)
			return
		}
		out, err := h.state.Issue(r.Context(), token, challenge, sig, blinded, h.cfg.CA)
		if err != nil {
			browserhttp.Error(w, 409)
			return
		}
		browserhttp.JSON(w, 200, map[string]string{"signature": browserhttp.Encode(out)})
	default:
		browserhttp.Error(w, 404)
	}
}

func (h *handler) authenticate(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		browserhttp.Error(w, 405)
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/browser/auth/"), "/")
	if len(parts) != 2 || (parts[0] != "register" && parts[0] != "login" && parts[0] != "reauthenticate") {
		browserhttp.Error(w, 404)
		return
	}
	kind := parts[0]
	storageKind := kind
	if kind == "reauthenticate" {
		storageKind = "login"
	}
	if parts[1] == "begin" {
		var in struct {
			Name      string `json:"name"`
			Bootstrap string `json:"bootstrap"`
		}
		if kind == "reauthenticate" {
			var empty *struct{}
			if !browserhttp.Read(w, r, &empty) {
				return
			}
			if empty == nil {
				browserhttp.Error(w, 400)
				return
			}
		} else if !browserhttp.Read(w, r, &in) {
			return
		}
		var c ceremony
		c.Kind = kind
		if kind == "reauthenticate" {
			token := browserhttp.Token(r, "session")
			defer clear(token)
			var err error
			c.User, err = h.state.Current(r.Context(), token)
			if err != nil {
				browserhttp.Error(w, 401)
				return
			}
			in.Name = c.User.Name
			c.Bearer = sha256.Sum256(token)
		}
		hash := sha256.Sum256([]byte(in.Name))
		if !h.attempts.Allow(string(hash[:])) {
			w.Header().Set("Retry-After", "300")
			browserhttp.Error(w, 429)
			return
		}
		if !browser.ValidUsername(in.Name) {
			browserhttp.Error(w, 400)
			return
		}
		var options any
		var err error
		if kind == "register" {
			c.User.Name = in.Name
			rand.Read(c.User.ID[:])
			if in.Bootstrap != "" {
				code, ok := browserhttp.Decode(in.Bootstrap, 32)
				defer clear(code)
				digest := sha256.Sum256(code)
				if !ok || h.cfg.BootstrapDigest == ([32]byte{}) || subtle.ConstantTimeCompare(digest[:], h.cfg.BootstrapDigest[:]) != 1 {
					browserhttp.Error(w, 403)
					return
				}
				c.User.Admin = true
			}
			var session *webauthn.SessionData
			options, session, err = h.auth.BeginRegistration(c.User)
			if session != nil {
				c.Session = *session
			}
		} else {
			c.User, err = h.state.User(r.Context(), in.Name)
			if err != nil {
				browserhttp.Error(w, 403)
				return
			}
			var session *webauthn.SessionData
			options, session, err = h.auth.BeginLogin(c.User)
			if session != nil {
				c.Session = *session
			}
		}
		if err != nil {
			browserhttp.Error(w, 403)
			return
		}
		raw, err := json.Marshal(c)
		if err != nil {
			browserhttp.Error(w, 503)
			return
		}
		secret := browserhttp.Random()
		defer clear(secret)
		if h.state.SaveCeremony(r.Context(), secret, storageKind, raw) != nil {
			browserhttp.Error(w, 503)
			return
		}
		browserhttp.Cookie(w, "ceremony", browserhttp.Encode(secret), 120)
		browserhttp.JSON(w, 200, options)
		return
	}
	if parts[1] != "finish" {
		browserhttp.Error(w, 404)
		return
	}
	secret := browserhttp.Token(r, "ceremony")
	defer clear(secret)
	raw, err := h.state.TakeCeremony(r.Context(), secret, storageKind)
	browserhttp.Cookie(w, "ceremony", "", -1)
	var c ceremony
	if err != nil || json.Unmarshal(raw, &c) != nil || c.Kind != kind {
		browserhttp.Error(w, 403)
		return
	}
	if kind == "reauthenticate" {
		token := browserhttp.Token(r, "session")
		defer clear(token)
		digest := sha256.Sum256(token)
		user, err := h.state.Current(r.Context(), token)
		if err != nil || user.ID != c.User.ID || subtle.ConstantTimeCompare(digest[:], c.Bearer[:]) != 1 {
			browserhttp.Error(w, 401)
			return
		}
	}
	// Bounded library parsing sees only the allowlisted WebAuthn response JSON.
	r.Body = http.MaxBytesReader(w, r.Body, browserhttp.MaxBody)
	if kind == "register" {
		credential, err := h.auth.FinishRegistration(c.User, c.Session, r)
		if err != nil {
			browserhttp.Error(w, 403)
			return
		}
		c.User.Credential = *credential
		if h.state.Register(r.Context(), c.User) != nil {
			browserhttp.Error(w, 409)
			return
		}
	} else {
		user, err := h.state.Login(r.Context(), c.User.Name, func(u browser.User) (*webauthn.Credential, error) {
			if u.ID != c.User.ID {
				return nil, browser.ErrDenied
			}
			return h.auth.FinishLogin(u, c.Session, r)
		})
		if err != nil {
			browserhttp.Error(w, 403)
			return
		}
		c.User = user
	}
	// Account changes cannot refresh an existing bearer without a verified ceremony.
	old := browserhttp.Token(r, "session")
	defer clear(old)
	if kind == "reauthenticate" {
		token, session, err := h.accounts.RotateSession(r.Context(), c.User.ID, old)
		if err != nil {
			browserhttp.Error(w, 401)
			return
		}
		defer clear(token)
		browserhttp.Cookie(w, "session", browserhttp.Encode(token), max(1, int(time.Until(session.ExpiresAt)/time.Second)))
		browserhttp.JSON(w, 200, map[string]bool{"authenticated": true})
		return
	}
	if len(old) == 32 {
		if h.accounts.Revoke(r.Context(), old) != nil {
			browserhttp.Error(w, 503)
			return
		}
	}
	token, _, err := h.accounts.StartSession(r.Context(), c.User.ID, time.Hour)
	if err != nil {
		browserhttp.Error(w, 503)
		return
	}
	defer clear(token)
	browserhttp.Cookie(w, "session", browserhttp.Encode(token), 3600)
	browserhttp.JSON(w, 200, map[string]bool{"authenticated": true})
}

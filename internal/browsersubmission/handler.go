// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

// Package browsersubmission serves the anonymous browser context. It imports no
// identity code and accepts no account cookie, certificate or account identifier.
package browsersubmission

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/mandipnotroot/anonce/internal/browserhttp"
	"github.com/mandipnotroot/anonce/internal/reviewprofile"
	"github.com/mandipnotroot/anonce/internal/submission/browser"
)

type Config struct {
	Origin, IdentityOrigin string
	Publication            ed25519.PublicKey
	Receipt                ed25519.PrivateKey
	Assets                 http.Handler
}
type handler struct {
	cfg   Config
	state *browser.Store
}

func New(ctx context.Context, pool *pgxpool.Pool, cfg Config) (http.Handler, error) {
	if !browserhttp.IsOrigin(cfg.Origin) || !browserhttp.IsOrigin(cfg.IdentityOrigin) || len(cfg.Publication) != 32 || len(cfg.Receipt) != 64 || cfg.Assets == nil {
		return nil, browser.ErrDenied
	}
	state, err := browser.New(ctx, pool, cfg.Publication)
	if err != nil {
		return nil, err
	}
	return browserhttp.NewGate(cfg.Origin, false).Wrap(&handler{cfg, state}), nil
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.URL.Path, "/api/browser/") {
		h.cfg.Assets.ServeHTTP(w, r)
		return
	}
	// This origin never uses cookies or HTTP bearer authentication, including for
	// review. Do not consume even accidentally delivered identity credentials.
	if r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" {
		browserhttp.Error(w, 403)
		return
	}
	origin := r.Header.Get("Origin")
	cross := origin == h.cfg.IdentityOrigin
	if origin != "" && origin != h.cfg.Origin && !cross {
		browserhttp.Error(w, 403)
		return
	}
	if cross {
		w.Header().Set("Access-Control-Allow-Origin", h.cfg.IdentityOrigin)
		w.Header().Set("Vary", "Origin")
	}
	if r.Method == "OPTIONS" {
		if !cross || r.Header.Get("Access-Control-Request-Method") != "POST" || strings.ToLower(r.Header.Get("Access-Control-Request-Headers")) != "content-type" {
			browserhttp.Error(w, 403)
			return
		}
		w.Header().Set("Access-Control-Allow-Methods", "POST")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.WriteHeader(204)
		return
	}
	if r.URL.Path == "/api/browser/config" && r.Method == "GET" {
		browserhttp.JSON(w, 200, map[string]string{"identity_origin": h.cfg.IdentityOrigin, "bulletin_key": browserhttp.Encode(h.cfg.Publication)})
		return
	}
	if r.URL.Path == "/api/browser/bulletin" && r.Method == "GET" {
		id, ok := browserhttp.Decode(r.URL.Query().Get("round"), 16)
		if !ok {
			browserhttp.Error(w, 400)
			return
		}
		_, raw, err := h.state.Bulletin(r.Context(), id)
		if err != nil {
			browserhttp.Error(w, 404)
			return
		}
		browserhttp.JSON(w, 200, map[string]string{"bulletin": browserhttp.Encode(raw)})
		return
	}
	if r.Method != "POST" {
		browserhttp.Error(w, 405)
		return
	}
	// Cross-origin JSON requests use an exact-origin preflight, never credentials.
	switch r.URL.Path {
	case "/api/browser/publish":
		var in struct {
			Bulletin string `json:"bulletin"`
		}
		if !browserhttp.Read(w, r, &in) {
			return
		}
		if len(in.Bulletin) > 2200 {
			browserhttp.Error(w, 400)
			return
		}
		raw, err := decodeVariable(in.Bulletin)
		if err != nil {
			browserhttp.Error(w, 400)
			return
		}
		b, err := reviewprofile.ParseBulletin(raw, h.cfg.Publication)
		if err != nil || !b.ReceiptKey.Equal(h.cfg.Receipt.Public()) {
			browserhttp.Error(w, 403)
			return
		}
		if h.state.Publish(r.Context(), raw) != nil {
			browserhttp.Error(w, 409)
			return
		}
		browserhttp.JSON(w, 200, map[string]bool{"published": true})
	case "/api/browser/submit":
		if cross {
			browserhttp.Error(w, 403)
			return
		}
		var in struct {
			Round    string `json:"round"`
			Token    string `json:"token"`
			Envelope string `json:"envelope"`
		}
		if !browserhttp.Read(w, r, &in) {
			return
		}
		id, ok := browserhttp.Decode(in.Round, 16)
		token, ok2 := browserhttp.Decode(in.Token, 504)
		defer clear(token)
		envelope, ok3 := browserhttp.Decode(in.Envelope, 4145)
		if !ok || !ok2 || !ok3 {
			browserhttp.Error(w, 400)
			return
		}
		receipt, err := h.state.Accept(r.Context(), id, token, envelope, h.cfg.Receipt)
		if err != nil {
			browserhttp.Error(w, 409)
			return
		}
		browserhttp.JSON(w, 200, map[string]string{"receipt": browserhttp.Encode(receipt)})
	case "/api/browser/review/challenge":
		var in struct {
			Round  string `json:"round"`
			Cursor string `json:"cursor"`
		}
		if !browserhttp.Read(w, r, &in) {
			return
		}
		id, ok := browserhttp.Decode(in.Round, 16)
		cursor, ok2 := browserhttp.Decode(in.Cursor, 16)
		if !ok || !ok2 {
			browserhttp.Error(w, 400)
			return
		}
		secret := browserhttp.Random()
		defer clear(secret)
		envelope, err := h.state.Challenge(r.Context(), id, cursor, secret)
		if err != nil {
			browserhttp.Error(w, 403)
			return
		}
		browserhttp.JSON(w, 200, map[string]string{"challenge": browserhttp.Encode(envelope)})
	case "/api/browser/review/read":
		var in struct {
			Round string `json:"round"`
			Proof string `json:"proof"`
		}
		if !browserhttp.Read(w, r, &in) {
			return
		}
		id, ok := browserhttp.Decode(in.Round, 16)
		proof, ok2 := browserhttp.Decode(in.Proof, 32)
		defer clear(proof)
		if !ok || !ok2 {
			browserhttp.Error(w, 400)
			return
		}
		out, cursor, err := h.state.Read(r.Context(), id, proof)
		if err != nil {
			browserhttp.Error(w, 403)
			return
		}
		encoded := make([]map[string]string, 0, len(out))
		for _, record := range out {
			encoded = append(encoded, map[string]string{"id": browserhttp.Encode(record.ID), "envelope": browserhttp.Encode(record.Envelope)})
		}
		browserhttp.JSON(w, 200, map[string]any{"records": encoded, "cursor": browserhttp.Encode(cursor)})
	default:
		browserhttp.Error(w, 404)
	}
}

func decodeVariable(s string) ([]byte, error) {
	if len(s) > 2200 {
		return nil, errors.New("invalid encoding")
	}
	b, e := base64.RawURLEncoding.Strict().DecodeString(s)
	if e != nil || browserhttp.Encode(b) != s {
		return nil, errors.New("invalid encoding")
	}
	return b, nil
}

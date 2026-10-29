// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

package browseridentity

import (
	"errors"
	"net/http"
	"time"

	"github.com/mandipnotroot/anonce/internal/browserhttp"
	"github.com/mandipnotroot/anonce/internal/identity/accounts"
)

func sessionError(w http.ResponseWriter, err error) {
	status := http.StatusServiceUnavailable
	if errors.Is(err, accounts.ErrReauthenticationRequired) {
		status = http.StatusForbidden
	} else if errors.Is(err, accounts.ErrUnavailable) {
		status = http.StatusUnauthorized
	}
	browserhttp.Error(w, status)
}

func (h *handler) manageSessions(w http.ResponseWriter, r *http.Request, token []byte) {
	if r.URL.Path == "/api/browser/sessions" && r.Method == http.MethodGet {
		list, err := h.accounts.ListSessions(r.Context(), token)
		if err != nil {
			sessionError(w, err)
			return
		}
		type info struct {
			ID        string    `json:"id"`
			CreatedAt time.Time `json:"created_at"`
			ExpiresAt time.Time `json:"expires_at"`
			Current   bool      `json:"current"`
		}
		out := make([]info, 0, len(list))
		for _, s := range list {
			out = append(out, info{browserhttp.Encode(s.ID[:]), s.CreatedAt, s.ExpiresAt, s.Current})
		}
		browserhttp.JSON(w, 200, out)
		return
	}
	if r.Method != http.MethodPost || r.URL.Path == "/api/browser/sessions" {
		browserhttp.Error(w, 405)
		return
	}
	if r.URL.Path == "/api/browser/sessions/revoke" {
		var in struct {
			ID string `json:"id"`
		}
		if !browserhttp.Read(w, r, &in) {
			return
		}
		id, ok := browserhttp.Decode(in.ID, 16)
		if !ok || accounts.SessionID(id) == (accounts.SessionID{}) {
			browserhttp.Error(w, 400)
			return
		}
		removed, err := h.accounts.RevokeSession(r.Context(), token, accounts.SessionID(id))
		if err != nil {
			sessionError(w, err)
			return
		}
		browserhttp.JSON(w, 200, map[string]bool{"removed": removed})
		return
	}
	var in *struct{}
	if !browserhttp.Read(w, r, &in) {
		return
	}
	if in == nil {
		browserhttp.Error(w, 400)
		return
	}
	if _, err := h.accounts.RevokeAllForSession(r.Context(), token); err != nil {
		sessionError(w, err)
		return
	}
	browserhttp.Cookie(w, "session", "", -1)
	browserhttp.JSON(w, 200, map[string]bool{"signed_out": true})
}

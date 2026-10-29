// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

package browseridentity

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"net/http"
	"path/filepath"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/mandipnotroot/anonce/internal/browserapp"
	"github.com/mandipnotroot/anonce/internal/browserhttp"
	"github.com/mandipnotroot/anonce/internal/identity/browser"
)

func FromState(ctx context.Context, pool *pgxpool.Pool, cfg browserapp.LocalConfig) (http.Handler, error) {
	caKey, err := browserapp.Seed(cfg.Directory, "membership")
	if err != nil {
		return nil, err
	}
	bulletin, err := browserapp.Seed(cfg.Directory, "bulletin")
	if err != nil {
		clear(caKey)
		return nil, err
	}
	caDER, err := browserapp.ReadFile(filepath.Join(cfg.Directory, "membership.der"), 1024, false)
	if err != nil {
		return nil, err
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, browser.ErrDenied
	}
	receipt, err := browserapp.ReadFile(filepath.Join(cfg.Directory, "receipt.pub"), 32, false)
	if err != nil {
		return nil, err
	}
	invitation, err := browserapp.ReadFile(filepath.Join(cfg.Directory, "administrator-invitation"), 43, true)
	if err != nil {
		return nil, err
	}
	bootstrap, ok := browserhttp.Decode(string(invitation), 32)
	clear(invitation)
	if !ok {
		return nil, browser.ErrDenied
	}
	digest := sha256.Sum256(bootstrap)
	clear(bootstrap)
	return New(ctx, pool, Config{Origin: cfg.Origin, SubmissionOrigin: cfg.Peer, BootstrapDigest: digest, CA: ca, CAKey: caKey, BulletinKey: bulletin, ReceiptKey: receipt, Assets: cfg.Assets})
}

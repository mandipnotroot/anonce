// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

package browsersubmission

import (
	"context"
	"net/http"
	"path/filepath"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/mandipnotroot/anonce/internal/browserapp"
)

func FromState(ctx context.Context, pool *pgxpool.Pool, cfg browserapp.LocalConfig) (http.Handler, error) {
	receipt, err := browserapp.Seed(cfg.Directory, "receipt")
	if err != nil {
		return nil, err
	}
	publication, err := browserapp.ReadFile(filepath.Join(cfg.Directory, "bulletin.pub"), 32, false)
	if err != nil {
		clear(receipt)
		return nil, err
	}
	return New(ctx, pool, Config{Origin: cfg.Origin, IdentityOrigin: cfg.Peer, Publication: publication, Receipt: receipt, Assets: cfg.Assets})
}

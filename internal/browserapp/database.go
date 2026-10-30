// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

package browserapp

import "github.com/jackc/pgx/v5"

// No arbitrary remote host, cross-service database, credential URL or fallback is
// admitted. Container mode is explicit and retains independent runtime roles.
func runtimeDatabase(c *pgx.ConnConfig, side string, container bool) bool {
	if c == nil || side != "identity" && side != "submission" || c.Database != side || c.User != "anonce_runtime" || c.Password != "" || len(c.Fallbacks) != 0 {
		return false
	}
	if container {
		return c.Host == side+"-db" && c.Port == 5432
	}
	return c.Host == "127.0.0.1"
}

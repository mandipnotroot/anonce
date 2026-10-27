// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

// Package clientwasm adapts public member-request verification for a local WASM
// caller. It provides no private-key, persistence, transport, or enrollment API.
package clientwasm

import (
	"encoding/hex"

	"github.com/mandipnotroot/anonce/internal/client/membercsr"
)

const encodedRequestSize = 2 * membercsr.DERSize

func verifyHex(encoded string) (string, error) {
	if len(encoded) != encodedRequestSize {
		return "", membercsr.ErrInvalidRequest
	}
	der, err := hex.DecodeString(encoded)
	if err != nil {
		return "", membercsr.ErrInvalidRequest
	}
	public, err := membercsr.Parse(der)
	if err != nil {
		return "", err
	}
	return "member:" + hex.EncodeToString(public) + "\n", nil
}

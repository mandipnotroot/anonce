// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

// Package clientwasm adapts public member-request verification for a local WASM
// caller. It provides no private-key, persistence, transport, or enrollment API.
package clientwasm

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"

	"github.com/mandipnotroot/anonce/internal/client/membercsr"
)

const encodedRequestSize = 2 * membercsr.DERSize

func verifyHex(encoded string) (string, error) {
	public, err := parseRequestHex(encoded)
	if err != nil {
		return "", err
	}
	return "member:" + hex.EncodeToString(public) + "\n", nil
}

func verifyHexForKey(encoded, expectedHex string) (string, error) {
	if len(expectedHex) != 2*ed25519.PublicKeySize {
		return "", membercsr.ErrInvalidRequest
	}
	expected, err := hex.DecodeString(expectedHex)
	if err != nil {
		return "", membercsr.ErrInvalidRequest
	}
	public, err := parseRequestHex(encoded)
	if err != nil {
		return "", err
	}
	// Both keys are public. Matching never bypasses profile/signature validation.
	if !bytes.Equal(public, expected) {
		return "", membercsr.ErrInvalidRequest
	}
	return "member:" + hex.EncodeToString(public) + "\n", nil
}

func parseRequestHex(encoded string) (ed25519.PublicKey, error) {
	if len(encoded) != encodedRequestSize {
		return nil, membercsr.ErrInvalidRequest
	}
	der, err := hex.DecodeString(encoded)
	if err != nil {
		return nil, membercsr.ErrInvalidRequest
	}
	return membercsr.Parse(der)
}

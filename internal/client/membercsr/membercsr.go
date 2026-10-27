// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

// Package membercsr creates and validates member CSR profile 1 from
// docs/cryptography.md. It provides no enrollment, transport, or authorization.
package membercsr

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
)

// DERSize is the exact size of a profile 1 request, including its signature.
const DERSize = 129

var (
	ErrInvalidKey     = errors.New("invalid member key")
	ErrInvalidRequest = errors.New("invalid member certificate request")
)

// Create signs only the fixed, identity-free request profile. The private key
// remains caller-owned and must be cleared after use, not mutated during a call.
func Create(ctx context.Context, key ed25519.PrivateKey) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("create member request: %w", err)
	}
	if len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("create member request: %w", ErrInvalidKey)
	}
	derived := ed25519.NewKeyFromSeed(key[:ed25519.SeedSize])
	defer clear(derived)
	if subtle.ConstantTimeCompare(key, derived) != 1 {
		return nil, fmt.Errorf("create member request: %w", ErrInvalidKey)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		SignatureAlgorithm: x509.PureEd25519,
	}, key)
	if err != nil {
		return nil, errors.New("create member request: signing failed")
	}
	if _, err := Parse(der); err != nil {
		return nil, fmt.Errorf("create member request: %w", err)
	}
	if err := ctx.Err(); err != nil {
		clear(der)
		return nil, fmt.Errorf("create member request: %w", err)
	}
	return der, nil
}

// Parse bounds decoding, enforces the complete canonical profile, and verifies
// the signature through x509. It returns an independently owned public key, not
// an identity, freshness check, or authorization. Inputs must not be mutated
// during the call. Invalid requests return ErrInvalidRequest without output.
func Parse(der []byte) (ed25519.PublicKey, error) {
	if len(der) != DERSize {
		return nil, ErrInvalidRequest
	}
	request, err := x509.ParseCertificateRequest(der)
	if err != nil || request.Version != 0 || request.SignatureAlgorithm != x509.PureEd25519 {
		return nil, ErrInvalidRequest
	}
	public, ok := request.PublicKey.(ed25519.PublicKey)
	if !ok || len(public) != ed25519.PublicKeySize {
		return nil, ErrInvalidRequest
	}
	spki, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return nil, ErrInvalidRequest
	}
	// Reconstruct all fields, including attributes unknown to x509, rather than
	// accepting the parser's filtered subject, extension, and attribute views.
	canonical, err := asn1.Marshal(certificateRequest{
		Info: requestInfo{
			Subject: asn1.RawValue{FullBytes: []byte{0x30, 0}},
			Public:  asn1.RawValue{FullBytes: spki},
		},
		Algorithm: pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 3, 101, 112}},
		Signature: asn1.BitString{Bytes: request.Signature, BitLength: ed25519.SignatureSize * 8},
	})
	if err != nil || !bytes.Equal(der, canonical) || request.CheckSignature() != nil {
		return nil, ErrInvalidRequest
	}
	return ed25519.PublicKey(bytes.Clone(public)), nil
}

type requestInfo struct {
	Version    int
	Subject    asn1.RawValue
	Public     asn1.RawValue
	Attributes []asn1.RawValue `asn1:"tag:0"`
}

type certificateRequest struct {
	Info      requestInfo
	Algorithm pkix.AlgorithmIdentifier
	Signature asn1.BitString
}

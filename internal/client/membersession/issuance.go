// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

package membersession

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"

	"github.com/mandipnotroot/anonce/internal/client/keystore"
	"github.com/mandipnotroot/anonce/internal/reviewprofile"
)

// Authorize signs only the fixed version-one issuance challenge. It never signs
// arbitrary application messages. The host must validate its common bulletin,
// round and blinded-request binding before explicit user authorization.
func (s *Session) Authorize(ctx context.Context, challenge []byte) ([]byte, error) {
	if len(challenge) != 113 || challenge[0] != 1 {
		return nil, keystore.ErrInvalidInput
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(s.key) != 64 {
		return nil, ErrState
	}
	message := append([]byte("anonce/issuance/v1\x00"), challenge...)
	sig := ed25519.Sign(s.key, message)
	if err := ctx.Err(); err != nil {
		clear(sig)
		return nil, err
	}
	return sig, nil
}

// AuthorizeForRound validates the independently configured publication key and
// all public challenge bindings before signing with the retained member key.
func (s *Session) AuthorizeForRound(ctx context.Context, challenge, bulletin, publication, blinded []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	b, err := reviewprofile.ParseBulletin(bulletin, publication)
	if err != nil || len(challenge) != 113 || len(blinded) != 384 {
		return nil, keystore.ErrInvalidInput
	}
	digest := sha256.Sum256(bulletin)
	request := sha256.Sum256(blinded)
	if !bytes.Equal(challenge[1:17], b.ID[:]) || !bytes.Equal(challenge[17:49], digest[:]) || !bytes.Equal(challenge[81:113], request[:]) {
		return nil, keystore.ErrInvalidInput
	}
	return s.Authorize(ctx, challenge)
}

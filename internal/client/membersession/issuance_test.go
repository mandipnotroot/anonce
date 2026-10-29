// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

package membersession

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/mandipnotroot/anonce/internal/reviewprofile"
)

func TestBoundIssuanceAuthorization(t *testing.T) {
	ctx := t.Context()
	var session Session
	defer session.Lock()
	setup, err := session.CreateConfirmed(ctx, []byte("synthetic issuance unlock"), []byte("synthetic issuance unlock"))
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal("generate round fixture")
	}
	review, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("generate reviewer fixture")
	}
	pub, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("generate publication fixture")
	}
	defer clear(signer)
	receipt, receiptPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("generate receipt fixture")
	}
	defer clear(receiptPrivate)
	now := time.Now().UTC().Truncate(time.Second)
	b := reviewprofile.Bulletin{Opens: now.Add(-time.Minute), Closes: now.Add(time.Hour), ReviewUntil: now.Add(24 * time.Hour), ResponseLimit: 1, Question: "Synthetic fixed authorization", RSA: &rsaKey.PublicKey, Reviewer: review.PublicKey().Bytes(), ReceiptKey: receipt}
	rand.Read(b.ID[:])
	raw, err := reviewprofile.SignBulletin(b, signer)
	if err != nil {
		t.Fatal(err)
	}
	blinded, _, err := reviewprofile.Prepare(b, raw)
	if err != nil {
		t.Fatal(err)
	}
	challenge := make([]byte, 113)
	challenge[0] = 1
	copy(challenge[1:17], b.ID[:])
	digest := sha256.Sum256(raw)
	copy(challenge[17:49], digest[:])
	rand.Read(challenge[49:81])
	request := sha256.Sum256(blinded)
	copy(challenge[81:], request[:])
	sig, err := session.AuthorizeForRound(ctx, challenge, raw, pub, blinded)
	message, err2 := reviewprofile.IssuanceMessage(challenge)
	if err != nil || err2 != nil || !ed25519.Verify(setup.PublicKey, message, sig) {
		t.Fatal("fixed authorization signature")
	}
	for _, tc := range []struct {
		name   string
		change func([]byte)
	}{{"version", func(b []byte) { b[0] = 2 }}, {"round", func(b []byte) { b[1] ^= 1 }}, {"bulletin", func(b []byte) { b[17] ^= 1 }}, {"blinded-request", func(b []byte) { b[81] ^= 1 }}} {
		t.Run(tc.name, func(t *testing.T) {
			wrong := bytes.Clone(challenge)
			tc.change(wrong)
			if out, err := session.AuthorizeForRound(ctx, wrong, raw, pub, blinded); err == nil || out != nil {
				t.Fatal("signed mismatched context")
			}
		})
	}
	wrong := bytes.Clone(raw)
	wrong[len(wrong)-1] ^= 1
	if out, err := session.AuthorizeForRound(ctx, challenge, wrong, pub, blinded); err == nil || out != nil {
		t.Fatal("signed an unverified bulletin")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if out, err := session.AuthorizeForRound(cancelled, challenge, raw, pub, blinded); out != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled signing returned output")
	}
	session.Lock()
	if out, err := session.AuthorizeForRound(ctx, challenge, raw, pub, blinded); out != nil || !errors.Is(err, ErrState) {
		t.Fatal("locked signing returned output")
	}
}

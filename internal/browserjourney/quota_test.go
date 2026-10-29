//go:build browsermvp

// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

package browserjourney

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cloudflare/circl/blindsign/blindrsa"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/mandipnotroot/anonce/internal/browserapp"
	"github.com/mandipnotroot/anonce/internal/client/membersession"
	"github.com/mandipnotroot/anonce/internal/identity/accounts"
	identity "github.com/mandipnotroot/anonce/internal/identity/browser"
	"github.com/mandipnotroot/anonce/internal/reviewprofile"
	submission "github.com/mandipnotroot/anonce/internal/submission/browser"
)

func quotaRace(t *testing.T, identityPool, submissionPool *pgxpool.Pool, state string, store *identity.Store, accountStore *accounts.Store, adminToken, memberToken []byte, member *membersession.Session, ca *x509.Certificate) {
	t.Helper()
	ctx := t.Context()
	now := time.Now().UTC().Truncate(time.Second)
	round, err := store.CreateRound(ctx, adminToken, identity.Round{Question: "Synthetic quota race", ReviewerName: "reviewer_one", Opens: now.Add(-time.Minute), Closes: now.Add(time.Hour), ReviewUntil: now.Add(24 * time.Hour), ResponseLimit: 1})
	if err != nil {
		t.Fatal("create quota-race round")
	}
	reviewer, err := store.User(ctx, "reviewer_one")
	if err != nil {
		t.Fatal(err)
	}
	reviewerSession, _, err := accountStore.StartSession(ctx, reviewer.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(reviewerSession)
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if store.PrepareReviewer(ctx, reviewerSession, round, private.PublicKey().Bytes()) != nil {
		t.Fatal("prepare quota-race reviewer")
	}
	publication, err := browserapp.Seed(filepath.Join(state, "identity"), "bulletin")
	if err != nil {
		t.Fatal(err)
	}
	defer clear(publication)
	receipt, err := browserapp.Seed(filepath.Join(state, "submission"), "receipt")
	if err != nil {
		t.Fatal(err)
	}
	defer clear(receipt)
	receiptPublic, err := os.ReadFile(filepath.Join(state, "identity/receipt.pub"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := store.Publish(ctx, adminToken, round, 1, publication, receiptPublic)
	if err != nil {
		t.Fatal("publish quota-race round")
	}
	public := ed25519.PublicKey(publication[32:])
	b, err := reviewprofile.ParseBulletin(raw, public)
	if err != nil {
		t.Fatal(err)
	}
	sub, err := submission.New(ctx, submissionPool, public)
	if err != nil {
		t.Fatal(err)
	}
	if sub.Publish(ctx, raw) != nil {
		t.Fatal("provision quota-race round")
	}
	blinded, pending, err := reviewprofile.Prepare(b, raw)
	if err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if out, err := store.Challenge(cancelled, memberToken, round, blinded); out != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled admission returned output or lost cancellation")
	}
	var wg sync.WaitGroup
	var winners atomic.Int32
	var mu sync.Mutex
	var challenge []byte
	start := make(chan struct{})
	for range 6 {
		wg.Go(func() {
			<-start
			out, err := store.Challenge(ctx, memberToken, round, blinded)
			if err == nil {
				winners.Add(1)
				mu.Lock()
				challenge = out
				mu.Unlock()
			}
		})
	}
	close(start)
	wg.Wait()
	if winners.Load() != 1 {
		t.Fatal("concurrent challenges did not serialize")
	}
	signature, err := member.AuthorizeForRound(ctx, challenge, raw, publication[32:], blinded)
	if err != nil {
		t.Fatal(err)
	}
	winners.Store(0)
	start = make(chan struct{})
	var blindSignature []byte
	for range 6 {
		wg.Go(func() {
			<-start
			out, err := store.Issue(ctx, memberToken, challenge, signature, blinded, ca)
			if err == nil {
				winners.Add(1)
				mu.Lock()
				blindSignature = out
				mu.Unlock()
			}
		})
	}
	close(start)
	wg.Wait()
	if winners.Load() != 1 {
		t.Fatal("concurrent issuance exceeded one membership allowance")
	}
	if _, err := store.Challenge(ctx, memberToken, round, blinded); err == nil {
		t.Fatal("reserved allowance was reused")
	}
	token, err := pending.Finalize(blindSignature)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(token)
	envelope, err := reviewprofile.Seal(b, raw, []byte("Synthetic concurrent acceptance"))
	if err != nil {
		t.Fatal(err)
	}
	var receipts [][]byte
	var failures atomic.Int32
	start = make(chan struct{})
	for range 8 {
		wg.Go(func() {
			<-start
			out, err := sub.Accept(ctx, round, token, envelope, receipt)
			if err != nil {
				failures.Add(1)
				return
			}
			mu.Lock()
			receipts = append(receipts, out)
			mu.Unlock()
		})
	}
	close(start)
	wg.Wait()
	if failures.Load() != 0 || len(receipts) != 8 {
		t.Fatal("exact retries failed")
	}
	for _, r := range receipts {
		if !bytes.Equal(r, receipts[0]) || reviewprofile.VerifyReceipt(b, raw, token, envelope, r) != nil {
			t.Fatal("retry receipt binding changed")
		}
	}
	changed := bytes.Clone(envelope)
	changed[len(changed)-1] ^= 1
	if out, err := sub.Accept(ctx, round, token, changed, receipt); err == nil || out != nil {
		t.Fatal("duplicate spend replaced ciphertext")
	}
	secret := make([]byte, 32)
	rand.Read(secret)
	defer clear(secret)
	encrypted, err := sub.Challenge(ctx, round, make([]byte, 16), secret)
	if err != nil {
		t.Fatal("prepare reviewer proof")
	}
	proof, err := reviewprofile.Open(raw, private.Bytes(), encrypted, true)
	if err != nil || !bytes.Equal(proof, secret) {
		t.Fatal("reviewer proof binding")
	}
	defer clear(proof)
	winners.Store(0)
	start = make(chan struct{})
	for range 6 {
		wg.Go(func() {
			<-start
			records, _, err := sub.Read(ctx, round, proof)
			if err == nil {
				if len(records) != 1 || !bytes.Equal(records[0].Envelope, envelope) {
					failures.Add(1)
				}
				winners.Add(1)
			}
		})
	}
	close(start)
	wg.Wait()
	if winners.Load() != 1 || failures.Load() != 0 {
		t.Fatal("review proof replay race")
	}
	// A genuinely valid token on a signed already-closed synthetic round must be
	// rejected after verification, not merely because its signature was malformed.
	closedKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	closed := b
	rand.Read(closed.ID[:])
	closed.RSA = &closedKey.PublicKey
	closed.Opens = now.Add(-2 * time.Hour)
	closed.Closes = now.Add(-time.Hour)
	closedRaw, err := reviewprofile.SignBulletin(closed, publication)
	if err != nil {
		t.Fatal(err)
	}
	if sub.Publish(ctx, closedRaw) != nil {
		t.Fatal("provision closed synthetic round")
	}
	blind, pendingClosed, err := reviewprofile.Prepare(closed, closedRaw)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := blindrsa.NewSigner(closedKey).BlindSign(blind)
	if err != nil {
		t.Fatal(err)
	}
	closedToken, err := pendingClosed.Finalize(sig)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(closedToken)
	closedEnvelope, err := reviewprofile.Seal(closed, closedRaw, []byte("Synthetic closed-round rejection"))
	if err != nil {
		t.Fatal(err)
	}
	if out, err := sub.Accept(ctx, closed.ID[:], closedToken, closedEnvelope, receipt); err == nil || out != nil {
		t.Fatal("closed round accepted a valid token")
	}
}

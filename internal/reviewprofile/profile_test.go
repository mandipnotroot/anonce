// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

package reviewprofile

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"encoding/binary"
	"sync"
	"testing"
	"time"

	"github.com/cloudflare/circl/blindsign/blindrsa"
)

var keyOnce = sync.OnceValues(func() (*rsa.PrivateKey, error) { return rsa.GenerateKey(rand.Reader, 3072) })

func fixture(t *testing.T) (Bulletin, []byte, []byte, ed25519.PrivateKey, *rsa.PrivateKey) {
	t.Helper()
	rsaKey, err := keyOnce()
	if err != nil {
		t.Fatal("generate RSA fixture")
	}
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("generate reviewer fixture")
	}
	_, signing, _ := ed25519.GenerateKey(rand.Reader)
	_, receipt, _ := ed25519.GenerateKey(rand.Reader)
	b := Bulletin{Opens: time.Now().UTC().Truncate(time.Second).Add(-time.Hour), Closes: time.Now().UTC().Truncate(time.Second).Add(time.Hour), ReviewUntil: time.Now().UTC().Truncate(time.Second).Add(24 * time.Hour), ResponseLimit: 1, Reviewer: private.PublicKey().Bytes(), RSA: &rsaKey.PublicKey, ReceiptKey: receipt.Public().(ed25519.PublicKey), Question: "Describe one improvement."}
	rand.Read(b.ID[:])
	raw, err := SignBulletin(b, signing)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseBulletin(raw, signing.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	return parsed, raw, private.Bytes(), receipt, rsaKey
}

func TestProfileJourney(t *testing.T) {
	b, raw, reviewer, receiptKey, rsaKey := fixture(t)
	defer clear(reviewer)
	defer clear(receiptKey)
	blind, pending, err := Prepare(b, raw)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := blindrsa.NewSigner(rsaKey).BlindSign(blind)
	if err != nil {
		t.Fatal(err)
	}
	token, err := pending.Finalize(sig)
	if err != nil {
		t.Fatal(err)
	}
	// Independent standard-library PSS verification of the finalized signature.
	h := sha512.Sum384(token[:120])
	if rsa.VerifyPSS(b.RSA, crypto.SHA384, h[:], token[120:], &rsa.PSSOptions{SaltLength: 48, Hash: crypto.SHA384}) != nil {
		t.Fatal("independent RSA verification failed")
	}
	spend, err := VerifyToken(b, raw, token)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := Seal(b, raw, []byte("Synthetic browser answer é"))
	if err != nil || len(envelope) != EnvelopeSize {
		t.Fatal("seal answer")
	}
	text, err := Open(raw, reviewer, envelope, false)
	if err != nil || string(text) != "Synthetic browser answer é" {
		t.Fatal("open answer")
	}
	clear(text)
	record := [16]byte{1}
	receipt, err := Receipt(b, raw, record, spend, envelope, receiptKey)
	if err != nil || VerifyReceipt(b, raw, token, envelope, receipt) != nil {
		t.Fatal("verify durable-acceptance contract")
	}
	for _, test := range []struct {
		name   string
		mutate func([]byte, []byte, []byte)
	}{{"token", func(t, e, r []byte) { t[90] ^= 1 }}, {"envelope", func(t, e, r []byte) { e[100] ^= 1 }}, {"receipt", func(t, e, r []byte) { r[80] ^= 1 }}} {
		t.Run(test.name, func(t *testing.T) {
			a, c, r := bytes.Clone(token), bytes.Clone(envelope), bytes.Clone(receipt)
			test.mutate(a, c, r)
			if VerifyReceipt(b, raw, a, c, r) == nil {
				t.Fatal("accepted modified binding")
			}
		})
	}
	if _, err := pending.Finalize(sig); err == nil {
		t.Fatal("reused finalized client state")
	}
}

func TestEnvelopeIsolation(t *testing.T) {
	b, raw, private, receipt, _ := fixture(t)
	defer clear(private)
	defer clear(receipt)
	envelope, err := Seal(b, raw, []byte("synthetic"))
	if err != nil {
		t.Fatal(err)
	}
	other, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name               string
		raw, key, envelope []byte
		review             bool
	}{{"wrong-key", raw, other.Bytes(), envelope, false}, {"wrong-bulletin", append(bytes.Clone(raw), 0), private, envelope, false}, {"wrong-purpose", raw, private, envelope, true}, {"truncated", raw, private, envelope[:100], false}, {"tampered", raw, private, append(bytes.Clone(envelope[:100]), make([]byte, len(envelope)-100)...), false}} {
		t.Run(tc.name, func(t *testing.T) {
			if out, e := Open(tc.raw, tc.key, tc.envelope, tc.review); e == nil || out != nil {
				t.Fatal("returned plaintext on invalid envelope")
			}
		})
	}
	secret := make([]byte, 32)
	rand.Read(secret)
	challenge, err := SealReviewChallenge(b, raw, secret)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := Open(raw, private, challenge, true)
	if err != nil || !bytes.Equal(proof, secret) {
		t.Fatal("review proof")
	}
	clear(proof)
	clear(secret)
}

func TestBulletinBounds(t *testing.T) {
	b, raw, private, receipt, _ := fixture(t)
	defer clear(private)
	defer clear(receipt)
	for _, limit := range []byte{0, 2, 255} {
		b.ResponseLimit = limit
		if _, err := SignBulletin(b, receipt); err == nil {
			t.Fatal("unsupported response limit")
		}
	}
	for _, size := range []int{0, 1, 563, 1588, 32768} {
		if _, err := ParseBulletin(make([]byte, size), ed25519.PublicKey(receipt[32:])); err == nil {
			t.Fatal("accepted malformed bulletin")
		}
	}
	b.ResponseLimit = 1
	for _, text := range [][]byte{nil, {0xff}, make([]byte, 4001)} {
		if _, err := Seal(b, raw, text); err == nil {
			t.Fatal("accepted malformed answer")
		}
	}
}

func TestSignedTimestampBounds(t *testing.T) {
	_, raw, private, receipt, _ := fixture(t)
	defer clear(private)
	defer clear(receipt)
	public, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("generate timestamp fixture signer")
	}
	defer clear(signer)
	for _, offset := range []int{24, 32, 40} {
		for _, value := range []uint64{0, 1767225599, 4133980800, ^uint64(0)} {
			modified := bytes.Clone(raw)
			binary.BigEndian.PutUint64(modified[offset:offset+8], value)
			copy(modified[len(modified)-64:], ed25519.Sign(signer, domain("bulletin", modified[:len(modified)-64])))
			if _, err := ParseBulletin(modified, public); err == nil {
				t.Fatal("accepted signed out-of-profile timestamp")
			}
		}
	}
}

func FuzzProfileRejection(f *testing.F) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		f.Fatal("generate fuzz key")
	}
	private := key.Bytes()
	defer clear(private)
	f.Add([]byte("synthetic"))
	f.Add(make([]byte, 564))
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 32768 {
			return
		}
		_, _ = ParseBulletin(input, make([]byte, 32))
		_, _ = Open(nil, private, input, false)
		_, _ = IssuanceMessage(input)
	})
}

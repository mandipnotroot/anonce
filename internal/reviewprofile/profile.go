// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

// Package reviewprofile implements the bounded browser MVP composition documented
// in docs/cryptography.md. It contains no transport or persistence.
package reviewprofile

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/big"
	"time"
	"unicode/utf8"

	"github.com/cloudflare/circl/blindsign/blindrsa"
)

const (
	EnvelopeSize    = 4145
	TokenSize       = 504
	ChallengeSize   = 113
	ReceiptSize     = 200
	MaxBulletinSize = 1587
	minimumBulletin = 564
)

var ErrInvalid = errors.New("invalid review profile input")

type Bulletin struct {
	ID                         [16]byte
	Opens, Closes, ReviewUntil time.Time
	ResponseLimit              byte
	Reviewer                   []byte
	RSA                        *rsa.PublicKey
	ReceiptKey                 ed25519.PublicKey
	Question                   string
}

func valid(b Bulletin) bool {
	return b.ID != [16]byte{} && len(b.Reviewer) == 32 && len(b.ReceiptKey) == 32 &&
		b.Opens.Nanosecond() == 0 && b.Closes.Nanosecond() == 0 && b.ReviewUntil.Nanosecond() == 0 &&
		b.RSA != nil && b.RSA.N != nil && b.RSA.N.BitLen() == 3072 && b.RSA.N.Bit(0) == 1 && b.RSA.E == 65537 &&
		b.ResponseLimit == 1 && len(b.Question) > 0 && len(b.Question) <= 1024 && utf8.ValidString(b.Question) &&
		b.Opens.Unix() >= 1767225600 && b.ReviewUntil.Unix() < 4133980800 &&
		b.Closes.After(b.Opens) && b.ReviewUntil.After(b.Closes) && b.ReviewUntil.Sub(b.Closes) <= 30*24*time.Hour
}

func SignBulletin(b Bulletin, key ed25519.PrivateKey) ([]byte, error) {
	if !valid(b) || len(key) != ed25519.PrivateKeySize {
		return nil, ErrInvalid
	}
	out := append([]byte("ANONCER1"), b.ID[:]...)
	for _, t := range []time.Time{b.Opens, b.Closes, b.ReviewUntil} {
		seconds := t.Unix()
		if seconds < 1767225600 || seconds >= 4133980800 {
			return nil, ErrInvalid
		}
		out = binary.BigEndian.AppendUint64(out, uint64(seconds))
	}
	out = append(out, b.ResponseLimit)
	out = append(out, b.Reviewer...)
	out = append(out, b.RSA.N.FillBytes(make([]byte, 384))...)
	out = append(out, b.ReceiptKey...)
	questionSize := len(b.Question)
	if questionSize < 1 || questionSize > 1024 {
		return nil, ErrInvalid
	}
	out = binary.BigEndian.AppendUint16(out, uint16(questionSize))
	out = append(out, b.Question...)
	return append(out, ed25519.Sign(key, domain("bulletin", out))...), nil
}

func ParseBulletin(raw []byte, key ed25519.PublicKey) (Bulletin, error) {
	var b Bulletin
	if len(raw) < minimumBulletin || len(raw) > MaxBulletinSize || len(key) != 32 || string(raw[:8]) != "ANONCER1" {
		return b, ErrInvalid
	}
	if !ed25519.Verify(key, domain("bulletin", raw[:len(raw)-64]), raw[len(raw)-64:]) {
		return b, ErrInvalid
	}
	copy(b.ID[:], raw[8:24])
	times := []*time.Time{&b.Opens, &b.Closes, &b.ReviewUntil}
	for i, target := range times {
		seconds := binary.BigEndian.Uint64(raw[24+8*i : 32+8*i])
		if seconds < 1767225600 || seconds >= 4133980800 {
			return Bulletin{}, ErrInvalid
		}
		*target = time.Unix(int64(seconds), 0).UTC()
	}
	b.ResponseLimit = raw[48]
	b.Reviewer = bytes.Clone(raw[49:81])
	b.RSA = &rsa.PublicKey{N: new(big.Int).SetBytes(raw[81:465]), E: 65537}
	b.ReceiptKey = bytes.Clone(raw[465:497])
	n := int(binary.BigEndian.Uint16(raw[497:499]))
	if n < 1 || n > 1024 || len(raw) != 499+n+64 {
		return Bulletin{}, ErrInvalid
	}
	b.Question = string(raw[499 : 499+n])
	if !valid(b) {
		return Bulletin{}, ErrInvalid
	}
	return b, nil
}

func domain(purpose string, raw []byte) []byte {
	return append([]byte("anonce/"+purpose+"/v1\x00"), raw...)
}

// IssuanceMessage permits fixed-profile challenge signatures only.
func IssuanceMessage(challenge []byte) ([]byte, error) {
	if len(challenge) != ChallengeSize || challenge[0] != 1 {
		return nil, ErrInvalid
	}
	return domain("issuance", challenge), nil
}

type Pending struct {
	client   blindrsa.Client
	state    blindrsa.State
	prepared []byte
}

func Prepare(b Bulletin, raw []byte) ([]byte, *Pending, error) {
	if !valid(b) {
		return nil, nil, ErrInvalid
	}
	digest := sha256.Sum256(raw)
	msg := append([]byte("ANONCET1"), b.ID[:]...)
	msg = append(msg, digest[:]...)
	nonce := make([]byte, 32)
	rand.Read(nonce)
	msg = append(msg, nonce...)
	c, err := blindrsa.NewClient(blindrsa.SHA384PSSRandomized, b.RSA)
	if err != nil {
		return nil, nil, ErrInvalid
	}
	prepared, err := c.Prepare(rand.Reader, msg)
	if err != nil {
		return nil, nil, ErrInvalid
	}
	blinded, state, err := c.Blind(rand.Reader, prepared)
	if err != nil {
		return nil, nil, ErrInvalid
	}
	return blinded, &Pending{c, state, prepared}, nil
}

func (p *Pending) Finalize(signature []byte) ([]byte, error) {
	if p == nil || len(p.prepared) != 120 || len(signature) != 384 {
		return nil, ErrInvalid
	}
	sig, err := p.client.Finalize(p.state, signature)
	if err != nil {
		return nil, ErrInvalid
	}
	out := append(bytes.Clone(p.prepared), sig...)
	clear(p.prepared)
	p.prepared = nil
	p.state = blindrsa.State{}
	return out, nil
}

func VerifyToken(b Bulletin, raw, token []byte) ([32]byte, error) {
	if !valid(b) || len(token) != TokenSize {
		return [32]byte{}, ErrInvalid
	}
	digest := sha256.Sum256(raw)
	if string(token[32:40]) != "ANONCET1" || !bytes.Equal(token[40:56], b.ID[:]) || !bytes.Equal(token[56:88], digest[:]) {
		return [32]byte{}, ErrInvalid
	}
	v, err := blindrsa.NewVerifier(blindrsa.SHA384PSSRandomized, b.RSA)
	if err != nil || v.Verify(token[:120], token[120:]) != nil {
		return [32]byte{}, ErrInvalid
	}
	return sha256.Sum256(domain("spend", token[:120])), nil
}

func Seal(b Bulletin, raw, text []byte) ([]byte, error) {
	textSize := len(text)
	if !valid(b) || textSize < 1 || textSize > 4000 || !utf8.Valid(text) {
		return nil, ErrInvalid
	}
	pt := make([]byte, 4096)
	defer clear(pt)
	binary.BigEndian.PutUint16(pt, uint16(textSize))
	copy(pt[2:], text)
	return seal(b, raw, "answer", 1, pt)
}

func SealReviewChallenge(b Bulletin, raw, secret []byte) ([]byte, error) {
	if !valid(b) || len(secret) != 32 {
		return nil, ErrInvalid
	}
	return seal(b, raw, "review", 2, secret)
}

func seal(b Bulletin, raw []byte, purpose string, version byte, pt []byte) ([]byte, error) {
	pk, err := hpke.DHKEM(ecdh.X25519()).NewPublicKey(b.Reviewer)
	if err != nil {
		return nil, ErrInvalid
	}
	digest := sha256.Sum256(raw)
	ct, err := hpke.Seal(pk, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), domain(purpose, digest[:]), pt)
	if err != nil {
		return nil, ErrInvalid
	}
	return append([]byte{version}, ct...), nil
}

func Open(raw, private, envelope []byte, review bool) ([]byte, error) {
	purpose, size, version := "answer", EnvelopeSize, byte(1)
	if review {
		purpose, size, version = "review", 81, 2
	}
	if len(envelope) != size || envelope[0] != version || len(private) != 32 {
		return nil, ErrInvalid
	}
	key, err := hpke.DHKEM(ecdh.X25519()).NewPrivateKey(private)
	if err != nil {
		return nil, ErrInvalid
	}
	digest := sha256.Sum256(raw)
	pt, err := hpke.Open(key, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), domain(purpose, digest[:]), envelope[1:])
	if err != nil {
		return nil, ErrInvalid
	}
	if review {
		if len(pt) != 32 {
			clear(pt)
			return nil, ErrInvalid
		}
		return pt, nil
	}
	defer clear(pt)
	if len(pt) != 4096 {
		return nil, ErrInvalid
	}
	n := int(binary.BigEndian.Uint16(pt))
	if n < 1 || n > 4000 || !utf8.Valid(pt[2:2+n]) {
		return nil, ErrInvalid
	}
	for _, v := range pt[2+n:] {
		if v != 0 {
			return nil, ErrInvalid
		}
	}
	return bytes.Clone(pt[2 : 2+n]), nil
}

func Receipt(b Bulletin, raw []byte, record [16]byte, spend [32]byte, envelope []byte, key ed25519.PrivateKey) ([]byte, error) {
	if len(key) != 64 || !bytes.Equal(key[32:], b.ReceiptKey) || len(envelope) != EnvelopeSize {
		return nil, ErrInvalid
	}
	digest := sha256.Sum256(raw)
	payload := sha256.Sum256(envelope)
	out := append([]byte("ANONCEA1"), b.ID[:]...)
	out = append(out, digest[:]...)
	out = append(out, record[:]...)
	out = append(out, spend[:]...)
	out = append(out, payload[:]...)
	return append(out, ed25519.Sign(key, out)...), nil
}

func VerifyReceipt(b Bulletin, raw, token, envelope, receipt []byte) error {
	spend, err := VerifyToken(b, raw, token)
	if err != nil || len(receipt) != ReceiptSize || len(envelope) != EnvelopeSize {
		return ErrInvalid
	}
	digest := sha256.Sum256(raw)
	payload := sha256.Sum256(envelope)
	if string(receipt[:8]) != "ANONCEA1" || !bytes.Equal(receipt[8:24], b.ID[:]) || !bytes.Equal(receipt[24:56], digest[:]) || !bytes.Equal(receipt[72:104], spend[:]) || !bytes.Equal(receipt[104:136], payload[:]) || !ed25519.Verify(b.ReceiptKey, receipt[:136], receipt[136:]) {
		return ErrInvalid
	}
	return nil
}

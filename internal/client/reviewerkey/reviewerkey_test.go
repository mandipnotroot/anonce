// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

package reviewerkey

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"crypto/x509"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/mandipnotroot/anonce/internal/client/keystore"
	"github.com/mandipnotroot/anonce/internal/client/memberkey"
)

// All keys are generated during tests; no private-key fixtures are retained.
func testKey(t *testing.T) []byte {
	t.Helper()
	key, err := Generate(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(key) })
	return key
}

func libraryKey(t *testing.T, privateKey []byte) *ecdh.PrivateKey {
	t.Helper()
	key, err := ecdh.X25519().NewPrivateKey(privateKey)
	if err != nil {
		t.Fatal("library rejected private encoding")
	}
	return key
}

func TestReviewerKeyGenerate(t *testing.T) {
	first, second := testKey(t), testKey(t)
	if len(first) != 32 || len(second) != 32 {
		t.Fatal("unexpected private-key size")
	}
	a, b := libraryKey(t, first), libraryKey(t, second)
	if a.PublicKey().Equal(b.PublicKey()) {
		t.Fatal("generation reused a reviewer key")
	}
	sharedA, err := a.ECDH(b.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	defer clear(sharedA)
	sharedB, err := b.ECDH(a.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	defer clear(sharedB)
	if subtle.ConstantTimeCompare(sharedA, sharedB) != 1 {
		t.Fatal("generated keys cannot agree on a shared secret")
	}
}

func TestReviewerKeyRoundTrip(t *testing.T) {
	key := testKey(t)
	original := bytes.Clone(key)
	defer clear(original)
	password := []byte("synthetic test password")
	defer clear(password)
	backup, err := Seal(t.Context(), password, key)
	if err != nil {
		t.Fatal(err)
	}
	if len(backup) != 108 || backup[8] != 1 || backup[9] != 2 || backup[10] != byte(keystore.ReviewerKey) {
		t.Fatal("unexpected reviewer-key backup size, profile, or purpose")
	}
	backupCopy := bytes.Clone(backup)
	opened, err := Open(t.Context(), password, backup)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(opened)
	if subtle.ConstantTimeCompare(key, opened) != 1 || subtle.ConstantTimeCompare(key, original) != 1 ||
		!bytes.Equal(backup, backupCopy) || string(password) != "synthetic test password" {
		t.Fatal("round trip changed key or caller-owned inputs")
	}
	if !libraryKey(t, key).PublicKey().Equal(libraryKey(t, opened).PublicKey()) {
		t.Fatal("imported key does not match original public key")
	}
	clear(opened)
	if subtle.ConstantTimeCompare(key, original) != 1 {
		t.Fatal("import returned an alias of caller-owned private bytes")
	}
	again, err := Open(t.Context(), password, backup)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(again)
	if subtle.ConstantTimeCompare(again, original) != 1 {
		t.Fatal("clearing imported key changed backup or later imports")
	}
	second, err := Seal(t.Context(), password, key)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(backup, second) || bytes.Equal(backup[12:28], second[12:28]) || bytes.Equal(backup[32:44], second[32:44]) {
		t.Fatal("re-export reused backup randomness")
	}
}

func TestReviewerKeyLibraryCompatibility(t *testing.T) {
	key := testKey(t)
	password := []byte("synthetic test password")
	defer clear(password)
	der, err := x509.MarshalPKCS8PrivateKey(libraryKey(t, key))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(der)
	if len(der) != privateKeyDERSize {
		t.Fatal("library encoding does not match documented profile")
	}
	// Import a backup composed without the reviewer-key wrapper.
	backup, err := keystore.Seal(t.Context(), keystore.ReviewerKey, password, der)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := Open(t.Context(), password, backup)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(opened)
	if subtle.ConstantTimeCompare(key, opened) != 1 {
		t.Fatal("could not import library-composed backup")
	}
	// Independently decrypt and parse the wrapper's exported payload.
	exported, err := Seal(t.Context(), password, key)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := keystore.Open(t.Context(), keystore.ReviewerKey, password, exported)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(payload)
	parsed, err := x509.ParsePKCS8PrivateKey(payload)
	if err != nil {
		t.Fatal("library could not parse exported payload")
	}
	parsedKey, ok := parsed.(*ecdh.PrivateKey)
	if !ok || parsedKey.Curve() != ecdh.X25519() {
		t.Fatal("export changed key algorithm")
	}
	privateBytes := parsedKey.Bytes()
	defer clear(privateBytes)
	if subtle.ConstantTimeCompare(privateBytes, key) != 1 || subtle.ConstantTimeCompare(payload, der) != 1 {
		t.Fatal("export changed private key or canonical encoding")
	}
}

func TestReviewerKeyPreservesEncoding(t *testing.T) {
	key := testKey(t)
	equivalent := bytes.Clone(key)
	defer clear(equivalent)
	equivalent[0] ^= 1 // X25519 ignores these low scalar bits during multiplication.
	if !libraryKey(t, key).PublicKey().Equal(libraryKey(t, equivalent).PublicKey()) {
		t.Fatal("library changed X25519 scalar processing")
	}
	password := []byte("synthetic test password")
	defer clear(password)
	backup, err := Seal(t.Context(), password, equivalent)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := Open(t.Context(), password, backup)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(opened)
	if subtle.ConstantTimeCompare(opened, equivalent) != 1 {
		t.Fatal("round trip normalized private encoding")
	}
}

func TestReviewerKeyRejectsInvalidInputs(t *testing.T) {
	key := testKey(t)
	cases := []struct {
		name     string
		key      []byte
		password []byte
	}{
		{"missing key", nil, []byte("synthetic test password")},
		{"truncated key", key[:31], []byte("synthetic test password")},
		{"oversized key", make([]byte, 33), []byte("synthetic test password")},
		{"missing password", key, nil},
		{"oversized password", key, make([]byte, keystore.MaxPasswordSize+1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			backup, err := Seal(t.Context(), tc.password, tc.key)
			if backup != nil || !errors.Is(err, keystore.ErrInvalidInput) {
				t.Fatalf("invalid input returned output or wrong error: %v", err)
			}
		})
	}
	for _, password := range [][]byte{nil, make([]byte, keystore.MaxPasswordSize+1)} {
		opened, err := Open(t.Context(), password, nil)
		if opened != nil || !errors.Is(err, keystore.ErrInvalidInput) {
			t.Fatalf("import accepted invalid password input: %v", err)
		}
	}
}

func TestReviewerKeyRejectsInvalidPayloads(t *testing.T) {
	key := testKey(t)
	der, err := x509.MarshalPKCS8PrivateKey(libraryKey(t, key))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(der)
	_, signingKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(signingKey)
	wrongAlgorithm, err := x509.MarshalPKCS8PrivateKey(signingKey)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(wrongAlgorithm)
	version := bytes.Clone(der)
	defer clear(version)
	version[4] = 1 // Accepted by x509, but not the canonical profile.
	unknown := bytes.Clone(der)
	defer clear(unknown)
	unknown[11] = 0xff
	trailing := append(bytes.Clone(der), 0)
	defer clear(trailing)
	parameters := append(bytes.Clone(der[:12]), 0x05, 0x00)
	parameters = append(parameters, der[12:]...)
	defer clear(parameters)
	parameters[1], parameters[6] = 0x30, 0x07
	attributes := append(bytes.Clone(der), 0xa0, 0x00)
	defer clear(attributes)
	attributes[1] = 0x30
	cases := []struct {
		name    string
		payload []byte
	}{
		{"opaque non-key", []byte("synthetic non-key payload")},
		{"raw private key", key},
		{"truncated DER", der[:len(der)-1]},
		{"trailing DER", trailing},
		{"noncanonical version", version},
		{"unknown algorithm", unknown},
		{"wrong algorithm", wrongAlgorithm},
		{"NULL algorithm parameters", parameters},
		{"attributes", attributes},
		{"malformed ASN.1", make([]byte, privateKeyDERSize)},
	}
	password := []byte("synthetic test password")
	defer clear(password)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Authentication is not sufficient: validate even reviewer-purpose payloads.
			backup, err := keystore.Seal(t.Context(), keystore.ReviewerKey, password, tc.payload)
			if err != nil {
				t.Fatal(err)
			}
			opened, err := Open(t.Context(), password, backup)
			if opened != nil || !errors.Is(err, keystore.ErrInvalidBackup) {
				t.Fatalf("invalid payload returned key or wrong error: %v", err)
			}
		})
	}
}

func TestReviewerKeyRejectsUnauthenticatedBackup(t *testing.T) {
	key := testKey(t)
	password := []byte("synthetic test password")
	defer clear(password)
	backup, err := Seal(t.Context(), password, key)
	if err != nil {
		t.Fatal(err)
	}
	wrongPurpose := bytes.Clone(backup)
	wrongPurpose[10] = byte(keystore.MemberKey)
	tampered := bytes.Clone(backup)
	tampered[len(tampered)-1] ^= 1
	cases := []struct {
		name     string
		password []byte
		backup   []byte
	}{
		{"wrong password", []byte("different synthetic test password"), backup},
		{"wrong purpose", password, wrongPurpose},
		{"tampered ciphertext", password, tampered},
		{"missing backup", password, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opened, err := Open(t.Context(), tc.password, tc.backup)
			if opened != nil || !errors.Is(err, keystore.ErrInvalidBackup) {
				t.Fatalf("unauthenticated backup returned key or wrong error: %v", err)
			}
		})
	}
}

func TestReviewerKeyPurposeIsolation(t *testing.T) {
	key := testKey(t)
	password := []byte("synthetic test password")
	defer clear(password)
	der, err := x509.MarshalPKCS8PrivateKey(libraryKey(t, key))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(der)
	// A genuine member-purpose backup cannot be imported as a reviewer key,
	// even if it contains valid X25519 DER and has an authentic header.
	memberPurpose, err := keystore.Seal(t.Context(), keystore.MemberKey, password, der)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := Open(t.Context(), password, memberPurpose)
	if opened != nil || !errors.Is(err, keystore.ErrInvalidBackup) {
		clear(opened)
		t.Fatalf("import accepted member purpose: %v", err)
	}
	reviewerPurpose, err := Seal(t.Context(), password, key)
	if err != nil {
		t.Fatal(err)
	}
	member, err := memberkey.Open(t.Context(), password, reviewerPurpose)
	if member != nil || !errors.Is(err, keystore.ErrInvalidBackup) {
		clear(member)
		t.Fatalf("member importer accepted reviewer purpose: %v", err)
	}
}

func TestReviewerKeyCancellation(t *testing.T) {
	key := testKey(t)
	password := []byte("synthetic test password")
	defer clear(password)
	backup, err := Seal(t.Context(), password, key)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		check   int32
		operate func(context.Context) ([]byte, error)
	}{
		{"generate at entry", 1, Generate},
		{"generate before output", 2, Generate},
		{"seal at entry", 1, func(ctx context.Context) ([]byte, error) { return Seal(ctx, password, key) }},
		{"seal before output", 5, func(ctx context.Context) ([]byte, error) { return Seal(ctx, password, key) }},
		{"open at entry", 1, func(ctx context.Context) ([]byte, error) { return Open(ctx, password, backup) }},
		{"open after validation", 5, func(ctx context.Context) ([]byte, error) { return Open(ctx, password, backup) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			parent, cancel := context.WithCancel(t.Context())
			defer cancel()
			ctx := &cancelOnCheck{Context: parent, cancel: cancel, trigger: tc.check}
			output, err := tc.operate(ctx)
			if output != nil || !errors.Is(err, context.Canceled) {
				clear(output)
				t.Fatalf("cancelled operation returned output or wrong error: %v", err)
			}
		})
	}
}

type cancelOnCheck struct {
	context.Context
	cancel  context.CancelFunc
	trigger int32
	checks  atomic.Int32
}

func (c *cancelOnCheck) Err() error {
	if c.checks.Add(1) == c.trigger {
		c.cancel()
	}
	return c.Context.Err()
}

func TestReviewerKeyConcurrent(t *testing.T) {
	key := testKey(t)
	password := []byte("synthetic test password")
	defer clear(password)
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			backup, err := Seal(t.Context(), password, key)
			if err != nil {
				t.Error(err)
				return
			}
			opened, err := Open(t.Context(), password, backup)
			if err != nil {
				t.Error(err)
				return
			}
			defer clear(opened)
			if subtle.ConstantTimeCompare(key, opened) != 1 {
				t.Error("concurrent import changed key")
			}
		})
	}
	wg.Wait()
}

func FuzzReviewerKeyPayload(f *testing.F) {
	// Only malformed non-key seeds and public DER structure, never private keys.
	f.Add([]byte{})
	f.Add([]byte("synthetic non-key payload"))
	f.Add(make([]byte, privateKeyDERSize))
	f.Add([]byte{0x30, 0x2e, 0x02, 0x01, 0, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20})
	f.Fuzz(func(t *testing.T, payload []byte) {
		if len(payload) > privateKeyDERSize+1 {
			return
		}
		key, err := parsePrivateKey(payload)
		if err != nil {
			if key != nil || !errors.Is(err, keystore.ErrInvalidBackup) {
				t.Fatal("rejected payload returned key or wrong error")
			}
			return
		}
		defer clear(key)
		if len(key) != 32 || len(payload) != privateKeyDERSize {
			t.Fatal("parser accepted unexpected size")
		}
		canonical, err := x509.MarshalPKCS8PrivateKey(libraryKey(t, key))
		if err != nil {
			t.Fatal("accepted key cannot be serialized")
		}
		defer clear(canonical)
		if subtle.ConstantTimeCompare(payload, canonical) != 1 {
			t.Fatal("parser accepted noncanonical encoding")
		}
	})
}

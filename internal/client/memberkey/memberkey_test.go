// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

package memberkey

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
)

// All keys are generated during tests and cleared, never retained as fixtures.
func testKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	key, err := Generate(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(key) })
	return key
}

func TestMemberKeyGenerate(t *testing.T) {
	first, second := testKey(t), testKey(t)
	if len(first) != ed25519.PrivateKeySize || len(second) != ed25519.PrivateKeySize {
		t.Fatal("unexpected private-key size")
	}
	if first.Public().(ed25519.PublicKey).Equal(second.Public()) {
		t.Fatal("generation reused a member key")
	}
	message := []byte("synthetic proof of possession")
	if !ed25519.Verify(first.Public().(ed25519.PublicKey), message, ed25519.Sign(first, message)) {
		t.Fatal("generated key cannot sign")
	}
}

func TestMemberKeyRoundTrip(t *testing.T) {
	key := testKey(t)
	original := bytes.Clone(key)
	defer clear(original)
	password := []byte("synthetic test password")
	defer clear(password)
	backup, err := Seal(t.Context(), password, key)
	if err != nil {
		t.Fatal(err)
	}
	if len(backup) != 108 || backup[8] != 1 || backup[9] != 2 {
		t.Fatal("unexpected member-key backup size or profile")
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
	message := []byte("synthetic imported proof of possession")
	if !ed25519.Verify(key.Public().(ed25519.PublicKey), message, ed25519.Sign(opened, message)) {
		t.Fatal("imported key does not match original public key")
	}
	clear(opened)
	if subtle.ConstantTimeCompare(key, original) != 1 {
		t.Fatal("import returned an alias of caller-owned private key")
	}
	second, err := Seal(t.Context(), password, key)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(backup, second) || bytes.Equal(backup[12:28], second[12:28]) || bytes.Equal(backup[32:44], second[32:44]) {
		t.Fatal("re-export reused backup randomness")
	}
}

func TestMemberKeyLibraryCompatibility(t *testing.T) {
	key := testKey(t)
	password := []byte("synthetic test password")
	defer clear(password)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(der)
	if len(der) != privateKeyDERSize {
		t.Fatal("library encoding does not match documented profile")
	}
	// Import a backup composed without the member-key export wrapper.
	backup, err := keystore.Seal(t.Context(), keystore.MemberKey, password, der)
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
	payload, err := keystore.Open(t.Context(), keystore.MemberKey, password, exported)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(payload)
	parsed, err := x509.ParsePKCS8PrivateKey(payload)
	if err != nil {
		t.Fatal("library could not parse exported payload")
	}
	parsedKey, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		t.Fatal("export changed key algorithm")
	}
	defer clear(parsedKey)
	if subtle.ConstantTimeCompare(parsedKey, key) != 1 || subtle.ConstantTimeCompare(payload, der) != 1 {
		t.Fatal("export changed private key or canonical encoding")
	}
}

func TestMemberKeyRejectsInvalidInputs(t *testing.T) {
	key := testKey(t)
	inconsistent := bytes.Clone(key)
	defer clear(inconsistent)
	inconsistent[ed25519.SeedSize] ^= 1
	cases := []struct {
		name     string
		key      ed25519.PrivateKey
		password []byte
	}{
		{"missing key", nil, []byte("synthetic test password")},
		{"seed only", key[:ed25519.SeedSize], []byte("synthetic test password")},
		{"truncated key", key[:ed25519.PrivateKeySize-1], []byte("synthetic test password")},
		{"oversized key", make([]byte, ed25519.PrivateKeySize+1), []byte("synthetic test password")},
		{"inconsistent public half", inconsistent, []byte("synthetic test password")},
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

func TestMemberKeyRejectsInvalidPayloads(t *testing.T) {
	key := testKey(t)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(der)
	xkey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	xder, err := x509.MarshalPKCS8PrivateKey(xkey)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(xder)
	version := bytes.Clone(der)
	defer clear(version)
	version[4] = 1 // x509 accepts this version, but it is not our canonical encoding.
	unknown := bytes.Clone(der)
	defer clear(unknown)
	unknown[11] = 0xff
	trailing := append(bytes.Clone(der), 0)
	defer clear(trailing)
	cases := []struct {
		name    string
		payload []byte
	}{
		{"opaque non-key", []byte("synthetic non-key payload")},
		{"seed only", key[:ed25519.SeedSize]},
		{"raw private key", key},
		{"truncated DER", der[:len(der)-1]},
		{"trailing DER", trailing},
		{"noncanonical version", version},
		{"unknown algorithm", unknown},
		{"wrong algorithm", xder},
		{"malformed ASN.1", make([]byte, privateKeyDERSize)},
	}
	password := []byte("synthetic test password")
	defer clear(password)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Even authenticated, member-purpose payloads must pass key validation.
			backup, err := keystore.Seal(t.Context(), keystore.MemberKey, password, tc.payload)
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

func TestMemberKeyRejectsUnauthenticatedBackup(t *testing.T) {
	key := testKey(t)
	password := []byte("synthetic test password")
	defer clear(password)
	backup, err := Seal(t.Context(), password, key)
	if err != nil {
		t.Fatal(err)
	}
	wrongPurpose := bytes.Clone(backup)
	wrongPurpose[10] = byte(keystore.ReviewerKey)
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

func TestMemberKeyCancellation(t *testing.T) {
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
		{"generate at entry", 1, func(ctx context.Context) ([]byte, error) { return Generate(ctx) }},
		{"generate before output", 2, func(ctx context.Context) ([]byte, error) { return Generate(ctx) }},
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

func TestMemberKeyConcurrent(t *testing.T) {
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

func FuzzMemberKeyPayload(f *testing.F) {
	// Only malformed non-key seeds are retained. Never add real private keys.
	f.Add([]byte{})
	f.Add([]byte("synthetic non-key payload"))
	f.Add(make([]byte, privateKeyDERSize))
	// Public DER structure only, without any seed bytes.
	f.Add([]byte{0x30, 0x2e, 0x02, 0x01, 0, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20})
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
		if len(key) != ed25519.PrivateKeySize || len(payload) != privateKeyDERSize {
			t.Fatal("parser accepted unexpected size")
		}
		canonical, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal("accepted key cannot be serialized")
		}
		defer clear(canonical)
		if subtle.ConstantTimeCompare(payload, canonical) != 1 {
			t.Fatal("parser accepted noncanonical encoding")
		}
	})
}

// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

package clientwasm

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/mandipnotroot/anonce/internal/client/membercsr"
)

func request(t testing.TB) ([]byte, string) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	der, err := membercsr.Create(t.Context(), private)
	if err != nil {
		t.Fatal(err)
	}
	return der, "member:" + hex.EncodeToString(public) + "\n"
}

func TestWASMVerifyCSR(t *testing.T) {
	der, want := request(t)
	encoded := hex.EncodeToString(der)
	for _, input := range []string{encoded, strings.ToUpper(encoded)} {
		got, err := verifyHex(input)
		if err != nil || got != want {
			t.Fatalf("verification = %q, %v", got, err)
		}
	}
	var group sync.WaitGroup
	for range 8 {
		group.Go(func() {
			if got, err := verifyHex(encoded); err != nil || got != want {
				t.Error("concurrent verification failed")
			}
		})
	}
	group.Wait()
}

func TestWASMVerifyCSRRejectsInvalidInput(t *testing.T) {
	der, _ := request(t)
	encoded := hex.EncodeToString(der)
	cases := map[string]string{
		"empty": "", "short": encoded[:len(encoded)-1], "long": encoded + "00",
		"nonhex":  strings.Repeat("z", encodedRequestSize),
		"unicode": strings.Repeat("é", membercsr.DERSize),
		"zeros":   strings.Repeat("0", encodedRequestSize),
		"space":   " " + encoded[1:], "newline": encoded[:len(encoded)-1] + "\n",
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			if got, err := verifyHex(input); got != "" || !errors.Is(err, membercsr.ErrInvalidRequest) {
				t.Fatalf("invalid input returned %q, %v", got, err)
			}
		})
	}
	for i := range der {
		mutated := bytes.Clone(der)
		mutated[i] ^= 1
		if got, err := verifyHex(hex.EncodeToString(mutated)); got != "" || !errors.Is(err, membercsr.ErrInvalidRequest) {
			t.Fatalf("mutation %d accepted", i)
		}
	}
}

func TestWASMVerifyCSRForKey(t *testing.T) {
	der, want := request(t)
	encoded := hex.EncodeToString(der)
	expected := strings.TrimSuffix(strings.TrimPrefix(want, "member:"), "\n")
	for name, key := range map[string]string{"lowercase": expected, "uppercase": strings.ToUpper(expected)} {
		t.Run(name, func(t *testing.T) {
			for _, input := range []string{encoded, strings.ToUpper(encoded)} {
				if got, err := verifyHexForKey(input, key); err != nil || got != want {
					t.Fatalf("expected-key verification = %q, %v", got, err)
				}
			}
		})
	}
	public, err := hex.DecodeString(expected)
	if err != nil {
		t.Fatal(err)
	}
	for i := range public {
		changed := bytes.Clone(public)
		changed[i] ^= 1
		if got, err := verifyHexForKey(encoded, hex.EncodeToString(changed)); got != "" || !errors.Is(err, membercsr.ErrInvalidRequest) {
			t.Fatalf("key mismatch at byte %d returned output or unexpected error", i)
		}
	}
	var group sync.WaitGroup
	for range 8 {
		group.Go(func() {
			if got, err := verifyHexForKey(encoded, expected); err != nil || got != want {
				t.Error("concurrent expected-key verification failed")
			}
		})
	}
	group.Wait()
}

func TestWASMVerifyCSRForKeyRejectsInvalidInput(t *testing.T) {
	der, want := request(t)
	encoded := hex.EncodeToString(der)
	expected := strings.TrimSuffix(strings.TrimPrefix(want, "member:"), "\n")
	cases := map[string]string{
		"empty": "", "short": expected[:len(expected)-1], "long": expected + "00",
		"nonhex": strings.Repeat("z", 64), "unicode": strings.Repeat("é", 32),
		"space": " " + expected[1:], "newline": expected[:len(expected)-1] + "\n",
		"label": "member:" + expected, "oversized": strings.Repeat("0", 1024*1024),
	}
	for name, key := range cases {
		t.Run(name, func(t *testing.T) {
			if got, err := verifyHexForKey(encoded, key); got != "" || !errors.Is(err, membercsr.ErrInvalidRequest) {
				t.Fatal("invalid expected key returned output or unexpected error")
			}
		})
	}
	// A matching key must not admit a malformed profile or signature.
	for i := range der {
		mutated := bytes.Clone(der)
		mutated[i] ^= 1
		if got, err := verifyHexForKey(hex.EncodeToString(mutated), expected); got != "" || !errors.Is(err, membercsr.ErrInvalidRequest) {
			t.Fatalf("request mutation %d accepted with expected key", i)
		}
	}
	for _, input := range []string{"", encoded[:len(encoded)-1], encoded + "00", strings.Repeat("z", encodedRequestSize)} {
		if got, err := verifyHexForKey(input, expected); got != "" || !errors.Is(err, membercsr.ErrInvalidRequest) {
			t.Fatal("invalid request returned output or unexpected error with expected key")
		}
	}
}

func FuzzWASMExpectedKey(f *testing.F) {
	der, want := request(f)
	encoded := hex.EncodeToString(der)
	expected := strings.TrimSuffix(strings.TrimPrefix(want, "member:"), "\n")
	f.Add(encoded, expected)
	f.Add(strings.ToUpper(encoded), strings.ToUpper(expected))
	f.Add(encoded, strings.Repeat("0", 64))
	f.Add(encoded, "")
	f.Add("", expected)
	f.Add(encoded, strings.Repeat("z", 64))
	f.Fuzz(func(t *testing.T, input, key string) {
		if len(input) > encodedRequestSize+1 || len(key) > 2*ed25519.PublicKeySize+1 {
			return
		}
		got, err := verifyHexForKey(input, key)
		keyBytes, decodeErr := hex.DecodeString(key)
		ordinary, verifyErr := verifyHex(input)
		valid := decodeErr == nil && len(keyBytes) == ed25519.PublicKeySize && verifyErr == nil && ordinary == "member:"+hex.EncodeToString(keyBytes)+"\n"
		if valid {
			if err != nil || got != ordinary {
				t.Fatal("expected-key verification rejected a matching validated request")
			}
		} else if got != "" || !errors.Is(err, membercsr.ErrInvalidRequest) {
			t.Fatal("invalid input returned output or unexpected error")
		}
	})
}

func FuzzWASMRequest(f *testing.F) {
	der, _ := request(f)
	f.Add(hex.EncodeToString(der))
	f.Add("")
	f.Add(strings.Repeat("0", encodedRequestSize))
	f.Add(strings.Repeat("z", encodedRequestSize))
	f.Fuzz(func(t *testing.T, encoded string) {
		if len(encoded) > encodedRequestSize+1 {
			return
		}
		got, err := verifyHex(encoded)
		if err != nil {
			if got != "" || !errors.Is(err, membercsr.ErrInvalidRequest) {
				t.Fatal("invalid request returned output or unexpected error")
			}
			return
		}
		der, decodeErr := hex.DecodeString(encoded)
		if decodeErr != nil {
			t.Fatal(decodeErr)
		}
		public, parseErr := membercsr.Parse(der)
		if parseErr != nil || got != "member:"+hex.EncodeToString(public)+"\n" {
			t.Fatal("verification disagrees with shared parser")
		}
	})
}

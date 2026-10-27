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

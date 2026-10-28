//go:build wasmintegration && !js

// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

package clientwasm

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json/v2"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestClientNativeWASMCompatibility exchanges only fresh public requests and
// expected public results. No passwords or private fixtures cross the boundary.
func TestClientNativeWASMCompatibility(t *testing.T) {
	type vector struct {
		Input string `json:"input"`
		// Preserve present empty keys so malformed-key cases use the keyed method.
		Expected *string `json:"expected,omitzero"`
		Want     *string `json:"want"`
	}
	var vectors []vector
	for range 3 {
		der, want := request(t)
		encoded := hex.EncodeToString(der)
		expected := strings.TrimSuffix(strings.TrimPrefix(want, "member:"), "\n")
		for _, input := range []string{encoded, strings.ToUpper(encoded)} {
			vectors = append(vectors, vector{Input: input, Want: new(want)})
			for _, key := range []string{expected, strings.ToUpper(expected)} {
				vectors = append(vectors, vector{Input: input, Expected: new(key), Want: new(want)})
			}
		}
		public, err := hex.DecodeString(expected)
		if err != nil {
			t.Fatal(err)
		}
		for i := range public {
			changed := bytes.Clone(public)
			changed[i] ^= 1
			vectors = append(vectors, vector{Input: encoded, Expected: new(hex.EncodeToString(changed))})
		}
		for _, key := range []string{"", expected[:len(expected)-1], expected + "00", "member:" + expected, strings.Repeat("z", 64), strings.Repeat("é", 32), " " + expected[1:], expected[:len(expected)-1] + "\n"} {
			vectors = append(vectors, vector{Input: encoded, Expected: new(key)})
		}
		for i := range der {
			mutated := bytes.Clone(der)
			mutated[i] ^= 1
			vectors = append(vectors,
				vector{Input: hex.EncodeToString(mutated)},
				vector{Input: hex.EncodeToString(mutated), Expected: new(expected)},
			)
		}
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	claimed, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "synthetic test claim"},
	}, private)
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{"", "00", strings.Repeat("0", encodedRequestSize), strings.Repeat("z", encodedRequestSize), hex.EncodeToString(claimed)} {
		vectors = append(vectors, vector{Input: input}, vector{Input: input, Expected: new(hex.EncodeToString(public))})
	}
	for _, v := range vectors {
		got, err := verifyHex(v.Input)
		if v.Expected != nil {
			got, err = verifyHexForKey(v.Input, *v.Expected)
		}
		if v.Want == nil && (err == nil || got != "") || v.Want != nil && (err != nil || got != *v.Want) {
			t.Fatal("native result disagrees with expected profile result")
		}
	}
	data, err := json.Marshal(vectors)
	if err != nil {
		t.Fatal(err)
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "node", filepath.Join(root, "scripts/wasm_test.mjs"), filepath.Join(root, "bin/wasm"))
	cmd.Stdin = bytes.NewReader(data)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("WASM compatibility: %v\n%s", err, output)
	}
}

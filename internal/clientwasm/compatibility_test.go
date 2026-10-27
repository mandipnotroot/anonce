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
		Input string  `json:"input"`
		Want  *string `json:"want"`
	}
	var vectors []vector
	for range 3 {
		der, want := request(t)
		vectors = append(vectors, vector{hex.EncodeToString(der), new(want)}, vector{strings.ToUpper(hex.EncodeToString(der)), new(want)})
		for i := range der {
			mutated := bytes.Clone(der)
			mutated[i] ^= 1
			vectors = append(vectors, vector{Input: hex.EncodeToString(mutated)})
		}
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
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
		vectors = append(vectors, vector{Input: input})
	}
	for _, v := range vectors {
		got, err := verifyHex(v.Input)
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

//go:build wasmintegration && !js

// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

package memberwasm

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json/v2"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/mandipnotroot/anonce/internal/client/membercsr"
	"github.com/mandipnotroot/anonce/internal/client/memberkey"
	"github.com/mandipnotroot/anonce/internal/client/membersession"
)

// TestMemberNativeWASMCompatibility exchanges only encrypted backups, public
// material, and a synthetic test password. Private bytes never cross the bridge.
func TestMemberNativeWASMCompatibility(t *testing.T) {
	password := bytes.Repeat([]byte{0, 0xff, 'x', '\n'}, 256) // Synthetic maximum-length input.
	defer clear(password)
	var session membersession.Session
	defer session.Lock()
	setup, err := session.Create(t.Context(), password)
	if err != nil {
		t.Fatal(err)
	}
	input, err := json.Marshal(map[string]string{
		"password": hex.EncodeToString(password), "backup": hex.EncodeToString(setup.Backup),
		"publicKey": hex.EncodeToString(setup.PublicKey), "csr": hex.EncodeToString(setup.CSR),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(input)
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 180*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "node", filepath.Join(root, "scripts/member_wasm_test.mjs"), filepath.Join(root, "bin/memberwasm"))
	cmd.Stdin = bytes.NewReader(input)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("member WASM compatibility: %v\n%s", err, stderr.String())
	}
	var result struct {
		Backup    string `json:"backup"`
		PublicKey string `json:"publicKey"`
		CSR       string `json:"csr"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal("invalid WASM result encoding")
	}
	backup, err := hex.DecodeString(result.Backup)
	if err != nil {
		t.Fatal("invalid WASM backup encoding")
	}
	key, err := memberkey.Open(t.Context(), password, backup)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	request, err := hex.DecodeString(result.CSR)
	if err != nil {
		t.Fatal("invalid WASM CSR encoding")
	}
	public, err := membercsr.Parse(request)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(public) != result.PublicKey || !bytes.Equal(key[32:], public) {
		t.Fatal("native/WASM member-key or CSR mismatch")
	}
}

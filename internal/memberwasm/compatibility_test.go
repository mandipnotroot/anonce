//go:build (wasmintegration || browserintegration) && !js

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
	testMemberCompatibility(t, "member_wasm_test.mjs")
}

func TestMemberNativeWorkerCompatibility(t *testing.T) {
	testMemberCompatibility(t, "member_worker_integration.mjs")
}

func testMemberCompatibility(t *testing.T, script string, args ...string) {
	t.Helper()
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
	commandArgs := append([]string{filepath.Join(root, "scripts", script), filepath.Join(root, "bin/memberwasm")}, args...)
	cmd := exec.CommandContext(ctx, "node", commandArgs...)
	cmd.Stdin = bytes.NewReader(input)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("member WASM compatibility: %v\n%s", err, stderr.String())
	}
	var result struct {
		Backup       string `json:"backup"`
		PublicKey    string `json:"publicKey"`
		CSR          string `json:"csr"`
		BackupExport string `json:"backupExport"`
		TextBackup   string `json:"textBackup"`
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
	exported, err := hex.DecodeString(result.BackupExport)
	if err != nil || len(exported) != 108 {
		t.Fatal("invalid WASM backup export encoding")
	}
	replacement := bytes.Clone(password)
	defer clear(replacement)
	replacement[0] ^= 1
	restored, err := memberkey.Open(t.Context(), replacement, exported)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(restored)
	original, err := memberkey.Open(t.Context(), password, setup.Backup)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(original)
	if !bytes.Equal(restored, original) || bytes.Equal(exported[12:28], setup.Backup[12:28]) ||
		bytes.Equal(exported[32:44], setup.Backup[32:44]) {
		t.Fatal("WASM backup export changed the key or reused randomness")
	}
	if script != "member_wasm_test.mjs" {
		textBackup, err := hex.DecodeString(result.TextBackup)
		if err != nil || len(textBackup) != 108 {
			t.Fatal("invalid text-passphrase backup encoding")
		}
		textPassword := bytes.Repeat([]byte(" é😀\x00"), 128) // Synthetic 1024-byte UTF-8 input.
		defer clear(textPassword)
		textKey, err := memberkey.Open(t.Context(), textPassword, textBackup)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(textKey)
		if !bytes.Equal(textKey, original) {
			t.Fatal("text-passphrase export changed the member key")
		}
	}
}

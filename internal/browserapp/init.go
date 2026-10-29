// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

// Package browserapp provides operator-only local initialization and startup for
// two separate browser services. It is not imported by device code.
package browserapp

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/mandipnotroot/anonce/internal/browserhttp"
)

// Initialize never replaces an existing directory or file. All server private
// keys are local development files, not a production signing-key custody design.
func Initialize(directory string) error {
	if err := os.Mkdir(directory, 0o700); err != nil {
		return errors.New("create new browser state directory")
	}
	stateRoot, err := os.OpenRoot(directory)
	if err != nil {
		return errors.New("open new browser state directory")
	}
	defer func() { _ = stateRoot.Close() }()
	write := func(name string, data []byte) error {
		f, err := stateRoot.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return errors.New("create browser state file")
		}
		_, err = f.Write(data)
		closeErr := f.Close()
		if err != nil || closeErr != nil {
			return errors.New("write browser state file")
		}
		return nil
	}
	for _, side := range []string{"identity", "submission"} {
		if os.Mkdir(filepath.Join(directory, side), 0o700) != nil {
			return errors.New("create service state directory")
		}
	}
	now := time.Now().UTC().Truncate(time.Second)
	serial := func() *big.Int { b := make([]byte, 16); rand.Read(b); b[0] |= 1; return new(big.Int).SetBytes(b) }
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	root := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "Anonce local development trust root"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, &rootKey.PublicKey, rootKey)
	if err != nil {
		return errors.New("create local trust root")
	}
	if write("local-root.crt", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})) != nil {
		return errors.New("write local trust root")
	}
	for _, side := range []string{"identity", "submission"} {
		name := "identity.localhost"
		if side == "submission" {
			name = "submit.localhost"
		}
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		leaf := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(30 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		der, err := x509.CreateCertificate(rand.Reader, leaf, root, &key.PublicKey, rootKey)
		if err != nil {
			return errors.New("create local TLS certificate")
		}
		pk, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return errors.New("encode local TLS key")
		}
		if write(side+"/tls.crt", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})) != nil || write(side+"/tls.key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk})) != nil {
			clear(pk)
			return errors.New("write local TLS materials")
		}
		clear(pk)
	}
	var bulletinPublic, receiptPublic []byte
	for _, entry := range []struct{ side, name string }{{"identity", "membership"}, {"identity", "bulletin"}, {"submission", "receipt"}} {
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		seed := private.Seed()
		if write(entry.side+"/"+entry.name+".seed", seed) != nil {
			clear(seed)
			clear(private)
			return errors.New("write signing seed")
		}
		clear(seed)
		if entry.name == "membership" {
			ca := &x509.Certificate{SerialNumber: serial(), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(10 * 365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
			der, err := x509.CreateCertificate(rand.Reader, ca, ca, public, private)
			if err != nil || write("identity/membership.der", der) != nil {
				clear(private)
				return errors.New("write membership authority")
			}
		}
		if entry.name == "bulletin" {
			bulletinPublic = public
		}
		if entry.name == "receipt" {
			receiptPublic = public
		}
		clear(private)
	}
	if write("submission/bulletin.pub", bulletinPublic) != nil || write("identity/receipt.pub", receiptPublic) != nil {
		return errors.New("write public trust configuration")
	}
	invitation := browserhttp.Random()
	defer clear(invitation)
	if write("identity/administrator-invitation", []byte(browserhttp.Encode(invitation))) != nil {
		return errors.New("write administrator invitation")
	}
	return nil
}

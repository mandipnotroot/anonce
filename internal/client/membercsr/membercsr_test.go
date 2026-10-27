// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

package membercsr

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"sync"
	"testing"
)

func TestMemberCSRRoundTrip(t *testing.T) {
	t.Parallel()
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	original := bytes.Clone(key)
	defer clear(original)
	der, err := Create(t.Context(), key)
	if err != nil {
		t.Fatal(err)
	}
	request, err := x509.ParseCertificateRequest(der)
	if err != nil || request.CheckSignature() != nil || len(der) != DERSize {
		t.Fatal("library could not verify the profile request")
	}
	var raw certificateRequest
	if rest, err := asn1.Unmarshal(der, &raw); err != nil || len(rest) != 0 || len(raw.Info.Attributes) != 0 {
		t.Fatal("request contained attributes or malformed DER")
	}
	if request.Version != 0 || len(request.Subject.Names) != 0 || len(request.Extensions) != 0 {
		t.Fatal("request contained identity or extension claims")
	}
	if !ed25519.Verify(public, request.RawTBSCertificateRequest, request.Signature) {
		t.Fatal("request did not use pure Ed25519 over the request info")
	}
	got, err := Parse(der)
	if err != nil || !bytes.Equal(got, public) || !bytes.Equal(key, original) {
		t.Fatal("request changed the key or public bytes")
	}
	clear(got)
	again, err := Parse(der)
	if err != nil || !bytes.Equal(again, public) {
		t.Fatal("public output aliases the request")
	}
	repeated, err := Create(t.Context(), key)
	if err != nil || !bytes.Equal(der, repeated) {
		t.Fatal("fixed Ed25519 request was not deterministic")
	}
	clear(key)
	if _, err := Parse(der); err != nil {
		t.Fatal("request output aliases private input")
	}
}

func TestMemberCSRRejectsInvalidKeys(t *testing.T) {
	t.Parallel()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	inconsistent := bytes.Clone(key)
	defer clear(inconsistent)
	inconsistent[len(inconsistent)-1] ^= 1
	for _, tc := range []struct {
		name string
		key  ed25519.PrivateKey
	}{
		{"nil", nil},
		{"seed only", key[:ed25519.SeedSize]},
		{"truncated", key[:len(key)-1]},
		{"oversized", make([]byte, ed25519.PrivateKeySize+1)},
		{"inconsistent", inconsistent},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if der, err := Create(t.Context(), tc.key); !errors.Is(err, ErrInvalidKey) || der != nil {
				t.Fatal("invalid key produced a request")
			}
		})
	}
}

func TestMemberCSRRejectsInvalidRequests(t *testing.T) {
	t.Parallel()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	der, err := Create(t.Context(), key)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		template x509.CertificateRequest
	}{
		{"subject", x509.CertificateRequest{Subject: pkix.Name{CommonName: "synthetic member"}}},
		{"SAN", x509.CertificateRequest{DNSNames: []string{"invalid.example"}}},
		{"unknown extension", x509.CertificateRequest{ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Value: []byte{5, 0}}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			other, err := x509.CreateCertificateRequest(rand.Reader, &tc.template, key)
			if err != nil {
				t.Fatal(err)
			}
			if public, err := Parse(other); !errors.Is(err, ErrInvalidRequest) || public != nil {
				t.Fatal("accepted a signed request outside the profile")
			}
		})
	}
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherAlgorithm, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, otherKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		der  []byte
	}{
		{"empty", nil},
		{"truncated", der[:len(der)-1]},
		{"trailing", append(bytes.Clone(der), 0)},
		{"oversized", make([]byte, DERSize+1)},
		{"wrong algorithm", otherAlgorithm},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if public, err := Parse(tc.der); !errors.Is(err, ErrInvalidRequest) || public != nil {
				t.Fatal("invalid request produced public output")
			}
		})
	}
	// A valid signature is not enough: a different request version still has
	// exactly the profile size and must be rejected independently of the signature.
	var alternate certificateRequest
	if rest, err := asn1.Unmarshal(der, &alternate); err != nil || len(rest) != 0 {
		t.Fatal("could not decode generated request")
	}
	alternate.Info.Version = 1
	info, err := asn1.Marshal(alternate.Info)
	if err != nil {
		t.Fatal(err)
	}
	alternate.Signature.Bytes = ed25519.Sign(key, info)
	nonzeroVersion, err := asn1.Marshal(alternate)
	if err != nil || len(nonzeroVersion) != DERSize {
		t.Fatal("could not construct same-size alternate request")
	}
	if !ed25519.Verify(key.Public().(ed25519.PublicKey), info, alternate.Signature.Bytes) {
		t.Fatal("alternate request signature is invalid")
	}
	if public, err := Parse(nonzeroVersion); !errors.Is(err, ErrInvalidRequest) || public != nil {
		t.Fatal("accepted a signed request with a nonzero version")
	}
	// Include an attribute outside x509's extension view without using its
	// deprecated attribute-construction API.
	attribute, err := asn1.Marshal(struct {
		Type   asn1.ObjectIdentifier
		Values []string `asn1:"set"`
	}{asn1.ObjectIdentifier{1, 2, 3, 4}, []string{"synthetic"}})
	if err != nil {
		t.Fatal(err)
	}
	alternate.Info.Version = 0
	alternate.Info.Attributes = []asn1.RawValue{{FullBytes: attribute}}
	info, err = asn1.Marshal(alternate.Info)
	if err != nil {
		t.Fatal(err)
	}
	alternate.Signature.Bytes = ed25519.Sign(key, info)
	withAttribute, err := asn1.Marshal(alternate)
	if err != nil {
		t.Fatal(err)
	}
	if public, err := Parse(withAttribute); !errors.Is(err, ErrInvalidRequest) || public != nil {
		t.Fatal("accepted a signed request with an unknown attribute")
	}
	// Every one-byte mutation, including all public/signature bytes and lengths,
	// must fail. This also covers same-size changes to version and identifiers.
	for i := range der {
		mutated := bytes.Clone(der)
		mutated[i] ^= 1
		if public, err := Parse(mutated); !errors.Is(err, ErrInvalidRequest) || public != nil {
			t.Fatalf("accepted mutation at byte %d", i)
		}
	}
}

func TestMemberCSRCancellation(t *testing.T) {
	t.Parallel()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	for _, at := range []int{1, 2} {
		ctx := &cancelContext{Context: t.Context(), at: at}
		if der, err := Create(ctx, key); !errors.Is(err, context.Canceled) || der != nil {
			t.Fatal("cancelled request returned output")
		}
	}
}

type cancelContext struct {
	context.Context
	at, checks int
}

func (c *cancelContext) Err() error {
	c.checks++
	if c.checks >= c.at {
		return context.Canceled
	}
	return nil
}

func TestMemberCSRConcurrent(t *testing.T) {
	t.Parallel()
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			der, err := Create(t.Context(), key)
			if err != nil {
				t.Error(err)
				return
			}
			got, err := Parse(der)
			if err != nil || !bytes.Equal(got, public) {
				t.Error("concurrent request did not verify")
			}
		})
	}
	wg.Wait()
}

func FuzzMemberCSR(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x30, 0x7f})
	f.Add(make([]byte, DERSize))
	// Only a public request enters the corpus, never private key material.
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	der, err := Create(f.Context(), key)
	clear(key)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(der)
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > DERSize+1 {
			return
		}
		public, err := Parse(data)
		if err != nil {
			if public != nil || !errors.Is(err, ErrInvalidRequest) {
				t.Fatal("failed parse returned output or unexpected error")
			}
			return
		}
		request, err := x509.ParseCertificateRequest(data)
		if err != nil || request.CheckSignature() != nil || len(public) != ed25519.PublicKeySize {
			t.Fatal("accepted request without a valid library signature")
		}
	})
}

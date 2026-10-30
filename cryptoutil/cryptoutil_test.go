package cryptoutil

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"math/big"
	"testing"
)

// TestGenerateSubjectKeyID compares the identifier with the one crypto/x509 puts in a certificate
// that has none, which follows the same RFC 7093 method.
func TestGenerateSubjectKeyID(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name string
		key  crypto.Signer
	}{
		{"RSA", rsaKey},
		{"ECDSA", ecdsaKey},
		{"Ed25519", edKey},
	} {
		t.Run(tt.name, func(t *testing.T) {
			template := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true}
			der, err := x509.CreateCertificate(rand.Reader, template, template, tt.key.Public(), tt.key)
			if err != nil {
				t.Fatal(err)
			}
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				t.Fatal(err)
			}
			ski, err := GenerateSubjectKeyID(tt.key.Public())
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(ski, cert.SubjectKeyId) {
				t.Fatalf("got % X, crypto/x509 derived % X", ski, cert.SubjectKeyId)
			}
		})
	}
	if _, err := GenerateSubjectKeyID(struct{}{}); err == nil {
		t.Fatal("an unknown key type was accepted")
	}
}

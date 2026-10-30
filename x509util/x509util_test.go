package x509util

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
)

func TestCreateCertificateRequest(t *testing.T) {
	r := rand.Reader
	priv, err := rsa.GenerateKey(r, 1024)
	if err != nil {
		t.Fatal(err)
	}

	template := CertificateRequest{
		Subject: pkix.Name{
			CommonName: "test.acme.co",
			Country:    []string{"US"},
		},
		ChallengePassword: "foobar",
	}

	derBytes, err := CreateCertificateRequest(r, &template, priv)
	if err != nil {
		t.Fatal(err)
	}

	out, err := x509.ParseCertificateRequest(derBytes)
	if err != nil {
		t.Fatalf("failed to create certificate request: %s", err)
	}

	if err := out.CheckSignature(); err != nil {
		t.Errorf("failed to check certificate request signature: %s", err)
	}

	challenge, err := ParseChallengePassword(derBytes)
	if err != nil {
		t.Fatalf("failed to parse challengePassword attribute: %s", err)
	}

	if have, want := challenge, template.ChallengePassword; have != want {
		t.Errorf("have %s, want %s", have, want)
	}
}

// TestCreateCertificateRequestSignatureAlgorithm checks that a request with a challenge password is
// signed with the requested algorithm, including SHA-1, which older SCEP servers expect, and RSA-PSS.
func TestCreateCertificateRequestSignatureAlgorithm(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		key  crypto.Signer
		algo x509.SignatureAlgorithm
	}{
		{rsaKey, x509.SHA1WithRSA},
		{rsaKey, x509.SHA256WithRSA},
		{rsaKey, x509.SHA512WithRSA},
		{rsaKey, x509.SHA256WithRSAPSS},
		{rsaKey, x509.SHA512WithRSAPSS},
		{ecKey, x509.ECDSAWithSHA1},
		{ecKey, x509.ECDSAWithSHA384},
	}
	for _, tt := range tests {
		template := CertificateRequest{
			Subject:            pkix.Name{CommonName: "device"},
			SignatureAlgorithm: tt.algo,
			ChallengePassword:  "foobar",
		}
		der, err := CreateCertificateRequest(rand.Reader, &template, tt.key)
		if err != nil {
			t.Errorf("%v: %v", tt.algo, err)
			continue
		}
		csr, err := x509.ParseCertificateRequest(der)
		if err != nil {
			t.Errorf("%v: %v", tt.algo, err)
			continue
		}
		if csr.SignatureAlgorithm != tt.algo {
			t.Errorf("signed with %v, want %v", csr.SignatureAlgorithm, tt.algo)
		}
		if err := csr.CheckSignature(); err != nil {
			t.Errorf("%v: %v", tt.algo, err)
		}
	}
}

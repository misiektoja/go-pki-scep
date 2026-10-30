package scep

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"

	"github.com/misiektoja/go-pkcs7"
)

// DegenerateCertificates encodes certificates as a certificate-only SignedData, the body of a
// GetCACert response that carries more than one certificate.
func DegenerateCertificates(certs []*x509.Certificate) ([]byte, error) {
	if len(certs) == 0 {
		return nil, errors.New("scep: no certificates to encode")
	}
	var buf bytes.Buffer
	for _, cert := range certs {
		buf.Write(cert.Raw)
	}
	return pkcs7.DegenerateCertificate(buf.Bytes())
}

// CACerts returns the certificates of a certificate-only SignedData, such as a GetCACert or
// GetNextCACert response body.
func CACerts(data []byte) ([]*x509.Certificate, error) {
	p7, err := pkcs7.Parse(data)
	if err != nil {
		return nil, err
	}
	if len(p7.Certificates) == 0 {
		return nil, errors.New("scep: the message carries no certificates")
	}
	return p7.Certificates, nil
}

// SignedCertificates encodes certs as a SignedData that the current CA or RA signs, the body of a
// GetNextCACert response (RFC 8894 section 4.7). The message carries certs only. The requester
// already holds the signer certificate from GetCACert. A zero digest selects SHA-256.
func SignedCertificates(certs []*x509.Certificate, signerCert *x509.Certificate, signerKey crypto.Signer, digest crypto.Hash) ([]byte, error) {
	if len(certs) == 0 {
		return nil, errors.New("scep: no certificates to encode")
	}
	if signerCert == nil || signerKey == nil {
		return nil, errors.New("scep: signing certificates needs a signer certificate and key")
	}
	if digest == 0 {
		digest = crypto.SHA256
	}
	oid, ok := digestAlgorithms[digest]
	if !ok {
		return nil, fmt.Errorf("scep: unsupported digest %v", digest)
	}
	sd, err := pkcs7.NewSignedData(nil)
	if err != nil {
		return nil, err
	}
	sd.SetDigestAlgorithm(oid)
	if err := sd.AddSigner(signerCert, signerKey, pkcs7.SignerInfoConfig{}); err != nil {
		return nil, fmt.Errorf("scep: sign certificates: %w", err)
	}
	sd.RemoveCertificates()
	for _, cert := range certs {
		sd.AddCertificate(cert)
	}
	return sd.Finish()
}

// ParseSignedCertificates verifies a GetNextCACert response against signers, the current CA or RA
// certificates from GetCACert, and returns the certificates it announces.
func ParseSignedCertificates(data []byte, signers []*x509.Certificate) ([]*x509.Certificate, error) {
	if len(signers) == 0 {
		return nil, errors.New("scep: verifying signed certificates needs the current CA or RA certificates")
	}
	p7, err := pkcs7.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("scep: parse signed certificates: %w", err)
	}
	if len(p7.Signers) != 1 {
		return nil, fmt.Errorf("scep: signed certificates have %d signers, want 1", len(p7.Signers))
	}
	// Only the expected signers take part in the check, so a carried certificate cannot stand in
	// for them.
	carried := p7.Certificates
	p7.Certificates = nil
	if err := p7.Verify(pkcs7.VerifyOptions{SignerCertificates: signers}); err != nil {
		return nil, fmt.Errorf("scep: verify signed certificates: %w", err)
	}
	var announced []*x509.Certificate
	for _, cert := range carried {
		if !slices.ContainsFunc(signers, cert.Equal) {
			announced = append(announced, cert)
		}
	}
	if len(announced) == 0 {
		return nil, errors.New("scep: the signed message announces no certificates")
	}
	return announced, nil
}

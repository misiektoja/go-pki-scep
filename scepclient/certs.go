package scepclient

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"slices"
)

// CACertificates is a GetCACert answer sorted by role.
type CACertificates struct {
	// All holds every certificate of the answer in the order the server sent them.
	All []*x509.Certificate

	// CA is the certificate of the CA that issues the requested certificates. CertPoll, GetCert
	// and GetCRL name it as the issuer.
	CA *x509.Certificate

	// Recipients are the certificates requests are encrypted for: the RSA RA certificates that
	// allow key encipherment when an RA has one, else the CA certificate when its key is RSA. It
	// is empty when no certificate has an RSA key, because SCEP encrypts with RSA key transport.
	Recipients []*x509.Certificate

	// Signers are the certificates allowed to sign CertRep messages: the RA certificates that
	// allow digital signatures and the CA certificate. A CertRep signed by any other key is
	// refused.
	Signers []*x509.Certificate
}

// SortCACertificates sorts the certificates of a GetCACert answer by role. A caller that pins the
// CA certificates instead of fetching them uses it too. Certificates without the CA flag are RA
// certificates. The issuing CA is the CA certificate that issued the RA certificates, or else the
// CA certificate that issued none of the other CA certificates.
func SortCACertificates(certs []*x509.Certificate) (*CACertificates, error) {
	if len(certs) == 0 {
		return nil, errors.New("scepclient: no CA certificates")
	}
	var cas, ras []*x509.Certificate
	for _, cert := range certs {
		if cert.BasicConstraintsValid && cert.IsCA {
			cas = append(cas, cert)
		} else {
			ras = append(ras, cert)
		}
	}
	if len(cas) == 0 {
		if len(certs) > 1 {
			return nil, errors.New("scepclient: the answer holds several certificates and none is a CA certificate")
		}
		// Some CAs send a single certificate without basic constraints.
		cas, ras = certs, nil
	}

	var issuing *x509.Certificate
	for _, ca := range cas {
		if slices.ContainsFunc(ras, func(ra *x509.Certificate) bool { return issuedBy(ra, ca) }) {
			issuing = ca
			break
		}
	}
	if issuing == nil {
		for _, ca := range cas {
			if !slices.ContainsFunc(cas, func(other *x509.Certificate) bool { return other != ca && issuedBy(other, ca) }) {
				issuing = ca
				break
			}
		}
	}
	if issuing == nil {
		issuing = cas[0]
	}

	sorted := &CACertificates{All: certs, CA: issuing}
	for _, ra := range ras {
		encipherment := ra.KeyUsage == 0 || ra.KeyUsage&(x509.KeyUsageKeyEncipherment|x509.KeyUsageDataEncipherment) != 0
		if encipherment && hasRSAKey(ra) {
			sorted.Recipients = append(sorted.Recipients, ra)
		}
		if ra.KeyUsage == 0 || ra.KeyUsage&x509.KeyUsageDigitalSignature != 0 {
			sorted.Signers = append(sorted.Signers, ra)
		}
	}
	if len(sorted.Recipients) == 0 && hasRSAKey(issuing) {
		sorted.Recipients = []*x509.Certificate{issuing}
	}
	sorted.Signers = append(sorted.Signers, issuing)
	return sorted, nil
}

// hasRSAKey reports whether cert holds an RSA public key.
func hasRSAKey(cert *x509.Certificate) bool {
	_, ok := cert.PublicKey.(*rsa.PublicKey)
	return ok
}

// issuedBy reports whether issuer's name and key identifier match those cert names as its issuer.
// It compares names rather than signatures, because Go refuses SHA-1 certificate signatures that
// older CAs still carry.
func issuedBy(cert, issuer *x509.Certificate) bool {
	if !bytes.Equal(cert.RawIssuer, issuer.RawSubject) {
		return false
	}
	return len(cert.AuthorityKeyId) == 0 || len(issuer.SubjectKeyId) == 0 ||
		bytes.Equal(cert.AuthorityKeyId, issuer.SubjectKeyId)
}

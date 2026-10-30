// Package cryptoutil derives key identifiers for SCEP transaction identifiers.
package cryptoutil

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
)

// GenerateSubjectKeyID returns the leftmost 160 bits of the SHA-256 hash of the subjectPublicKey
// bits, method 1 of RFC 7093 section 2. It accepts every key type crypto/x509 can encode.
func GenerateSubjectKeyID(pub crypto.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("cryptoutil: encode public key: %w", err)
	}
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	rest, err := asn1.Unmarshal(der, &spki)
	if err != nil {
		return nil, fmt.Errorf("cryptoutil: decode public key: %w", err)
	}
	if len(rest) != 0 {
		return nil, errors.New("cryptoutil: trailing data after the public key")
	}
	hash := sha256.Sum256(spki.PublicKey.Bytes)
	return hash[:20], nil
}

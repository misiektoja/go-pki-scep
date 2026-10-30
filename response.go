package scep

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/misiektoja/go-pkcs7"
)

// ResponseOptions holds what a CertRep needs: who signs it and the algorithms.
type ResponseOptions struct {
	// SignerCertificate and SignerKey sign the response. They belong to the CA or to its RA, the
	// certificate a requester trusts from GetCACert.
	SignerCertificate *x509.Certificate
	SignerKey         crypto.Signer

	// Certificates are carried next to the signer certificate, such as the CA certificate when an
	// RA signs.
	Certificates []*x509.Certificate

	// Digest is the signature digest. The zero value follows the request when it used SHA-1,
	// SHA-256, SHA-384 or SHA-512, or MD5 when the request was signed with MD5, and selects SHA-256
	// otherwise, so a requester gets a digest it can check.
	Digest crypto.Hash

	// ContentEncryption is the cipher of the response pkiEnvelope. The zero value follows the
	// request, or AES-128-CBC when the request envelope was not decrypted.
	ContentEncryption pkcs7.ContentEncryptionAlgorithm
}

// Success answers an enrollment, CertPoll or GetCert with certificates. certs holds the issued or
// requested certificate first and may add its chain. The certificates are encrypted for the
// request signer certificate.
func (msg *PKIMessage) Success(certs []*x509.Certificate, opts ResponseOptions) (*PKIMessage, error) {
	if !msg.MessageType.isEnrollment() && msg.MessageType != CertPoll && msg.MessageType != GetCert {
		return nil, fmt.Errorf("scep: %s is not answered with certificates", msg.MessageType)
	}
	if len(certs) == 0 {
		return nil, errors.New("scep: a SUCCESS response needs at least one certificate")
	}
	var chain bytes.Buffer
	for _, cert := range certs {
		chain.Write(cert.Raw)
	}
	degenerate, err := pkcs7.DegenerateCertificate(chain.Bytes())
	if err != nil {
		return nil, fmt.Errorf("scep: encode response certificates: %w", err)
	}
	rep, err := msg.respond(SUCCESS, "", degenerate, opts)
	if err != nil {
		return nil, err
	}
	rep.CertRepMessage.Certificates = certs
	return rep, nil
}

// SuccessCRL answers a GetCRL with a DER encoded CRL, encrypted for the request signer certificate.
func (msg *PKIMessage) SuccessCRL(crl []byte, opts ResponseOptions) (*PKIMessage, error) {
	if msg.MessageType != GetCRL {
		return nil, fmt.Errorf("scep: %s is not answered with a CRL", msg.MessageType)
	}
	degenerate, err := pkcs7.DegenerateCRL(crl)
	if err != nil {
		return nil, fmt.Errorf("scep: encode response CRL: %w", err)
	}
	rep, err := msg.respond(SUCCESS, "", degenerate, opts)
	if err != nil {
		return nil, err
	}
	rep.CRL = crl
	return rep, nil
}

// Pending answers an enrollment or CertPoll whose certificate is not issued yet, for example
// while an operator approves it. The requester then polls with CertPoll.
func (msg *PKIMessage) Pending(opts ResponseOptions) (*PKIMessage, error) {
	if !msg.MessageType.isEnrollment() && msg.MessageType != CertPoll {
		return nil, fmt.Errorf("scep: %s cannot be answered with PENDING", msg.MessageType)
	}
	return msg.respond(PENDING, "", nil, opts)
}

// Fail answers any request with a FAILURE and the reason info.
func (msg *PKIMessage) Fail(info FailInfo, opts ResponseOptions) (*PKIMessage, error) {
	if !info.valid() {
		return nil, fmt.Errorf("scep: %s", info)
	}
	if msg.MessageType == CertRep {
		return nil, errors.New("scep: a CertRep is not answered")
	}
	return msg.respond(FAILURE, info, nil, opts)
}

// respond builds a CertRep for the request. A non-nil content is encrypted for the request
// signer certificate.
func (msg *PKIMessage) respond(status PKIStatus, info FailInfo, content []byte, opts ResponseOptions) (*PKIMessage, error) {
	if opts.SignerCertificate == nil || opts.SignerKey == nil {
		return nil, errors.New("scep: the response needs a signer certificate and key")
	}
	var envelope []byte
	if content != nil {
		if msg.SignerCertificate == nil {
			return nil, errors.New("scep: the request has no signer certificate to encrypt the response for")
		}
		cipher := opts.ContentEncryption
		if cipher == 0 {
			cipher = msg.ContentEncryption
		}
		var err error
		recipients := []*x509.Certificate{msg.SignerCertificate}
		envelope, err = pkcs7.Encrypt(content, recipients, pkcs7.EncryptOptions{ContentEncryption: cipher})
		if err != nil {
			return nil, fmt.Errorf("scep: encrypt response pkiEnvelope: %w", err)
		}
	}
	nonce := newNonce()
	attrs := []pkcs7.Attribute{
		{Type: oidSCEPtransactionID, Value: string(msg.TransactionID)},
		{Type: oidSCEPmessageType, Value: string(CertRep)},
		{Type: oidSCEPpkiStatus, Value: string(status)},
		{Type: oidSCEPsenderNonce, Value: []byte(nonce)},
		{Type: oidSCEPrecipientNonce, Value: []byte(msg.SenderNonce)},
	}
	if status == FAILURE {
		attrs = append(attrs, pkcs7.Attribute{Type: oidSCEPfailInfo, Value: string(info)})
	}
	digest := msg.responseDigest(opts.Digest)
	raw, digest, err := signMessage(envelope, opts.SignerCertificate, opts.SignerKey, digest, opts.Certificates, attrs)
	if err != nil {
		return nil, err
	}
	return &PKIMessage{
		TransactionID:     msg.TransactionID,
		MessageType:       CertRep,
		SenderNonce:       nonce,
		Raw:               raw,
		SignerCertificate: opts.SignerCertificate,
		Digest:            digest,
		CertRepMessage: &CertRepMessage{
			PKIStatus:      status,
			FailInfo:       info,
			RecipientNonce: RecipientNonce(msg.SenderNonce),
		},
	}, nil
}

// responseDigest picks the response digest: the configured one, else the request digest when
// the requester can check it, else SHA-256.
func (msg *PKIMessage) responseDigest(configured crypto.Hash) crypto.Hash {
	if configured != 0 {
		return configured
	}
	switch msg.Digest {
	case crypto.MD5, crypto.SHA1, crypto.SHA256, crypto.SHA384, crypto.SHA512:
		return msg.Digest
	default:
		return crypto.SHA256
	}
}

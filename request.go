package scep

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	"github.com/misiektoja/go-pkcs7"

	"github.com/misiektoja/go-scep/cryptoutil"
)

// RequestOptions holds what every request needs: who signs it, who it is encrypted for and the
// algorithms.
type RequestOptions struct {
	// Recipients are the CA or RA certificates the pkiEnvelope is encrypted for, usually the
	// encryption certificate from GetCACert.
	Recipients []*x509.Certificate

	// SignerCertificate and SignerKey sign the request. A PKCSReq is signed with a self-signed
	// certificate for the CSR key, a RenewalReq with the certificate being renewed. CertPoll,
	// GetCert and GetCRL use the same certificate as the enrollment they follow.
	SignerCertificate *x509.Certificate
	SignerKey         crypto.Signer

	// TransactionID identifies the transaction. CertPoll needs the identifier of the enrollment
	// it polls for. When empty, NewCSRRequest derives one from the CSR key and the other
	// functions pick a random one.
	TransactionID TransactionID

	// Digest is the signature digest. The zero value selects SHA-256.
	Digest crypto.Hash

	// Encryption selects the content cipher and the key transport. The zero value selects
	// AES-128-CBC with PKCS #1 v1.5 key transport.
	Encryption pkcs7.EncryptOptions
}

// NewCSRRequest builds a PKCSReq, RenewalReq or UpdateReq message for csr.
func NewCSRRequest(messageType MessageType, csr *x509.CertificateRequest, opts RequestOptions) (*PKIMessage, error) {
	if !messageType.isEnrollment() {
		return nil, fmt.Errorf("scep: %s does not carry a CSR", messageType)
	}
	if csr == nil {
		return nil, errors.New("scep: the request needs a CSR")
	}
	if opts.TransactionID == "" {
		id, err := CSRTransactionID(csr)
		if err != nil {
			return nil, err
		}
		opts.TransactionID = id
	}
	msg, err := newRequest(messageType, csr.Raw, opts)
	if err != nil {
		return nil, err
	}
	msg.CSRReqMessage = &CSRReqMessage{CSR: csr}
	return msg, nil
}

// CSRTransactionID derives the transactionID that NewCSRRequest uses when none is set: the hex
// encoded key identifier of the CSR public key. A requester that polls later can derive it again.
func CSRTransactionID(csr *x509.CertificateRequest) (TransactionID, error) {
	if csr == nil {
		return "", errors.New("scep: deriving a transactionID needs a CSR")
	}
	id, err := cryptoutil.GenerateSubjectKeyID(csr.PublicKey)
	if err != nil {
		return "", fmt.Errorf("scep: derive transactionID: %w", err)
	}
	return TransactionID(hex.EncodeToString(id)), nil
}

// NewCertPollRequest builds a CertPoll for the enrollment opts.TransactionID names. issuer is the
// DER encoded subject of the CA, subject the DER encoded subject of the CSR.
func NewCertPollRequest(issuer, subject []byte, opts RequestOptions) (*PKIMessage, error) {
	if opts.TransactionID == "" {
		return nil, errors.New("scep: CertPoll needs the transactionID of the enrollment")
	}
	content, err := asn1.Marshal(issuerAndSubject{
		Issuer:  asn1.RawValue{FullBytes: issuer},
		Subject: asn1.RawValue{FullBytes: subject},
	})
	if err != nil {
		return nil, fmt.Errorf("scep: encode issuerAndSubject: %w", err)
	}
	msg, err := newRequest(CertPoll, content, opts)
	if err != nil {
		return nil, err
	}
	msg.PollRequest = &IssuerAndSubject{Issuer: issuer, Subject: subject}
	return msg, nil
}

// NewGetCertRequest builds a GetCert for the certificate that issuer issued with serial.
func NewGetCertRequest(issuer []byte, serial *big.Int, opts RequestOptions) (*PKIMessage, error) {
	return newIssuerAndSerialRequest(GetCert, issuer, serial, opts)
}

// NewGetCRLRequest builds a GetCRL for the CRL that covers the certificate issuer issued with
// serial.
func NewGetCRLRequest(issuer []byte, serial *big.Int, opts RequestOptions) (*PKIMessage, error) {
	return newIssuerAndSerialRequest(GetCRL, issuer, serial, opts)
}

// newIssuerAndSerialRequest builds a GetCert or GetCRL message.
func newIssuerAndSerialRequest(messageType MessageType, issuer []byte, serial *big.Int, opts RequestOptions) (*PKIMessage, error) {
	if serial == nil {
		return nil, fmt.Errorf("scep: %s needs a serial number", messageType)
	}
	content, err := asn1.Marshal(issuerAndSerial{Issuer: asn1.RawValue{FullBytes: issuer}, SerialNumber: serial})
	if err != nil {
		return nil, fmt.Errorf("scep: encode issuerAndSerialNumber: %w", err)
	}
	msg, err := newRequest(messageType, content, opts)
	if err != nil {
		return nil, err
	}
	msg.CertificateID = &IssuerAndSerial{Issuer: issuer, SerialNumber: serial}
	return msg, nil
}

// newRequest encrypts content for the recipients and signs it with the request attributes.
func newRequest(messageType MessageType, content []byte, opts RequestOptions) (*PKIMessage, error) {
	if len(opts.Recipients) == 0 {
		return nil, errors.New("scep: the request needs at least one CA or RA recipient")
	}
	if opts.SignerCertificate == nil || opts.SignerKey == nil {
		return nil, errors.New("scep: the request needs a signer certificate and key")
	}
	if opts.TransactionID == "" {
		id := make([]byte, 16)
		_, _ = rand.Read(id)
		opts.TransactionID = TransactionID(hex.EncodeToString(id))
	}
	envelope, err := pkcs7.Encrypt(content, opts.Recipients, opts.Encryption)
	if err != nil {
		return nil, fmt.Errorf("scep: encrypt pkiEnvelope: %w", err)
	}
	nonce := newNonce()
	raw, digest, err := signMessage(envelope, opts.SignerCertificate, opts.SignerKey, opts.Digest, nil, []pkcs7.Attribute{
		{Type: oidSCEPtransactionID, Value: string(opts.TransactionID)},
		{Type: oidSCEPmessageType, Value: string(messageType)},
		{Type: oidSCEPsenderNonce, Value: []byte(nonce)},
	})
	if err != nil {
		return nil, err
	}
	contentEncryption := opts.Encryption.ContentEncryption
	if contentEncryption == 0 {
		contentEncryption = pkcs7.AES128CBC
	}
	return &PKIMessage{
		TransactionID:     opts.TransactionID,
		MessageType:       messageType,
		SenderNonce:       nonce,
		Raw:               raw,
		SignerCertificate: opts.SignerCertificate,
		Certificates:      []*x509.Certificate{opts.SignerCertificate},
		Digest:            digest,
		ContentEncryption: contentEncryption,
		Recipients:        opts.Recipients,
	}, nil
}

// signMessage signs content with the SCEP attributes. A zero digest selects SHA-256. extra
// certificates are carried next to the signer certificate.
func signMessage(content []byte, cert *x509.Certificate, key crypto.Signer, digest crypto.Hash, extra []*x509.Certificate, attrs []pkcs7.Attribute) ([]byte, crypto.Hash, error) {
	if digest == 0 {
		digest = crypto.SHA256
	}
	oid, ok := digestAlgorithms[digest]
	if !ok {
		return nil, 0, fmt.Errorf("scep: unsupported digest %v", digest)
	}
	sd, err := pkcs7.NewSignedData(content)
	if err != nil {
		return nil, 0, err
	}
	sd.SetDigestAlgorithm(oid)
	if err := sd.AddSigner(cert, key, pkcs7.SignerInfoConfig{ExtraSignedAttributes: attrs}); err != nil {
		return nil, 0, fmt.Errorf("scep: sign pkiMessage: %w", err)
	}
	for _, c := range extra {
		if !c.Equal(cert) {
			sd.AddCertificate(c)
		}
	}
	raw, err := sd.Finish()
	if err != nil {
		return nil, 0, fmt.Errorf("scep: encode pkiMessage: %w", err)
	}
	return raw, digest, nil
}

// newNonce returns a random 16-byte nonce. crypto/rand.Read does not fail.
func newNonce() SenderNonce {
	nonce := make([]byte, 16)
	_, _ = rand.Read(nonce)
	return nonce
}

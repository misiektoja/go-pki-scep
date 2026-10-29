package scep

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"slices"

	"github.com/misiektoja/go-pkcs7"

	"github.com/misiektoja/go-scep/x509util"
)

// PKIMessage is a parsed or built SCEP pkiMessage.
type PKIMessage struct {
	TransactionID TransactionID
	MessageType   MessageType

	// SenderNonce is required in requests. Some CA products leave it out of CertRep messages.
	SenderNonce SenderNonce

	// CertRepMessage is set on CertRep messages.
	*CertRepMessage

	// CSRReqMessage is set on PKCSReq, RenewalReq and UpdateReq messages once their pkiEnvelope
	// is decrypted, and on built requests.
	*CSRReqMessage

	// PollRequest is set on CertPoll messages once their pkiEnvelope is decrypted.
	PollRequest *IssuerAndSubject

	// CertificateID is set on GetCert and GetCRL messages once their pkiEnvelope is decrypted.
	CertificateID *IssuerAndSerial

	// Raw is the DER encoded pkiMessage.
	Raw []byte

	// SignerCertificate is the certificate that signed the message. A responder encrypts its
	// answer for it.
	SignerCertificate *x509.Certificate

	// Certificates are the certificates carried in the SignedData, which usually include the
	// signer certificate.
	Certificates []*x509.Certificate

	// Digest is the digest algorithm of the signature.
	Digest crypto.Hash

	// ContentEncryption is the content cipher of the pkiEnvelope once it is decrypted. A responder
	// answers with the same cipher.
	ContentEncryption pkcs7.ContentEncryptionAlgorithm

	// Recipients are the CA or RA certificates a built request is encrypted for.
	Recipients []*x509.Certificate

	p7       *pkcs7.PKCS7
	envelope *pkcs7.PKCS7
}

// CertRepMessage holds the CertRep attributes and, once the pkiEnvelope of a SUCCESS response is
// decrypted, its certificates or CRL.
type CertRepMessage struct {
	PKIStatus
	RecipientNonce
	FailInfo

	// Certificates are the certificates of a SUCCESS response, such as the issued certificate and
	// its chain. Their order is the order the responder sent.
	Certificates []*x509.Certificate

	// CRL is the DER encoded CRL of a SUCCESS response to GetCRL.
	CRL []byte
}

// CSRReqMessage holds the CSR of a PKCSReq, RenewalReq or UpdateReq.
type CSRReqMessage struct {
	// RawDecrypted is the decrypted pkiEnvelope, the DER encoded CSR.
	RawDecrypted []byte

	// CSR is the parsed certificate request.
	CSR *x509.CertificateRequest

	// ChallengePassword is the challengePassword attribute of the CSR, or empty.
	ChallengePassword string
}

// IssuerAndSubject is the content of a CertPoll: the name of the CA and the subject of the CSR
// whose certificate the requester waits for (RFC 8894 section 3.3.3).
type IssuerAndSubject struct {
	// Issuer is the DER encoded name of the CA.
	Issuer []byte
	// Subject is the DER encoded subject of the CSR.
	Subject []byte
}

// IssuerAndSerial is the content of GetCert and GetCRL: a certificate identified by its issuer
// name and serial number (RFC 8894 sections 3.3.4 and 3.3.5).
type IssuerAndSerial struct {
	// Issuer is the DER encoded name of the issuing CA.
	Issuer []byte
	// SerialNumber is the certificate serial number.
	SerialNumber *big.Int
}

// issuerAndSubject is the ASN.1 form of IssuerAndSubject.
type issuerAndSubject struct {
	Issuer  asn1.RawValue
	Subject asn1.RawValue
}

// issuerAndSerial is the ASN.1 form of IssuerAndSerial.
type issuerAndSerial struct {
	Issuer       asn1.RawValue
	SerialNumber *big.Int
}

// ParseOptions controls how ParsePKIMessage reads a message.
type ParseOptions struct {
	// Signers restricts who may sign the message to these certificates, which are then the only
	// certificates the signature is checked against. A requester sets the CA and RA certificates
	// from GetCACert, so a CertRep that omits its signer certificate still verifies and a CertRep
	// signed by any other key is refused. A responder leaves it empty, because requests are signed
	// with the requester's own certificate.
	Signers []*x509.Certificate

	// AllowMD5 accepts messages signed with the MD5 digest. Some network devices still send them.
	AllowMD5 bool

	// LegacyCertificateParser accepts certificates that mark the authority key identifier
	// critical, which some Windows SCEP clients send.
	LegacyCertificateParser bool
}

// ParsePKIMessage parses a DER or BER encoded pkiMessage, verifies its signature and reads its
// attributes. The signature proves possession of the signer key only. Whether the signer is
// authorized is up to the caller, through ParseOptions.Signers for a response or the challenge
// password or existing certificate of a request.
func ParsePKIMessage(data []byte, opts ParseOptions) (*PKIMessage, error) {
	parseOpts := pkcs7.ParseOptions{LegacyCertificateParser: opts.LegacyCertificateParser}
	p7, err := pkcs7.ParseWithOptions(data, parseOpts)
	if err != nil {
		return nil, fmt.Errorf("scep: parse pkiMessage: %w", err)
	}
	if len(p7.Signers) != 1 {
		return nil, fmt.Errorf("scep: pkiMessage has %d signers, want 1", len(p7.Signers))
	}
	carried := p7.Certificates
	verifyOpts := pkcs7.VerifyOptions{AllowMD5: opts.AllowMD5}
	candidates := carried
	if len(opts.Signers) > 0 {
		// A certificate carried in the message could name the expected issuer and serial number
		// with another key, so only the expected signers take part in the check.
		p7.Certificates = nil
		verifyOpts.SignerCertificates = opts.Signers
		candidates = opts.Signers
	}
	err = p7.Verify(verifyOpts)
	p7.Certificates = carried
	if err != nil {
		return nil, fmt.Errorf("scep: verify pkiMessage: %w", err)
	}
	signer := p7.Signers[0]
	msg := &PKIMessage{
		Raw:          data,
		Certificates: carried,
		Digest:       digestForOID(signer.DigestAlgorithm.Algorithm),
		p7:           p7,
	}
	for _, cert := range candidates {
		if cert.SerialNumber.Cmp(signer.IssuerAndSerialNumber.SerialNumber) == 0 &&
			bytes.Equal(cert.RawIssuer, signer.IssuerAndSerialNumber.IssuerName.FullBytes) {
			msg.SignerCertificate = cert
			break
		}
	}
	if msg.SignerCertificate == nil {
		return nil, errors.New("scep: the signer certificate of the pkiMessage is missing")
	}
	if err := msg.readAttributes(); err != nil {
		return nil, err
	}
	return msg, nil
}

// readAttributes reads the signed attributes that every message type carries and those of its
// own type.
func (msg *PKIMessage) readAttributes() error {
	var tID string
	if err := msg.p7.UnmarshalSignedAttribute(oidSCEPtransactionID, &tID); err != nil {
		return fmt.Errorf("scep: transactionID attribute: %w", err)
	}
	if tID == "" || len(tID) > maxTransactionIDLength {
		return fmt.Errorf("scep: transactionID must hold 1 to %d characters", maxTransactionIDLength)
	}
	msg.TransactionID = TransactionID(tID)

	var msgType string
	if err := msg.p7.UnmarshalSignedAttribute(oidSCEPmessageType, &msgType); err != nil {
		return fmt.Errorf("scep: messageType attribute: %w", err)
	}
	msg.MessageType = MessageType(msgType)

	var sn []byte
	err := msg.p7.UnmarshalSignedAttribute(oidSCEPsenderNonce, &sn)
	switch {
	case errors.Is(err, pkcs7.ErrAttributeNotFound) && msg.MessageType == CertRep:
	case err != nil:
		return fmt.Errorf("scep: senderNonce attribute: %w", err)
	case len(sn) == 0 || len(sn) > maxNonceLength:
		return fmt.Errorf("scep: senderNonce must hold 1 to %d bytes", maxNonceLength)
	default:
		msg.SenderNonce = sn
	}

	switch {
	case msg.MessageType == CertRep:
		return msg.readCertRepAttributes()
	case msg.MessageType.isEnrollment(), msg.MessageType == CertPoll,
		msg.MessageType == GetCert, msg.MessageType == GetCRL:
		return nil
	default:
		return fmt.Errorf("%w %q", errUnknownMessageType, string(msg.MessageType))
	}
}

// readCertRepAttributes reads the pkiStatus, recipientNonce and failInfo attributes of a CertRep.
func (msg *PKIMessage) readCertRepAttributes() error {
	var status string
	if err := msg.p7.UnmarshalSignedAttribute(oidSCEPpkiStatus, &status); err != nil {
		return fmt.Errorf("scep: pkiStatus attribute: %w", err)
	}
	var rn []byte
	if err := msg.p7.UnmarshalSignedAttribute(oidSCEPrecipientNonce, &rn); err != nil {
		return fmt.Errorf("scep: recipientNonce attribute: %w", err)
	}
	if len(rn) == 0 || len(rn) > maxNonceLength {
		return fmt.Errorf("scep: recipientNonce must hold 1 to %d bytes", maxNonceLength)
	}
	cr := &CertRepMessage{PKIStatus: PKIStatus(status), RecipientNonce: rn}
	switch cr.PKIStatus {
	case SUCCESS, PENDING:
	case FAILURE:
		var fi string
		if err := msg.p7.UnmarshalSignedAttribute(oidSCEPfailInfo, &fi); err != nil {
			return fmt.Errorf("scep: failInfo attribute of a FAILURE: %w", err)
		}
		cr.FailInfo = FailInfo(fi)
	default:
		return fmt.Errorf("scep: unknown pkiStatus %q", status)
	}
	msg.CertRepMessage = cr
	return nil
}

// MatchesRequest checks that a CertRep answers req: the transaction identifiers are equal and the
// recipientNonce repeats the senderNonce of req.
func (msg *PKIMessage) MatchesRequest(req *PKIMessage) error {
	if msg.MessageType != CertRep || msg.CertRepMessage == nil {
		return fmt.Errorf("scep: got %s, want a CertRep", msg.MessageType)
	}
	if msg.TransactionID != req.TransactionID {
		return fmt.Errorf("scep: CertRep transactionID %q does not match the request's %q",
			msg.TransactionID, req.TransactionID)
	}
	if !bytes.Equal(msg.RecipientNonce, req.SenderNonce) {
		return errors.New("scep: CertRep recipientNonce does not match the request senderNonce")
	}
	return nil
}

// EnvelopeRecipients lists the certificates the pkiEnvelope of a parsed message is encrypted for,
// so a server that holds several CA or RA keys can pick the one that decrypts it.
func (msg *PKIMessage) EnvelopeRecipients() ([]IssuerAndSerial, error) {
	envelope, err := msg.parsedEnvelope()
	if err != nil {
		return nil, err
	}
	recipients, err := envelope.Recipients()
	if err != nil {
		return nil, fmt.Errorf("scep: pkiEnvelope recipients: %w", err)
	}
	ids := make([]IssuerAndSerial, 0, len(recipients))
	for _, r := range recipients {
		ids = append(ids, IssuerAndSerial{Issuer: r.Issuer, SerialNumber: r.SerialNumber})
	}
	return ids, nil
}

// parsedEnvelope parses the pkiEnvelope of a parsed message once.
func (msg *PKIMessage) parsedEnvelope() (*pkcs7.PKCS7, error) {
	if msg.envelope != nil {
		return msg.envelope, nil
	}
	if msg.p7 == nil || len(msg.p7.Content) == 0 {
		return nil, errNoEnvelope
	}
	envelope, err := pkcs7.Parse(msg.p7.Content)
	if err != nil {
		return nil, fmt.Errorf("scep: parse pkiEnvelope: %w", err)
	}
	msg.envelope = envelope
	return envelope, nil
}

// DecryptPKIEnvelope decrypts the pkiEnvelope with the recipient certificate and its RSA key and
// parses its content: the CSR of an enrollment request, the query of CertPoll, GetCert and GetCRL,
// or the certificates or CRL of a SUCCESS CertRep. opts lists the content ciphers to accept.
func (msg *PKIMessage) DecryptPKIEnvelope(cert *x509.Certificate, key crypto.Decrypter, opts pkcs7.DecryptOptions) error {
	if cert == nil || key == nil {
		return errors.New("scep: decrypting the pkiEnvelope needs a certificate and a key")
	}
	if _, ok := key.Public().(*rsa.PublicKey); !ok {
		return fmt.Errorf("scep: the pkiEnvelope needs an RSA key, got %T", key.Public())
	}
	envelope, err := msg.parsedEnvelope()
	if err != nil {
		return err
	}
	content, err := envelope.Decrypt(cert, key, opts)
	if err != nil {
		return fmt.Errorf("scep: decrypt pkiEnvelope: %w", err)
	}
	if msg.ContentEncryption, err = envelope.ContentEncryptionAlgorithm(); err != nil {
		return err
	}
	return msg.parseEnvelopeContent(content)
}

// parseEnvelopeContent parses the decrypted pkiEnvelope according to the message type.
func (msg *PKIMessage) parseEnvelopeContent(content []byte) error {
	switch {
	case msg.MessageType == CertRep:
		if msg.PKIStatus != SUCCESS {
			return fmt.Errorf("scep: a CertRep with status %s carries no certificates", msg.PKIStatus)
		}
		degenerate, err := pkcs7.Parse(content)
		if err != nil {
			return fmt.Errorf("scep: parse CertRep certificates: %w", err)
		}
		msg.CertRepMessage.Certificates = degenerate.Certificates
		if len(degenerate.CRLs) > 0 {
			if msg.CRL, err = asn1.Marshal(degenerate.CRLs[0]); err != nil {
				return fmt.Errorf("scep: encode CertRep CRL: %w", err)
			}
		}
		if len(msg.CertRepMessage.Certificates) == 0 && msg.CRL == nil {
			return errors.New("scep: SUCCESS CertRep carries neither certificates nor a CRL")
		}
		return nil
	case msg.MessageType.isEnrollment():
		csr, err := x509.ParseCertificateRequest(content)
		if err != nil {
			return fmt.Errorf("scep: parse CSR from pkiEnvelope: %w", err)
		}
		if err := csr.CheckSignature(); err != nil {
			return fmt.Errorf("scep: CSR signature: %w", err)
		}
		password, err := x509util.ParseChallengePassword(content)
		if err != nil {
			return fmt.Errorf("scep: parse challenge password in pkiEnvelope: %w", err)
		}
		msg.CSRReqMessage = &CSRReqMessage{RawDecrypted: content, CSR: csr, ChallengePassword: password}
		return nil
	case msg.MessageType == CertPoll:
		var ias issuerAndSubject
		if err := unmarshalExact(content, &ias); err != nil {
			return fmt.Errorf("scep: parse CertPoll issuerAndSubject: %w", err)
		}
		msg.PollRequest = &IssuerAndSubject{Issuer: ias.Issuer.FullBytes, Subject: ias.Subject.FullBytes}
		return nil
	case msg.MessageType == GetCert, msg.MessageType == GetCRL:
		var ias issuerAndSerial
		if err := unmarshalExact(content, &ias); err != nil {
			return fmt.Errorf("scep: parse %s issuerAndSerialNumber: %w", msg.MessageType, err)
		}
		if ias.SerialNumber == nil {
			return fmt.Errorf("scep: %s has no serial number", msg.MessageType)
		}
		msg.CertificateID = &IssuerAndSerial{Issuer: ias.Issuer.FullBytes, SerialNumber: ias.SerialNumber}
		return nil
	default:
		return errUnknownMessageType
	}
}

// unmarshalExact decodes DER into out and refuses trailing data. Names must be SEQUENCEs.
func unmarshalExact(der []byte, out any) error {
	rest, err := asn1.Unmarshal(der, out)
	if err != nil {
		return err
	}
	if len(rest) != 0 {
		return errors.New("trailing data")
	}
	var names []asn1.RawValue
	switch v := out.(type) {
	case *issuerAndSubject:
		names = []asn1.RawValue{v.Issuer, v.Subject}
	case *issuerAndSerial:
		names = []asn1.RawValue{v.Issuer}
	}
	if slices.ContainsFunc(names, func(name asn1.RawValue) bool {
		return name.Class != asn1.ClassUniversal || name.Tag != asn1.TagSequence || !name.IsCompound
	}) {
		return errors.New("a name is not a SEQUENCE")
	}
	return nil
}

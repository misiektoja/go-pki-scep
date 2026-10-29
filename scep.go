// Package scep encodes and decodes the pkiMessage structures of the Simple Certificate Enrollment
// Protocol (SCEP, RFC 8894).
//
// A pkiMessage is a CMS SignedData whose content is an EnvelopedData. The signed attributes carry
// the message type, the transaction identifier and the nonces. The envelope carries a CSR, a
// certificate query or the certificates of a response.
//
// Requesters build PKCSReq, RenewalReq, CertPoll, GetCert and GetCRL messages with the New
// functions. Responders parse them with ParsePKIMessage, decrypt them with DecryptPKIEnvelope and
// answer with Success, SuccessCRL, Pending or Fail. Algorithm choices are made per call. The HTTP
// transport lives in the scepserver and scepclient packages.
package scep

import (
	"crypto"
	"encoding/asn1"
	"errors"
	"fmt"

	"github.com/misiektoja/go-pkcs7"
)

// MessageType is the SCEP messageType attribute, a decimal number in a PrintableString.
type MessageType string

// Message types from RFC 8894 section 3.2.1.2. UpdateReq comes from earlier drafts and is parsed
// like RenewalReq.
const (
	CertRep    MessageType = "3"
	RenewalReq MessageType = "17"
	UpdateReq  MessageType = "18"
	PKCSReq    MessageType = "19"
	CertPoll   MessageType = "20"
	GetCert    MessageType = "21"
	GetCRL     MessageType = "22"
)

// String returns the message type name and number.
func (msg MessageType) String() string {
	switch msg {
	case CertRep:
		return "CertRep (3)"
	case RenewalReq:
		return "RenewalReq (17)"
	case UpdateReq:
		return "UpdateReq (18)"
	case PKCSReq:
		return "PKCSReq (19)"
	case CertPoll:
		return "CertPoll (20)"
	case GetCert:
		return "GetCert (21)"
	case GetCRL:
		return "GetCRL (22)"
	default:
		return fmt.Sprintf("unknown messageType %q", string(msg))
	}
}

// isEnrollment reports whether the message type carries a CSR.
func (msg MessageType) isEnrollment() bool {
	return msg == PKCSReq || msg == RenewalReq || msg == UpdateReq
}

// PKIStatus is the SCEP pkiStatus attribute of a CertRep.
type PKIStatus string

// Statuses from RFC 8894 section 3.2.1.3.
const (
	SUCCESS PKIStatus = "0"
	FAILURE PKIStatus = "2"
	PENDING PKIStatus = "3"
)

// String returns the status name and number.
func (status PKIStatus) String() string {
	switch status {
	case SUCCESS:
		return "SUCCESS (0)"
	case FAILURE:
		return "FAILURE (2)"
	case PENDING:
		return "PENDING (3)"
	default:
		return fmt.Sprintf("unknown pkiStatus %q", string(status))
	}
}

// FailInfo is the SCEP failInfo attribute of a CertRep with status FAILURE.
type FailInfo string

// Failure reasons from RFC 8894 section 3.2.1.4.
const (
	BadAlg          FailInfo = "0"
	BadMessageCheck FailInfo = "1"
	BadRequest      FailInfo = "2"
	BadTime         FailInfo = "3"
	BadCertID       FailInfo = "4"
)

// String returns the failure reason name and number.
func (info FailInfo) String() string {
	switch info {
	case BadAlg:
		return "badAlg (0)"
	case BadMessageCheck:
		return "badMessageCheck (1)"
	case BadRequest:
		return "badRequest (2)"
	case BadTime:
		return "badTime (3)"
	case BadCertID:
		return "badCertID (4)"
	default:
		return fmt.Sprintf("unknown failInfo %q", string(info))
	}
}

// valid reports whether the failure reason is one RFC 8894 defines.
func (info FailInfo) valid() bool {
	switch info {
	case BadAlg, BadMessageCheck, BadRequest, BadTime, BadCertID:
		return true
	default:
		return false
	}
}

// SenderNonce is the random senderNonce of a message, 16 bytes in messages built by this package.
type SenderNonce []byte

// RecipientNonce is the recipientNonce of a CertRep. It repeats the senderNonce of the request.
type RecipientNonce []byte

// TransactionID identifies an enrollment across its PKCSReq or RenewalReq, its CertPoll messages
// and their responses. It is a PrintableString.
type TransactionID string

// SCEP attribute identifiers from RFC 8894 section 3.2.1.
var (
	oidSCEPmessageType    = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 2}
	oidSCEPpkiStatus      = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 3}
	oidSCEPfailInfo       = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 4}
	oidSCEPsenderNonce    = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 5}
	oidSCEPrecipientNonce = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 6}
	oidSCEPtransactionID  = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 7}
)

// maxNonceLength bounds received nonces. RFC 8894 nonces are 16 bytes.
const maxNonceLength = 64

// maxTransactionIDLength bounds received transaction identifiers.
const maxTransactionIDLength = 256

var (
	errUnknownMessageType = errors.New("scep: unknown messageType")
	errNoEnvelope         = errors.New("scep: the message carries no pkiEnvelope")
)

// digestAlgorithms maps the digests this package signs with to their CMS identifiers.
var digestAlgorithms = map[crypto.Hash]asn1.ObjectIdentifier{
	crypto.MD5:    pkcs7.OIDDigestAlgorithmMD5,
	crypto.SHA1:   pkcs7.OIDDigestAlgorithmSHA1,
	crypto.SHA224: pkcs7.OIDDigestAlgorithmSHA224,
	crypto.SHA256: pkcs7.OIDDigestAlgorithmSHA256,
	crypto.SHA384: pkcs7.OIDDigestAlgorithmSHA384,
	crypto.SHA512: pkcs7.OIDDigestAlgorithmSHA512,
}

// rsaSignatureDigests maps RSA signature identifiers that some signers put in the digest algorithm
// field to their hashes.
var rsaSignatureDigests = map[crypto.Hash]asn1.ObjectIdentifier{
	crypto.MD5:    pkcs7.OIDEncryptionAlgorithmRSAMD5,
	crypto.SHA1:   pkcs7.OIDEncryptionAlgorithmRSASHA1,
	crypto.SHA224: pkcs7.OIDEncryptionAlgorithmRSASHA224,
	crypto.SHA256: pkcs7.OIDEncryptionAlgorithmRSASHA256,
	crypto.SHA384: pkcs7.OIDEncryptionAlgorithmRSASHA384,
	crypto.SHA512: pkcs7.OIDEncryptionAlgorithmRSASHA512,
}

// digestForOID returns the hash of a digest algorithm identifier, or zero when it is unknown.
func digestForOID(oid asn1.ObjectIdentifier) crypto.Hash {
	for _, table := range []map[crypto.Hash]asn1.ObjectIdentifier{digestAlgorithms, rsaSignatureDigests} {
		for hash, known := range table {
			if oid.Equal(known) {
				return hash
			}
		}
	}
	return 0
}

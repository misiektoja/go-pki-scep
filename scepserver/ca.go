package scepserver

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"time"

	scep "github.com/misiektoja/go-pki-scep"
)

// CA is the certificate authority behind a Handler. The handler calls its methods concurrently.
//
// Enroll, Poll and the optional GetCert and GetCRL return one of these:
//
//   - the certificates of a SUCCESS answer, the requested certificate first
//   - ErrPending while a request waits for approval, answered with PENDING
//   - a *Failure that refuses the request with a failInfo
//   - a *Busy that asks the client to retry later, answered with HTTP 503
//
// Any other error is answered with HTTP 500, so the client retries instead of giving up on the
// transaction.
type CA interface {
	// CACertificates answers GetCACert. name is the message parameter, which clients set to a CA
	// name or leave empty. The CA certificate comes first. RA certificates follow when an RA
	// signs for the CA. Return ErrNotFound for a name the CA does not serve.
	CACertificates(ctx context.Context, name string) ([]*x509.Certificate, error)

	// Responder returns the identity whose decrypter certificate has the issuer and serial number
	// of recipient, a recipient that a pkiEnvelope names. Return ErrNotFound when none matches.
	Responder(ctx context.Context, recipient scep.IssuerAndSerial) (*Responder, error)

	// Enroll answers a PKCSReq, RenewalReq or UpdateReq. It authorizes the requester, such as by
	// the challenge password of a PKCSReq or the signer certificate of a RenewalReq.
	Enroll(ctx context.Context, req *Request) ([]*x509.Certificate, error)

	// Poll answers a CertPoll for an earlier enrollment, which the transaction ID, the issuer
	// and the subject identify.
	Poll(ctx context.Context, req *Request) ([]*x509.Certificate, error)
}

// CertificateGetter is implemented by a CA that answers GetCert.
type CertificateGetter interface {
	// GetCert returns the certificate that req.Message.CertificateID names, optionally followed by
	// its chain.
	GetCert(ctx context.Context, req *Request) ([]*x509.Certificate, error)
}

// CRLGetter is implemented by a CA that answers GetCRL.
type CRLGetter interface {
	// GetCRL returns the DER encoded CRL that covers the certificate req.Message.CertificateID
	// names.
	GetCRL(ctx context.Context, req *Request) ([]byte, error)
}

// NextCAGetter is implemented by a CA that announces its next CA certificate through
// GetNextCACert ahead of a rollover.
type NextCAGetter interface {
	// NextCACertificates returns the certificates that will replace those of CACertificates for
	// name and the current responder that signs the answer. Return ErrNotFound when no rollover is
	// planned.
	NextCACertificates(ctx context.Context, name string) ([]*x509.Certificate, *Responder, error)
}

// ChainGetter is implemented by a CA that answers GetCACertChain. RFC 8894 does not define the
// operation, but some CAs serve it and their clients still send it.
type ChainGetter interface {
	// CACertificateChain returns the CA certificate for name followed by the certificates that
	// issued it, up to the root. Return ErrNotFound for a name the CA does not serve.
	CACertificateChain(ctx context.Context, name string) ([]*x509.Certificate, error)
}

// RefusalRecorder is implemented by a CA that records the requests the handler refuses without
// passing them to the CA: a signer certificate without an RSA key, a pkiEnvelope that does not
// decrypt or uses a refused cipher, an operation the CA does not implement and a message type that
// is not a request.
type RefusalRecorder interface {
	// RecordRefusal is called before the FAILURE answer is sent. The pkiEnvelope of req may not be
	// decrypted, so its CSR and query fields can be empty. failure.Err holds the cause, such as
	// ErrSignerNotRSA.
	RecordRefusal(ctx context.Context, req *Request, failure *Failure)
}

// Responder is the CA or RA identity that decrypts the requests for one CA and signs its answers.
type Responder struct {
	// SignerCertificate and SignerKey sign CertRep messages and GetNextCACert answers. Requesters
	// trust the certificate from GetCACert.
	SignerCertificate *x509.Certificate
	SignerKey         crypto.Signer

	// DecrypterCertificate and DecrypterKey decrypt pkiEnvelopes, for an RA with separate signing
	// and encryption certificates. When DecrypterCertificate is nil, the signer certificate
	// decrypts and SignerKey must implement crypto.Decrypter.
	DecrypterCertificate *x509.Certificate
	DecrypterKey         crypto.Decrypter

	// Certificates are carried in CertRep messages next to the signer certificate, such as the CA
	// certificate when an RA signs.
	Certificates []*x509.Certificate
}

// decrypter returns the certificate and key that decrypt pkiEnvelopes.
func (r *Responder) decrypter() (*x509.Certificate, crypto.Decrypter, error) {
	if r.DecrypterCertificate != nil {
		if r.DecrypterKey == nil {
			return nil, nil, errors.New("scepserver: responder has a decrypter certificate without a key")
		}
		return r.DecrypterCertificate, r.DecrypterKey, nil
	}
	key, ok := r.SignerKey.(crypto.Decrypter)
	if r.SignerCertificate == nil || !ok {
		return nil, nil, errors.New("scepserver: responder has no decrypter and its signer key cannot decrypt")
	}
	return r.SignerCertificate, key, nil
}

// Request is a PKIOperation request after the handler has verified and decrypted it.
type Request struct {
	// Message is the pkiMessage. Its CSRReqMessage, PollRequest or CertificateID holds the
	// decrypted content.
	Message *scep.PKIMessage

	// Responder is the identity the request was encrypted for, which tells the CA it addresses.
	Responder *Responder

	// HTTPRequest carries the client address, headers and TLS state.
	HTTPRequest *http.Request
}

// ErrPending answers an enrollment or a poll with PENDING. The client polls again later.
var ErrPending = errors.New("scepserver: request pending")

// ErrNotFound reports a CA name, recipient or next CA certificate the CA does not have. A GetCACert
// or GetNextCACert gets HTTP 404 and a PKIOperation gets HTTP 400.
var ErrNotFound = errors.New("scepserver: not found")

// ErrSignerNotRSA is the cause of the badAlg answer to a request whose signer certificate has no
// RSA key. The answer is encrypted for that certificate with RSA key transport, the only kind
// supported.
// A device with an ECDSA key can sign its request with a separate RSA key and certificate.
var ErrSignerNotRSA = errors.New("scepserver: the request signer certificate has no RSA key")

// Failure refuses a request with a SCEP failInfo.
type Failure struct {
	// Info is the reason sent to the client.
	Info scep.FailInfo
	// Err is the cause, which is logged and not sent.
	Err error
}

// Error describes the failure.
func (f *Failure) Error() string {
	if f.Err == nil {
		return fmt.Sprintf("scepserver: request refused with %s", f.Info)
	}
	return fmt.Sprintf("scepserver: request refused with %s: %v", f.Info, f.Err)
}

// Unwrap returns the cause.
func (f *Failure) Unwrap() error {
	return f.Err
}

// Busy asks the client to send the request again later, for example when it polls more often than
// the CA allows. The handler answers HTTP 503 with a Retry-After header.
type Busy struct {
	// RetryAfter is the delay sent to the client, rounded up to whole seconds. Zero leaves the
	// header out.
	RetryAfter time.Duration
}

// Error describes the delay.
func (b *Busy) Error() string {
	return fmt.Sprintf("scepserver: busy, retry after %s", b.RetryAfter)
}

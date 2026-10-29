package scepclient

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/misiektoja/go-pkcs7"

	"github.com/misiektoja/go-scep"
)

// EnrollRequest describes a PKCSReq or RenewalReq and the CertPoll messages that follow it.
type EnrollRequest struct {
	// MessageType is scep.PKCSReq, the default, or scep.RenewalReq.
	MessageType scep.MessageType

	// CSR is the certificate request. Its public key identifies the issued certificate in the
	// answer.
	CSR *x509.CertificateRequest

	// SignerCertificate and SignerKey sign the request, and the key decrypts the answer, so it
	// must be an RSA crypto.Decrypter. A PKCSReq uses a self-signed certificate for the CSR key.
	// A RenewalReq uses the certificate being renewed and its key.
	SignerCertificate *x509.Certificate
	SignerKey         crypto.Signer

	// TransactionID identifies the enrollment. The zero value derives it from the CSR public key
	// with scep.CSRTransactionID, so Poll finds the same transaction without it.
	TransactionID scep.TransactionID

	// Digest is the signature digest. The zero value picks the strongest digest the server lists.
	Digest crypto.Hash

	// Encryption selects the content cipher and key transport. A zero cipher picks AES-128-CBC,
	// or DES-EDE3-CBC when the server lists DES3 and not AES.
	Encryption pkcs7.EncryptOptions
}

// Result is the answer to an enrollment or a poll.
type Result struct {
	// Status is SUCCESS, PENDING or FAILURE.
	Status scep.PKIStatus

	// FailInfo is the reason of a FAILURE.
	FailInfo scep.FailInfo

	// Certificate is the issued certificate, the one whose public key is the CSR key.
	Certificate *x509.Certificate

	// Certificates holds every certificate of a SUCCESS answer, such as the chain.
	Certificates []*x509.Certificate

	// TransactionID identifies the enrollment for Poll.
	TransactionID scep.TransactionID

	// Response is the verified CertRep.
	Response *scep.PKIMessage
}

// Enroll sends a PKCSReq or RenewalReq to ca and returns the answer. A PENDING result is polled
// with Poll, or use EnrollAndWait.
func (c *Client) Enroll(ctx context.Context, ca *CACertificates, req EnrollRequest) (*Result, error) {
	messageType := req.MessageType
	if messageType == "" {
		messageType = scep.PKCSReq
	}
	if messageType != scep.PKCSReq && messageType != scep.RenewalReq {
		return nil, fmt.Errorf("scepclient: Enroll sends PKCSReq or RenewalReq, not %s", messageType)
	}
	if req.CSR == nil {
		return nil, errors.New("scepclient: Enroll needs a CSR")
	}
	opts, key, err := c.requestOptions(ctx, ca, req.SignerCertificate, req.SignerKey, req.Digest, req.Encryption)
	if err != nil {
		return nil, err
	}
	opts.TransactionID = req.TransactionID
	msg, err := scep.NewCSRRequest(messageType, req.CSR, opts)
	if err != nil {
		return nil, err
	}
	rep, err := c.exchange(ctx, ca, msg, key)
	if err != nil {
		return nil, err
	}
	return issued(rep, req.CSR)
}

// Poll sends one CertPoll for the enrollment req describes and returns the answer. It derives the
// transaction ID like Enroll when req sets none.
func (c *Client) Poll(ctx context.Context, ca *CACertificates, req EnrollRequest) (*Result, error) {
	if req.CSR == nil {
		return nil, errors.New("scepclient: Poll needs the CSR of the enrollment")
	}
	opts, key, err := c.requestOptions(ctx, ca, req.SignerCertificate, req.SignerKey, req.Digest, req.Encryption)
	if err != nil {
		return nil, err
	}
	opts.TransactionID = req.TransactionID
	if opts.TransactionID == "" {
		if opts.TransactionID, err = scep.CSRTransactionID(req.CSR); err != nil {
			return nil, err
		}
	}
	msg, err := scep.NewCertPollRequest(ca.CA.RawSubject, req.CSR.RawSubject, opts)
	if err != nil {
		return nil, err
	}
	rep, err := c.exchange(ctx, ca, msg, key)
	if err != nil {
		return nil, err
	}
	return issued(rep, req.CSR)
}

// EnrollAndWait enrolls and polls every interval while the answer is PENDING. It returns the first
// SUCCESS or FAILURE result, or the context error with the last PENDING result when ctx ends
// first. Set a deadline on ctx to bound the wait.
func (c *Client) EnrollAndWait(ctx context.Context, ca *CACertificates, req EnrollRequest, interval time.Duration) (*Result, error) {
	if interval <= 0 {
		return nil, errors.New("scepclient: the poll interval must be positive")
	}
	res, err := c.Enroll(ctx, ca, req)
	if err != nil {
		return nil, err
	}
	req.TransactionID = res.TransactionID
	for res.Status == scep.PENDING {
		if err := sleep(ctx, interval); err != nil {
			return res, err
		}
		next, err := c.Poll(ctx, ca, req)
		if err != nil {
			return res, err
		}
		res = next
	}
	return res, nil
}

// issued turns a CertRep into a Result and finds the certificate for the CSR key.
func issued(rep *scep.PKIMessage, csr *x509.CertificateRequest) (*Result, error) {
	res := &Result{
		Status:        rep.PKIStatus,
		FailInfo:      rep.FailInfo,
		TransactionID: rep.TransactionID,
		Response:      rep,
	}
	if rep.PKIStatus != scep.SUCCESS {
		return res, nil
	}
	res.Certificates = rep.CertRepMessage.Certificates
	pub, ok := csr.PublicKey.(interface{ Equal(x crypto.PublicKey) bool })
	if !ok {
		return nil, fmt.Errorf("scepclient: unsupported CSR key type %T", csr.PublicKey)
	}
	for _, cert := range res.Certificates {
		if pub.Equal(cert.PublicKey) {
			res.Certificate = cert
			return res, nil
		}
	}
	return nil, errors.New("scepclient: the SUCCESS answer holds no certificate for the CSR key")
}

// QueryRequest describes a GetCert or GetCRL.
type QueryRequest struct {
	// Issuer is the DER encoded name of the CA that issued the certificate. The zero value takes
	// the subject of the CA certificate.
	Issuer []byte

	// SerialNumber is the serial number of the certificate to fetch, or whose CRL to fetch.
	SerialNumber *big.Int

	// SignerCertificate and SignerKey sign the request, and the key decrypts the answer, so it
	// must be an RSA crypto.Decrypter. Servers usually expect a certificate the CA issued.
	SignerCertificate *x509.Certificate
	SignerKey         crypto.Signer

	// Digest and Encryption work as in EnrollRequest.
	Digest     crypto.Hash
	Encryption pkcs7.EncryptOptions
}

// GetCert fetches the certificate that req names. It returns a *FailureError when the server
// answers FAILURE.
func (c *Client) GetCert(ctx context.Context, ca *CACertificates, req QueryRequest) ([]*x509.Certificate, error) {
	rep, err := c.query(ctx, ca, scep.GetCert, req)
	if err != nil {
		return nil, err
	}
	if len(rep.CertRepMessage.Certificates) == 0 {
		return nil, errors.New("scepclient: the GetCert answer holds no certificates")
	}
	return rep.CertRepMessage.Certificates, nil
}

// GetCRL fetches the DER encoded CRL that covers the certificate req names. It returns a
// *FailureError when the server answers FAILURE.
func (c *Client) GetCRL(ctx context.Context, ca *CACertificates, req QueryRequest) ([]byte, error) {
	rep, err := c.query(ctx, ca, scep.GetCRL, req)
	if err != nil {
		return nil, err
	}
	if rep.CRL == nil {
		return nil, errors.New("scepclient: the GetCRL answer holds no CRL")
	}
	return rep.CRL, nil
}

// FailureError is a FAILURE answer to GetCert or GetCRL, or a PENDING answer, which those
// requests do not expect.
type FailureError struct {
	Status   scep.PKIStatus
	FailInfo scep.FailInfo
}

// Error describes the answer.
func (e *FailureError) Error() string {
	if e.Status == scep.FAILURE {
		return fmt.Sprintf("scepclient: server answered FAILURE with %s", e.FailInfo)
	}
	return fmt.Sprintf("scepclient: server answered %s", e.Status)
}

// query sends a GetCert or GetCRL and returns the SUCCESS CertRep.
func (c *Client) query(ctx context.Context, ca *CACertificates, messageType scep.MessageType, req QueryRequest) (*scep.PKIMessage, error) {
	opts, key, err := c.requestOptions(ctx, ca, req.SignerCertificate, req.SignerKey, req.Digest, req.Encryption)
	if err != nil {
		return nil, err
	}
	issuer := req.Issuer
	if issuer == nil {
		issuer = ca.CA.RawSubject
	}
	var msg *scep.PKIMessage
	if messageType == scep.GetCert {
		msg, err = scep.NewGetCertRequest(issuer, req.SerialNumber, opts)
	} else {
		msg, err = scep.NewGetCRLRequest(issuer, req.SerialNumber, opts)
	}
	if err != nil {
		return nil, err
	}
	rep, err := c.exchange(ctx, ca, msg, key)
	if err != nil {
		return nil, err
	}
	if rep.PKIStatus != scep.SUCCESS {
		return nil, &FailureError{Status: rep.PKIStatus, FailInfo: rep.FailInfo}
	}
	return rep, nil
}

// Package testca is an in-memory SCEP CA for the tests of the server and client packages.
package testca

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/misiektoja/go-scep"
	"github.com/misiektoja/go-scep/scepserver"
	"github.com/misiektoja/go-scep/x509util"
)

// Options selects the behavior of a CA.
type Options struct {
	// Name is the CA name GetCACert accepts. Empty accepts any name.
	Name string
	// Password is the challenge password a PKCSReq must carry. Empty accepts any.
	Password string
	// Manual keeps enrollments pending until Approve or ApproveAfterPolls.
	Manual bool
	// ApproveAfterPolls approves a pending enrollment when it has been polled this many times.
	ApproveAfterPolls int
	// RA adds an RA with separate signing and encryption certificates that answers for the CA.
	RA bool
	// Rollover announces a next CA certificate through GetNextCACert.
	Rollover bool
	// Root has a separate root CA issue the CA certificate, so GetCACertChain returns both.
	Root bool
}

// CA issues certificates in memory. Its methods implement every scepserver CA interface.
type CA struct {
	opts Options

	Certificate *x509.Certificate
	Key         *rsa.PrivateKey
	// Root is the certificate that issued Certificate in Root mode.
	Root *x509.Certificate

	RASigner        *x509.Certificate
	RASignerKey     *rsa.PrivateKey
	RAEncrypter     *x509.Certificate
	RAEncrypterKey  *rsa.PrivateKey
	NextCertificate *x509.Certificate

	mu       sync.Mutex
	serial   int64
	pending  map[scep.TransactionID]*pending
	issued   map[string]*x509.Certificate
	busy     int
	requests []scep.MessageType
}

// pending is an enrollment that waits for approval.
type pending struct {
	csr      *x509.CertificateRequest
	approved bool
	polls    int
}

// New creates a CA with fresh 2048-bit RSA keys.
func New(t testing.TB, opts Options) *CA {
	t.Helper()
	ca := &CA{
		opts:    opts,
		serial:  100,
		pending: map[scep.TransactionID]*pending{},
		issued:  map[string]*x509.Certificate{},
	}
	caUsage := x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	if !opts.RA {
		caUsage |= x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	}
	ca.Key = newKey(t)
	issuer, issuerKey := (*x509.Certificate)(nil), ca.Key
	if opts.Root {
		issuerKey = newKey(t)
		ca.Root = create(t, &x509.Certificate{
			SerialNumber:          randomSerial(t),
			Subject:               pkix.Name{CommonName: "SCEP Test Root CA"},
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			IsCA:                  true,
			BasicConstraintsValid: true,
		}, nil, issuerKey, issuerKey)
		issuer = ca.Root
	}
	ca.Certificate = create(t, &x509.Certificate{
		SerialNumber:          randomSerial(t),
		Subject:               pkix.Name{CommonName: "SCEP Test CA", Organization: []string{"Example"}},
		KeyUsage:              caUsage,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}, issuer, issuerKey, ca.Key)
	if opts.RA {
		ca.RASignerKey = newKey(t)
		ca.RASigner = create(t, &x509.Certificate{
			SerialNumber: randomSerial(t),
			Subject:      pkix.Name{CommonName: "SCEP Test RA signer"},
			KeyUsage:     x509.KeyUsageDigitalSignature,
		}, ca.Certificate, ca.Key, ca.RASignerKey)
		ca.RAEncrypterKey = newKey(t)
		ca.RAEncrypter = create(t, &x509.Certificate{
			SerialNumber: randomSerial(t),
			Subject:      pkix.Name{CommonName: "SCEP Test RA encrypter"},
			KeyUsage:     x509.KeyUsageKeyEncipherment,
		}, ca.Certificate, ca.Key, ca.RAEncrypterKey)
	}
	if opts.Rollover {
		nextKey := newKey(t)
		ca.NextCertificate = create(t, &x509.Certificate{
			SerialNumber:          randomSerial(t),
			Subject:               pkix.Name{CommonName: "SCEP Test CA 2", Organization: []string{"Example"}},
			KeyUsage:              caUsage,
			IsCA:                  true,
			BasicConstraintsValid: true,
		}, nil, nextKey, nextKey)
	}
	return ca
}

// newKey returns a 2048-bit RSA key.
func newKey(t testing.TB) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// randomSerial returns a random 64-bit serial number, so certificates of different test CAs never
// share an issuer and serial number.
func randomSerial(t testing.TB) *big.Int {
	t.Helper()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	if err != nil {
		t.Fatal(err)
	}
	return serial
}

// create signs template with the issuer key, or self-signs it when issuer is nil.
func create(t testing.TB, template, issuer *x509.Certificate, issuerKey, key *rsa.PrivateKey) *x509.Certificate {
	t.Helper()
	template.NotBefore = time.Now().Add(-time.Hour)
	template.NotAfter = time.Now().Add(24 * time.Hour)
	if issuer == nil {
		issuer = template
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, key.Public(), issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// Approve approves the pending enrollment with the transaction ID.
func (ca *CA) Approve(id scep.TransactionID) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	if p, ok := ca.pending[id]; ok {
		p.approved = true
	}
}

// SetBusy makes the next n PKIOperation requests answer with a *scepserver.Busy.
func (ca *CA) SetBusy(n int) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	ca.busy = n
}

// Requests returns the message types the CA has received in order.
func (ca *CA) Requests() []scep.MessageType {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	return append([]scep.MessageType(nil), ca.requests...)
}

// CACertificates returns the CA certificate and the RA certificates.
func (ca *CA) CACertificates(_ context.Context, name string) ([]*x509.Certificate, error) {
	if ca.opts.Name != "" && name != ca.opts.Name {
		return nil, scepserver.ErrNotFound
	}
	if ca.opts.RA {
		return []*x509.Certificate{ca.Certificate, ca.RASigner, ca.RAEncrypter}, nil
	}
	return []*x509.Certificate{ca.Certificate}, nil
}

// CACertificateChain returns the CA certificate and, in Root mode, the root that issued it.
func (ca *CA) CACertificateChain(_ context.Context, name string) ([]*x509.Certificate, error) {
	if ca.opts.Name != "" && name != ca.opts.Name {
		return nil, scepserver.ErrNotFound
	}
	if ca.Root != nil {
		return []*x509.Certificate{ca.Certificate, ca.Root}, nil
	}
	return []*x509.Certificate{ca.Certificate}, nil
}

// Responder returns the CA or RA identity when the recipient is its decrypter certificate.
func (ca *CA) Responder(_ context.Context, recipient scep.IssuerAndSerial) (*scepserver.Responder, error) {
	responder := ca.responder()
	cert := responder.SignerCertificate
	if responder.DecrypterCertificate != nil {
		cert = responder.DecrypterCertificate
	}
	if !bytes.Equal(cert.RawIssuer, recipient.Issuer) || cert.SerialNumber.Cmp(recipient.SerialNumber) != 0 {
		return nil, scepserver.ErrNotFound
	}
	return responder, nil
}

// responder returns the identity that answers for the CA.
func (ca *CA) responder() *scepserver.Responder {
	if ca.opts.RA {
		return &scepserver.Responder{
			SignerCertificate:    ca.RASigner,
			SignerKey:            ca.RASignerKey,
			DecrypterCertificate: ca.RAEncrypter,
			DecrypterKey:         ca.RAEncrypterKey,
			Certificates:         []*x509.Certificate{ca.Certificate},
		}
	}
	return &scepserver.Responder{SignerCertificate: ca.Certificate, SignerKey: ca.Key}
}

// record notes a request and returns a *scepserver.Busy while SetBusy asks for one.
func (ca *CA) record(messageType scep.MessageType) error {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	ca.requests = append(ca.requests, messageType)
	if ca.busy > 0 {
		ca.busy--
		return &scepserver.Busy{}
	}
	return nil
}

// Enroll checks the challenge password of a PKCSReq or the signer certificate of a RenewalReq and
// issues the certificate, or keeps it pending in manual mode.
func (ca *CA) Enroll(_ context.Context, req *scepserver.Request) ([]*x509.Certificate, error) {
	msg := req.Message
	if err := ca.record(msg.MessageType); err != nil {
		return nil, err
	}
	switch msg.MessageType {
	case scep.PKCSReq:
		if ca.opts.Password != "" && msg.ChallengePassword != ca.opts.Password {
			return nil, &scepserver.Failure{Info: scep.BadRequest, Err: errors.New("wrong challenge password")}
		}
	default:
		ca.mu.Lock()
		known, ok := ca.issued[msg.SignerCertificate.SerialNumber.String()]
		ca.mu.Unlock()
		if !ok || !known.Equal(msg.SignerCertificate) {
			err := errors.New("renewal not signed by an issued certificate")
			return nil, &scepserver.Failure{Info: scep.BadRequest, Err: err}
		}
	}
	if ca.opts.Manual {
		ca.mu.Lock()
		ca.pending[msg.TransactionID] = &pending{csr: msg.CSR}
		ca.mu.Unlock()
		return nil, scepserver.ErrPending
	}
	return ca.issue(msg.CSR)
}

// Poll answers a CertPoll for a pending enrollment.
func (ca *CA) Poll(_ context.Context, req *scepserver.Request) ([]*x509.Certificate, error) {
	msg := req.Message
	if err := ca.record(msg.MessageType); err != nil {
		return nil, err
	}
	ca.mu.Lock()
	p, ok := ca.pending[msg.TransactionID]
	if ok {
		p.polls++
		if ca.opts.ApproveAfterPolls > 0 && p.polls >= ca.opts.ApproveAfterPolls {
			p.approved = true
		}
	}
	ca.mu.Unlock()
	switch {
	case !ok || !bytes.Equal(msg.PollRequest.Subject, p.csr.RawSubject) ||
		!bytes.Equal(msg.PollRequest.Issuer, ca.Certificate.RawSubject):
		return nil, &scepserver.Failure{Info: scep.BadCertID, Err: errors.New("unknown transaction")}
	case !p.approved:
		return nil, scepserver.ErrPending
	}
	return ca.issue(p.csr)
}

// issue signs a certificate for the CSR and returns it with the CA certificate.
func (ca *CA) issue(csr *x509.CertificateRequest) ([]*x509.Certificate, error) {
	ca.mu.Lock()
	ca.serial++
	serial := ca.serial
	ca.mu.Unlock()
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      csr.Subject,
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}, ca.Certificate, csr.PublicKey, ca.Key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	ca.mu.Lock()
	ca.issued[cert.SerialNumber.String()] = cert
	ca.mu.Unlock()
	return []*x509.Certificate{cert, ca.Certificate}, nil
}

// GetCert returns an issued certificate.
func (ca *CA) GetCert(_ context.Context, req *scepserver.Request) ([]*x509.Certificate, error) {
	id := req.Message.CertificateID
	if err := ca.record(req.Message.MessageType); err != nil {
		return nil, err
	}
	ca.mu.Lock()
	cert, ok := ca.issued[id.SerialNumber.String()]
	ca.mu.Unlock()
	if !ok || !bytes.Equal(id.Issuer, ca.Certificate.RawSubject) {
		return nil, &scepserver.Failure{Info: scep.BadCertID}
	}
	return []*x509.Certificate{cert}, nil
}

// GetCRL returns an empty CRL signed by the CA.
func (ca *CA) GetCRL(_ context.Context, req *scepserver.Request) ([]byte, error) {
	if err := ca.record(req.Message.MessageType); err != nil {
		return nil, err
	}
	return x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now().Add(-time.Minute),
		NextUpdate: time.Now().Add(time.Hour),
	}, ca.Certificate, ca.Key)
}

// NextCACertificates announces the next CA certificate in rollover mode.
func (ca *CA) NextCACertificates(_ context.Context, name string) ([]*x509.Certificate, *scepserver.Responder, error) {
	if ca.NextCertificate == nil || (ca.opts.Name != "" && name != ca.opts.Name) {
		return nil, nil, scepserver.ErrNotFound
	}
	return []*x509.Certificate{ca.NextCertificate}, ca.responder(), nil
}

// Requester is a device with an RSA key, a self-signed certificate for it and a CSR.
type Requester struct {
	Key         *rsa.PrivateKey
	Certificate *x509.Certificate
	CSR         *x509.CertificateRequest
}

// NewRequester creates a requester whose CSR carries the challenge password.
func NewRequester(t testing.TB, commonName, password string) *Requester {
	t.Helper()
	key := newKey(t)
	csr := NewCSR(t, key, commonName, password)
	cert := create(t, &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      csr.Subject,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}, nil, key, key)
	return &Requester{Key: key, Certificate: cert, CSR: csr}
}

// NewCSR returns a CSR for key that carries the challenge password when it is not empty.
func NewCSR(t testing.TB, key *rsa.PrivateKey, commonName, password string) *x509.CertificateRequest {
	t.Helper()
	der, err := x509util.CreateCertificateRequest(rand.Reader, &x509util.CertificateRequest{
		Subject:           pkix.Name{CommonName: commonName},
		ChallengePassword: password,
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	return csr
}

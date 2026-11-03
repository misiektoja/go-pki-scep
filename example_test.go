package scep_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log"
	"math/big"
	"time"

	"github.com/misiektoja/go-pkcs7"

	scep "github.com/misiektoja/go-pki-scep"
	"github.com/misiektoja/go-pki-scep/x509util"
)

// Example builds a PKCSReq as a requester, answers it as a CA and reads the answer as the requester
// again. The HTTP transport is left out.
func Example() {
	caCert, caKey := newExampleCA()
	deviceCert, deviceKey, csr := newExampleDevice("device-1", "secret")

	// --8<-- [start:request]
	req, err := scep.NewCSRRequest(scep.PKCSReq, csr, scep.RequestOptions{
		Recipients:        []*x509.Certificate{caCert},
		SignerCertificate: deviceCert,
		SignerKey:         deviceKey,
	})
	if err != nil {
		log.Fatal(err)
	}
	// --8<-- [end:request]

	// --8<-- [start:respond]
	msg, err := scep.ParsePKIMessage(req.Raw, scep.ParseOptions{})
	if err != nil {
		log.Fatal(err)
	}
	if err := msg.DecryptPKIEnvelope(caCert, caKey, pkcs7.DecryptOptions{}); err != nil {
		log.Fatal(err)
	}
	opts := scep.ResponseOptions{SignerCertificate: caCert, SignerKey: caKey}
	var rep *scep.PKIMessage
	if msg.ChallengePassword != "secret" {
		rep, err = msg.Fail(scep.BadRequest, opts)
	} else {
		rep, err = msg.Success([]*x509.Certificate{issueExample(caCert, caKey, msg.CSR), caCert}, opts)
	}
	if err != nil {
		log.Fatal(err)
	}
	// --8<-- [end:respond]

	// --8<-- [start:answer]
	answer, err := scep.ParsePKIMessage(rep.Raw, scep.ParseOptions{Signers: []*x509.Certificate{caCert}})
	if err != nil {
		log.Fatal(err)
	}
	if err := answer.MatchesRequest(req); err != nil {
		log.Fatal(err)
	}
	if answer.PKIStatus == scep.SUCCESS {
		if err := answer.DecryptPKIEnvelope(deviceCert, deviceKey, pkcs7.DecryptOptions{}); err != nil {
			log.Fatal(err)
		}
		fmt.Println(answer.PKIStatus, answer.CertRepMessage.Certificates[0].Subject)
	}
	// --8<-- [end:answer]

	// Output: SUCCESS (0) CN=device-1
}

// newExampleCA returns a self-signed RSA CA certificate and its key.
func newExampleCA() (*x509.Certificate, *rsa.PrivateKey) {
	key := newExampleKey()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Example CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	return createExample(template, template, key, key), key
}

// newExampleDevice returns a self-signed certificate, an RSA key and a CSR with the challenge
// password, which a requester signs its PKCSReq with.
func newExampleDevice(name, password string) (*x509.Certificate, *rsa.PrivateKey, *x509.CertificateRequest) {
	key := newExampleKey()
	der, err := x509util.CreateCertificateRequest(rand.Reader, &x509util.CertificateRequest{
		Subject:           pkix.Name{CommonName: name},
		ChallengePassword: password,
	}, key)
	if err != nil {
		log.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		log.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      csr.Subject,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	return createExample(template, template, key, key), key, csr
}

// issueExample signs a certificate for the CSR key.
func issueExample(caCert *x509.Certificate, caKey *rsa.PrivateKey, csr *x509.CertificateRequest) *x509.Certificate {
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      csr.Subject,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}, caCert, csr.PublicKey, caKey)
	if err != nil {
		log.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		log.Fatal(err)
	}
	return cert
}

// createExample signs template with the issuer key and parses the result.
func createExample(template, issuer *x509.Certificate, key, issuerKey *rsa.PrivateKey) *x509.Certificate {
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, &key.PublicKey, issuerKey)
	if err != nil {
		log.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		log.Fatal(err)
	}
	return cert
}

// newExampleKey returns a 2048-bit RSA key.
func newExampleKey() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	return key
}

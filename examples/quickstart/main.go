// A local SCEP server for trying go-pki-scep. A throwaway RSA CA checks a challenge password and is
// served over HTTP. A client enrolls and renews against it.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"time"

	scep "github.com/misiektoja/go-pki-scep"
	"github.com/misiektoja/go-pki-scep/scepclient"
	"github.com/misiektoja/go-pki-scep/scepserver"
	"github.com/misiektoja/go-pki-scep/x509util"
)

// --8<-- [start:ca]

// quickstartCA issues a certificate for every PKCSReq that carries the challenge password and for
// every RenewalReq signed with a certificate it issued. It keeps nothing on disk.
type quickstartCA struct {
	cert     *x509.Certificate
	key      *rsa.PrivateKey
	password string
}

// newQuickstartCA creates a self-signed RSA CA that lives as long as the process.
func newQuickstartCA(password string) (*quickstartCA, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber:          randomSerial(),
		Subject:               pkix.Name{CommonName: "go-pki-scep quickstart CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(30 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		// The CA key signs CertRep messages and decrypts requests, so it needs both usages.
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign |
			x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &quickstartCA{cert: cert, key: key, password: password}, nil
}

// CACertificates answers GetCACert with the CA certificate for any CA name.
func (ca *quickstartCA) CACertificates(context.Context, string) ([]*x509.Certificate, error) {
	return []*x509.Certificate{ca.cert}, nil
}

// Responder returns the CA identity when the request is encrypted for the CA certificate.
func (ca *quickstartCA) Responder(_ context.Context, recipient scep.IssuerAndSerial) (*scepserver.Responder, error) {
	if !bytes.Equal(recipient.Issuer, ca.cert.RawIssuer) || recipient.SerialNumber.Cmp(ca.cert.SerialNumber) != 0 {
		return nil, scepserver.ErrNotFound
	}
	// The RSA CA key signs the answers and, as a crypto.Decrypter, decrypts the requests.
	return &scepserver.Responder{SignerCertificate: ca.cert, SignerKey: ca.key}, nil
}

// Enroll authorizes a PKCSReq by its challenge password and a RenewalReq by its signer certificate.
func (ca *quickstartCA) Enroll(_ context.Context, req *scepserver.Request) ([]*x509.Certificate, error) {
	msg := req.Message
	switch msg.MessageType {
	case scep.PKCSReq:
		if subtle.ConstantTimeCompare([]byte(msg.ChallengePassword), []byte(ca.password)) != 1 {
			return nil, &scepserver.Failure{Info: scep.BadRequest, Err: errors.New("wrong challenge password")}
		}
	default:
		// A RenewalReq is signed with the certificate being renewed. A real CA also checks that the
		// certificate is not revoked and that the CSR asks for the same subject.
		signer := msg.SignerCertificate
		if err := signer.CheckSignatureFrom(ca.cert); err != nil {
			return nil, &scepserver.Failure{Info: scep.BadRequest, Err: fmt.Errorf("renewal signer: %w", err)}
		}
		// The handler refuses a signing-time outside the certificate validity, but that attribute is
		// optional and set by the signer, so check the current time too.
		if time.Now().After(signer.NotAfter) {
			return nil, &scepserver.Failure{Info: scep.BadRequest, Err: errors.New("renewal signer expired")}
		}
	}
	return ca.issue(msg.CSR)
}

// Poll refuses every CertPoll, because this CA never keeps a request pending.
func (ca *quickstartCA) Poll(context.Context, *scepserver.Request) ([]*x509.Certificate, error) {
	return nil, &scepserver.Failure{Info: scep.BadCertID, Err: errors.New("no pending request")}
}

// issue signs a one-day client certificate for the CSR key and returns it with the CA certificate.
func (ca *quickstartCA) issue(csr *x509.CertificateRequest) ([]*x509.Certificate, error) {
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: randomSerial(),
		Subject:      csr.Subject,
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}, ca.cert, csr.PublicKey, ca.key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return []*x509.Certificate{cert, ca.cert}, nil
}

// --8<-- [end:ca]

// randomSerial returns a random 64-bit certificate serial number.
func randomSerial() *big.Int {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	if err != nil {
		panic(err)
	}
	return serial
}

// server is the running SCEP server.
type server struct {
	url         string
	fingerprint [32]byte
	http        *http.Server
}

// start serves SCEP for a new CA on addr under the path /scep.
func start(ctx context.Context, addr, password string, logs io.Writer) (*server, error) {
	ca, err := newQuickstartCA(password)
	if err != nil {
		return nil, err
	}
	// --8<-- [start:handler]
	handler, err := scepserver.NewHandler(ca, scepserver.Options{
		Logger: slog.New(slog.NewTextHandler(logs, nil)),
	})
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.Handle("/scep", handler)
	// --8<-- [end:handler]
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	srv := &server{
		url:         "http://" + listener.Addr().String() + "/scep",
		fingerprint: sha256.Sum256(ca.cert.Raw),
		http:        &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second},
	}
	go func() { _ = srv.http.Serve(listener) }()
	return srv, nil
}

// close stops the server.
func (s *server) close() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = s.http.Shutdown(ctx)
}

// --8<-- [start:client]

// enrollAndRenew enrolls a new key with a PKCSReq and renews its certificate with a RenewalReq.
func enrollAndRenew(ctx context.Context, serverURL string, caFingerprint [32]byte, password string, out io.Writer) error {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	client, err := scepclient.New(serverURL, scepclient.Options{})
	if err != nil {
		return err
	}
	ca, err := client.GetCACert(ctx)
	if err != nil {
		return err
	}
	if err := checkCACertificates(ca, caFingerprint); err != nil {
		return err
	}
	cert, key, err := enroll(ctx, client, ca, password)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(out, "Enrolled %s with serial %s\n", cert.Subject, cert.SerialNumber)
	renewed, err := renew(ctx, client, ca, cert, key)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(out, "Renewed %s with serial %s\n", renewed.Subject, renewed.SerialNumber)
	return nil
}

// --8<-- [end:client]

// --8<-- [start:trust]

// checkCACertificates trusts a GetCACert answer only when the CA certificate has the fingerprint
// obtained out of band and every certificate that signs or decrypts for it was issued by that CA.
func checkCACertificates(ca *scepclient.CACertificates, fingerprint [32]byte) error {
	if sha256.Sum256(ca.CA.Raw) != fingerprint {
		return errors.New("the CA certificate does not match the pinned fingerprint")
	}
	for _, cert := range slices.Concat(ca.Signers, ca.Recipients) {
		if cert.Equal(ca.CA) {
			continue
		}
		if err := cert.CheckSignatureFrom(ca.CA); err != nil {
			return fmt.Errorf("RA certificate %s: %w", cert.Subject, err)
		}
	}
	return nil
}

// --8<-- [end:trust]

// --8<-- [start:enroll]

// enroll creates an RSA key and a CSR with the challenge password and enrolls it with a PKCSReq.
func enroll(ctx context.Context, client *scepclient.Client, ca *scepclient.CACertificates, password string) (*x509.Certificate, *rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	der, err := x509util.CreateCertificateRequest(rand.Reader, &x509util.CertificateRequest{
		Subject:           pkix.Name{CommonName: "quickstart-device"},
		ChallengePassword: password,
	}, key)
	if err != nil {
		return nil, nil, err
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, nil, err
	}
	// A PKCSReq is signed with a self-signed certificate for the CSR key. The answer is encrypted
	// for that certificate.
	signer, err := selfSigned(key, csr.Subject)
	if err != nil {
		return nil, nil, err
	}
	res, err := client.EnrollAndWait(ctx, ca, scepclient.EnrollRequest{
		CSR:               csr,
		SignerCertificate: signer,
		SignerKey:         key,
	}, 5*time.Second)
	if err != nil {
		return nil, nil, err
	}
	if res.Status != scep.SUCCESS {
		return nil, nil, fmt.Errorf("enrollment answered %s %s", res.Status, res.FailInfo)
	}
	return res.Certificate, key, nil
}

// selfSigned returns a short-lived self-signed certificate for key.
func selfSigned(key *rsa.PrivateKey, subject pkix.Name) (*x509.Certificate, error) {
	template := &x509.Certificate{
		SerialNumber: randomSerial(),
		Subject:      subject,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// --8<-- [end:enroll]

// --8<-- [start:renew]

// renew requests a certificate for a new key with a RenewalReq signed by the current certificate.
func renew(ctx context.Context, client *scepclient.Client, ca *scepclient.CACertificates, cert *x509.Certificate, key *rsa.PrivateKey) (*x509.Certificate, error) {
	newKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: cert.Subject}, newKey)
	if err != nil {
		return nil, err
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, err
	}
	res, err := client.Enroll(ctx, ca, scepclient.EnrollRequest{
		MessageType:       scep.RenewalReq,
		CSR:               csr,
		SignerCertificate: cert,
		SignerKey:         key,
	})
	if err != nil {
		return nil, err
	}
	if res.Status != scep.SUCCESS {
		return nil, fmt.Errorf("renewal answered %s %s", res.Status, res.FailInfo)
	}
	return res.Certificate, nil
}

// --8<-- [end:renew]

// run serves SCEP on addr, enrolls and renews once with the client and serves until ctx ends.
func run(ctx context.Context, addr, password string, out io.Writer) error {
	srv, err := start(ctx, addr, password, os.Stderr)
	if err != nil {
		return err
	}
	defer srv.close()
	if err := enrollAndRenew(ctx, srv.url, srv.fingerprint, password, out); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(out, "Serving %s with the challenge password %q.\n", srv.url, password)
	_, _ = fmt.Fprintf(out, "CA certificate SHA-256 fingerprint: %x\n", srv.fingerprint)
	_, _ = fmt.Fprintln(out, "Press Ctrl+C to stop.")
	<-ctx.Done()
	return nil
}

// main parses the flags and runs the server until it is interrupted.
func main() {
	addr := flag.String("addr", "127.0.0.1:8080", "address to serve SCEP on")
	password := flag.String("challenge", "secret", "challenge password a PKCSReq must carry")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	err := run(ctx, *addr, *password, os.Stdout)
	stop()
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "quickstart:", err)
		os.Exit(1)
	}
}

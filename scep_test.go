package scep_test

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"os"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/misiektoja/go-pkcs7"

	scep "github.com/misiektoja/go-pki-scep"
	"github.com/misiektoja/go-pki-scep/x509util"
)

// testCA is a CA that signs its own responses, the common SCEP setup without an RA.
type testCA struct {
	cert *x509.Certificate
	key  *rsa.PrivateKey
}

// testRequester is a device with a key, a self-signed certificate for that key and a CSR.
type testRequester struct {
	key  *rsa.PrivateKey
	cert *x509.Certificate
	csr  *x509.CertificateRequest
}

// newTestCA creates a CA certificate with the key usages a SCEP CA needs.
func newTestCA(t testing.TB) *testCA {
	t.Helper()
	cert, key := createCaCertWithKeyUsage(t, x509.KeyUsageCertSign|x509.KeyUsageCRLSign|x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment)
	return &testCA{cert: cert, key: key}
}

// issue signs a certificate for the CSR.
func (ca *testCA) issue(t *testing.T, csr *x509.CertificateRequest, serial int64) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      csr.Subject,
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}, ca.cert, csr.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// responseOptions signs responses with the CA key.
func (ca *testCA) responseOptions() scep.ResponseOptions {
	return scep.ResponseOptions{SignerCertificate: ca.cert, SignerKey: ca.key}
}

// newTestRequester creates a key, a CSR with a challenge password and a self-signed certificate.
func newTestRequester(t testing.TB, password string) *testRequester {
	t.Helper()
	key := newRSAKey(t, 2048)
	der, err := x509util.CreateCertificateRequest(rand.Reader, &x509util.CertificateRequest{
		Subject:           pkix.Name{CommonName: "device-1", Organization: []string{"Example"}},
		ChallengePassword: password,
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      csr.Subject,
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}, &x509.Certificate{Subject: csr.Subject, SerialNumber: big.NewInt(1)}, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	return &testRequester{key: key, cert: cert, csr: csr}
}

// requestOptions signs requests with the requester's self-signed certificate.
func (r *testRequester) requestOptions(ca *testCA) scep.RequestOptions {
	return scep.RequestOptions{Recipients: []*x509.Certificate{ca.cert}, SignerCertificate: r.cert, SignerKey: r.key}
}

// serve parses a request as a responder does and decrypts its envelope.
func serve(t *testing.T, ca *testCA, raw []byte, opts scep.ParseOptions, decrypt pkcs7.DecryptOptions) *scep.PKIMessage {
	t.Helper()
	msg, err := scep.ParsePKIMessage(raw, opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := msg.DecryptPKIEnvelope(ca.cert, ca.key, decrypt); err != nil {
		t.Fatal(err)
	}
	return msg
}

// receive parses a CertRep as a requester does and checks it answers req.
func receive(t *testing.T, ca *testCA, req *scep.PKIMessage, raw []byte) *scep.PKIMessage {
	t.Helper()
	rep, err := scep.ParsePKIMessage(raw, scep.ParseOptions{Signers: []*x509.Certificate{ca.cert}})
	if err != nil {
		t.Fatal(err)
	}
	if err := rep.MatchesRequest(req); err != nil {
		t.Fatal(err)
	}
	return rep
}

func TestEnrollmentRoundTrip(t *testing.T) {
	ca := newTestCA(t)
	device := newTestRequester(t, "secret")
	for _, messageType := range []scep.MessageType{scep.PKCSReq, scep.RenewalReq, scep.UpdateReq} {
		t.Run(messageType.String(), func(t *testing.T) {
			req, err := scep.NewCSRRequest(messageType, device.csr, device.requestOptions(ca))
			if err != nil {
				t.Fatal(err)
			}
			got := serve(t, ca, req.Raw, scep.ParseOptions{}, pkcs7.DecryptOptions{})
			if got.MessageType != messageType || got.TransactionID != req.TransactionID || !bytes.Equal(got.SenderNonce, req.SenderNonce) {
				t.Fatalf("parsed %s %q, want %s %q with the request nonce", got.MessageType, got.TransactionID, messageType, req.TransactionID)
			}
			if got.ChallengePassword != "secret" || !bytes.Equal(got.CSR.Raw, device.csr.Raw) {
				t.Fatalf("got challenge password %q and a CSR that differs: %v", got.ChallengePassword, !bytes.Equal(got.CSR.Raw, device.csr.Raw))
			}
			if !got.SignerCertificate.Equal(device.cert) || got.Digest != crypto.SHA256 || got.ContentEncryption != pkcs7.AES128CBC {
				t.Fatalf("got signer %v, digest %v and cipher %v", got.SignerCertificate.Subject, got.Digest, got.ContentEncryption)
			}

			issued := ca.issue(t, got.CSR, 10)
			rep, err := got.Success([]*x509.Certificate{issued, ca.cert}, ca.responseOptions())
			if err != nil {
				t.Fatal(err)
			}
			parsed := receive(t, ca, req, rep.Raw)
			if parsed.PKIStatus != scep.SUCCESS || len(parsed.SenderNonce) != 16 || bytes.Equal(parsed.SenderNonce, req.SenderNonce) {
				t.Fatalf("got status %s and a senderNonce that is not fresh", parsed.PKIStatus)
			}
			if err := parsed.DecryptPKIEnvelope(device.cert, device.key, pkcs7.DecryptOptions{}); err != nil {
				t.Fatal(err)
			}
			if len(parsed.CertRepMessage.Certificates) != 2 || !parsed.CertRepMessage.Certificates[0].Equal(issued) {
				t.Fatalf("got %d certificates, want the issued certificate and the CA", len(parsed.CertRepMessage.Certificates))
			}
		})
	}
}

func TestPendingAndCertPoll(t *testing.T) {
	ca := newTestCA(t)
	device := newTestRequester(t, "")
	req, err := scep.NewCSRRequest(scep.PKCSReq, device.csr, device.requestOptions(ca))
	if err != nil {
		t.Fatal(err)
	}
	got := serve(t, ca, req.Raw, scep.ParseOptions{}, pkcs7.DecryptOptions{})
	pending, err := got.Pending(ca.responseOptions())
	if err != nil {
		t.Fatal(err)
	}
	parsed := receive(t, ca, req, pending.Raw)
	if parsed.PKIStatus != scep.PENDING {
		t.Fatalf("got status %s, want PENDING", parsed.PKIStatus)
	}
	if err := parsed.DecryptPKIEnvelope(device.cert, device.key, pkcs7.DecryptOptions{}); err == nil {
		t.Fatal("a PENDING CertRep decrypted")
	}

	pollOpts := device.requestOptions(ca)
	if _, err := scep.NewCertPollRequest(ca.cert.RawSubject, device.csr.RawSubject, pollOpts); err == nil {
		t.Fatal("CertPoll without a transactionID was built")
	}
	pollOpts.TransactionID = req.TransactionID
	poll, err := scep.NewCertPollRequest(ca.cert.RawSubject, device.csr.RawSubject, pollOpts)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(poll.SenderNonce, req.SenderNonce) {
		t.Fatal("CertPoll reused the senderNonce of the enrollment")
	}
	polled := serve(t, ca, poll.Raw, scep.ParseOptions{}, pkcs7.DecryptOptions{})
	if polled.MessageType != scep.CertPoll || polled.TransactionID != req.TransactionID {
		t.Fatalf("parsed %s %q", polled.MessageType, polled.TransactionID)
	}
	if !bytes.Equal(polled.PollRequest.Issuer, ca.cert.RawSubject) || !bytes.Equal(polled.PollRequest.Subject, device.csr.RawSubject) {
		t.Fatal("the CertPoll issuer and subject changed on the way")
	}
	issued := ca.issue(t, device.csr, 11)
	rep, err := polled.Success([]*x509.Certificate{issued}, ca.responseOptions())
	if err != nil {
		t.Fatal(err)
	}
	final := receive(t, ca, poll, rep.Raw)
	if err := final.DecryptPKIEnvelope(device.cert, device.key, pkcs7.DecryptOptions{}); err != nil {
		t.Fatal(err)
	}
	if !final.CertRepMessage.Certificates[0].Equal(issued) {
		t.Fatal("the polled certificate is not the issued one")
	}
}

func TestGetCertAndGetCRL(t *testing.T) {
	ca := newTestCA(t)
	device := newTestRequester(t, "")
	issued := ca.issue(t, device.csr, 12)

	getCert, err := scep.NewGetCertRequest(ca.cert.RawSubject, issued.SerialNumber, device.requestOptions(ca))
	if err != nil {
		t.Fatal(err)
	}
	got := serve(t, ca, getCert.Raw, scep.ParseOptions{}, pkcs7.DecryptOptions{})
	if got.MessageType != scep.GetCert || got.CertificateID.SerialNumber.Cmp(issued.SerialNumber) != 0 || !bytes.Equal(got.CertificateID.Issuer, ca.cert.RawSubject) {
		t.Fatalf("parsed %s for serial %v", got.MessageType, got.CertificateID.SerialNumber)
	}
	if _, err := got.SuccessCRL([]byte{0x30, 0x00}, ca.responseOptions()); err == nil {
		t.Fatal("GetCert was answered with a CRL")
	}
	rep, err := got.Success([]*x509.Certificate{issued}, ca.responseOptions())
	if err != nil {
		t.Fatal(err)
	}
	parsed := receive(t, ca, getCert, rep.Raw)
	if err := parsed.DecryptPKIEnvelope(device.cert, device.key, pkcs7.DecryptOptions{}); err != nil {
		t.Fatal(err)
	}
	if !parsed.CertRepMessage.Certificates[0].Equal(issued) {
		t.Fatal("GetCert returned another certificate")
	}

	crl, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now().Add(-time.Minute),
		NextUpdate: time.Now().Add(time.Hour),
	}, ca.cert, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	getCRL, err := scep.NewGetCRLRequest(ca.cert.RawSubject, issued.SerialNumber, device.requestOptions(ca))
	if err != nil {
		t.Fatal(err)
	}
	got = serve(t, ca, getCRL.Raw, scep.ParseOptions{}, pkcs7.DecryptOptions{})
	if got.MessageType != scep.GetCRL || got.CertificateID.SerialNumber.Cmp(issued.SerialNumber) != 0 {
		t.Fatalf("parsed %s", got.MessageType)
	}
	if _, err := got.Success([]*x509.Certificate{issued}, ca.responseOptions()); err == nil {
		t.Fatal("GetCRL was answered with certificates")
	}
	rep, err = got.SuccessCRL(crl, ca.responseOptions())
	if err != nil {
		t.Fatal(err)
	}
	parsed = receive(t, ca, getCRL, rep.Raw)
	if err := parsed.DecryptPKIEnvelope(device.cert, device.key, pkcs7.DecryptOptions{}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(parsed.CRL, crl) {
		t.Fatal("GetCRL returned another CRL")
	}
}

func TestFail(t *testing.T) {
	ca := newTestCA(t)
	device := newTestRequester(t, "")
	req, err := scep.NewCSRRequest(scep.PKCSReq, device.csr, device.requestOptions(ca))
	if err != nil {
		t.Fatal(err)
	}
	got := serve(t, ca, req.Raw, scep.ParseOptions{}, pkcs7.DecryptOptions{})
	for _, info := range []scep.FailInfo{scep.BadAlg, scep.BadMessageCheck, scep.BadRequest, scep.BadTime, scep.BadCertID} {
		rep, err := got.Fail(info, ca.responseOptions())
		if err != nil {
			t.Fatal(err)
		}
		if rep.FailInfo != info {
			t.Fatalf("built FailInfo %s, want %s", rep.FailInfo, info)
		}
		parsed := receive(t, ca, req, rep.Raw)
		if parsed.PKIStatus != scep.FAILURE || parsed.FailInfo != info {
			t.Fatalf("parsed %s %s, want FAILURE %s", parsed.PKIStatus, parsed.FailInfo, info)
		}
	}
	if _, err := got.Fail("9", ca.responseOptions()); err == nil {
		t.Fatal("an undefined failInfo was sent")
	}
}

// TestResponseFollowsRequestAlgorithms checks that a responder answers with the digest and cipher
// of the request, so an older requester can read the answer.
func TestResponseFollowsRequestAlgorithms(t *testing.T) {
	ca := newTestCA(t)
	device := newTestRequester(t, "")
	for _, tt := range []struct {
		digest crypto.Hash
		cipher pkcs7.ContentEncryptionAlgorithm
	}{
		{crypto.SHA1, pkcs7.DESEDE3CBC},
		{crypto.SHA512, pkcs7.AES256CBC},
		{crypto.MD5, pkcs7.DESCBC},
	} {
		t.Run(tt.digest.String()+"/"+tt.cipher.String(), func(t *testing.T) {
			opts := device.requestOptions(ca)
			opts.Digest = tt.digest
			opts.Encryption = pkcs7.EncryptOptions{ContentEncryption: tt.cipher}
			req, err := scep.NewCSRRequest(scep.PKCSReq, device.csr, opts)
			if err != nil {
				t.Fatal(err)
			}
			if tt.digest == crypto.MD5 {
				if _, err := scep.ParsePKIMessage(req.Raw, scep.ParseOptions{}); err == nil {
					t.Fatal("an MD5 signature was accepted without AllowMD5")
				}
			}
			decrypt := pkcs7.DecryptOptions{ContentEncryptionAlgorithms: []pkcs7.ContentEncryptionAlgorithm{tt.cipher}}
			got := serve(t, ca, req.Raw, scep.ParseOptions{AllowMD5: true}, decrypt)
			if got.Digest != tt.digest || got.ContentEncryption != tt.cipher {
				t.Fatalf("request digest %v and cipher %v, want %v and %v", got.Digest, got.ContentEncryption, tt.digest, tt.cipher)
			}
			rep, err := got.Success([]*x509.Certificate{ca.issue(t, got.CSR, 13)}, ca.responseOptions())
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := scep.ParsePKIMessage(rep.Raw, scep.ParseOptions{Signers: []*x509.Certificate{ca.cert}, AllowMD5: true})
			if err != nil {
				t.Fatal(err)
			}
			if err := parsed.DecryptPKIEnvelope(device.cert, device.key, decrypt); err != nil {
				t.Fatal(err)
			}
			if parsed.Digest != tt.digest || parsed.ContentEncryption != tt.cipher {
				t.Fatalf("response digest %v and cipher %v, want %v and %v", parsed.Digest, parsed.ContentEncryption, tt.digest, tt.cipher)
			}
		})
	}
}

// TestSignersRestrictCertRep checks that a requester accepts a CertRep only from the expected
// signer, even when the message carries a certificate that names the expected issuer and serial
// number with another key.
func TestSignersRestrictCertRep(t *testing.T) {
	ca := newTestCA(t)
	impostor := newTestCA(t)
	device := newTestRequester(t, "")
	req, err := scep.NewCSRRequest(scep.PKCSReq, device.csr, device.requestOptions(ca))
	if err != nil {
		t.Fatal(err)
	}
	got := serve(t, ca, req.Raw, scep.ParseOptions{}, pkcs7.DecryptOptions{})
	rep, err := got.Pending(impostor.responseOptions())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := scep.ParsePKIMessage(rep.Raw, scep.ParseOptions{Signers: []*x509.Certificate{ca.cert}}); err == nil {
		t.Fatal("a CertRep signed by another CA was accepted")
	}
	// The impostor certificate has the subject and serial number of the real CA certificate.
	if impostor.cert.SerialNumber.Cmp(ca.cert.SerialNumber) != 0 || !bytes.Equal(impostor.cert.RawIssuer, ca.cert.RawIssuer) {
		t.Fatal("the impostor certificate does not imitate the CA certificate")
	}
}

// TestCertRepWithoutSenderNonceOrCertificates covers a CertRep shape that some CA products send:
// no senderNonce attribute and no certificates, so the requester verifies it with the CA
// certificate it already has.
func TestCertRepWithoutSenderNonceOrCertificates(t *testing.T) {
	ca := newTestCA(t)
	device := newTestRequester(t, "")
	req, err := scep.NewCSRRequest(scep.PKCSReq, device.csr, device.requestOptions(ca))
	if err != nil {
		t.Fatal(err)
	}
	sd, err := pkcs7.NewSignedData(nil)
	if err != nil {
		t.Fatal(err)
	}
	oid := func(last int) asn1.ObjectIdentifier { return asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, last} }
	if err := sd.AddSigner(ca.cert, ca.key, pkcs7.SignerInfoConfig{ExtraSignedAttributes: []pkcs7.Attribute{
		{Type: oid(7), Value: string(req.TransactionID)},
		{Type: oid(2), Value: string(scep.CertRep)},
		{Type: oid(3), Value: string(scep.PENDING)},
		{Type: oid(6), Value: []byte(req.SenderNonce)},
	}}); err != nil {
		t.Fatal(err)
	}
	sd.RemoveCertificates()
	raw, err := sd.Finish()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := scep.ParsePKIMessage(raw, scep.ParseOptions{}); err == nil {
		t.Fatal("a CertRep without its signer certificate verified without Signers")
	}
	parsed := receive(t, ca, req, raw)
	if parsed.PKIStatus != scep.PENDING || parsed.SenderNonce != nil {
		t.Fatalf("got status %s and senderNonce % X", parsed.PKIStatus, parsed.SenderNonce)
	}
}

func TestMatchesRequest(t *testing.T) {
	ca := newTestCA(t)
	device := newTestRequester(t, "")
	req, err := scep.NewCSRRequest(scep.PKCSReq, device.csr, device.requestOptions(ca))
	if err != nil {
		t.Fatal(err)
	}
	other, err := scep.NewCSRRequest(scep.PKCSReq, device.csr, device.requestOptions(ca))
	if err != nil {
		t.Fatal(err)
	}
	got := serve(t, ca, req.Raw, scep.ParseOptions{}, pkcs7.DecryptOptions{})
	rep, err := got.Pending(ca.responseOptions())
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := scep.ParsePKIMessage(rep.Raw, scep.ParseOptions{Signers: []*x509.Certificate{ca.cert}})
	if err != nil {
		t.Fatal(err)
	}
	// other has the same key-derived transactionID and a different nonce.
	if err := parsed.MatchesRequest(other); err == nil || !strings.Contains(err.Error(), "recipientNonce") {
		t.Fatalf("MatchesRequest with another nonce = %v", err)
	}
	poll := device.requestOptions(ca)
	poll.TransactionID = "another"
	pollReq, err := scep.NewCertPollRequest(ca.cert.RawSubject, device.csr.RawSubject, poll)
	if err != nil {
		t.Fatal(err)
	}
	if err := parsed.MatchesRequest(pollReq); err == nil || !strings.Contains(err.Error(), "transactionID") {
		t.Fatalf("MatchesRequest with another transaction = %v", err)
	}
	if err := req.MatchesRequest(req); err == nil {
		t.Fatal("a request matched itself as a CertRep")
	}
}

func TestRequestValidation(t *testing.T) {
	ca := newTestCA(t)
	device := newTestRequester(t, "")
	opts := device.requestOptions(ca)
	if _, err := scep.NewCSRRequest(scep.CertPoll, device.csr, opts); err == nil {
		t.Fatal("a CertPoll was built with a CSR")
	}
	if _, err := scep.NewCSRRequest(scep.PKCSReq, nil, opts); err == nil {
		t.Fatal("a PKCSReq was built without a CSR")
	}
	if _, err := scep.NewGetCertRequest(ca.cert.RawSubject, nil, opts); err == nil {
		t.Fatal("a GetCert was built without a serial number")
	}
	noRecipients := opts
	noRecipients.Recipients = nil
	if _, err := scep.NewCSRRequest(scep.PKCSReq, device.csr, noRecipients); err == nil {
		t.Fatal("a request was built without recipients")
	}
	noSigner := opts
	noSigner.SignerKey = nil
	if _, err := scep.NewCSRRequest(scep.PKCSReq, device.csr, noSigner); err == nil {
		t.Fatal("a request was built without a signer key")
	}
	badDigest := opts
	badDigest.Digest = crypto.SHA3_256
	if _, err := scep.NewCSRRequest(scep.PKCSReq, device.csr, badDigest); err == nil {
		t.Fatal("a request was signed with an unsupported digest")
	}
}

// TestParseRejectsMissingAttributes builds messages that lack a required attribute.
func TestParseRejectsMissingAttributes(t *testing.T) {
	ca := newTestCA(t)
	device := newTestRequester(t, "")
	oid := func(last int) asn1.ObjectIdentifier { return asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, last} }
	nonce := []byte("0123456789abcdef")
	for _, tt := range []struct {
		name    string
		attrs   []pkcs7.Attribute
		wantErr string
	}{
		{"no transactionID", []pkcs7.Attribute{{Type: oid(2), Value: "19"}, {Type: oid(5), Value: nonce}}, "transactionID"},
		{"empty transactionID", []pkcs7.Attribute{{Type: oid(7), Value: ""}, {Type: oid(2), Value: "19"}, {Type: oid(5), Value: nonce}}, "transactionID"},
		{"no messageType", []pkcs7.Attribute{{Type: oid(7), Value: "t"}, {Type: oid(5), Value: nonce}}, "messageType"},
		{"unknown messageType", []pkcs7.Attribute{{Type: oid(7), Value: "t"}, {Type: oid(2), Value: "99"}, {Type: oid(5), Value: nonce}}, "unknown messageType"},
		{"request without senderNonce", []pkcs7.Attribute{{Type: oid(7), Value: "t"}, {Type: oid(2), Value: "19"}}, "senderNonce"},
		{"oversized senderNonce", []pkcs7.Attribute{{Type: oid(7), Value: "t"}, {Type: oid(2), Value: "19"}, {Type: oid(5), Value: make([]byte, 65)}}, "senderNonce"},
		{"CertRep without pkiStatus", []pkcs7.Attribute{{Type: oid(7), Value: "t"}, {Type: oid(2), Value: "3"}, {Type: oid(6), Value: nonce}}, "pkiStatus"},
		{"CertRep without recipientNonce", []pkcs7.Attribute{{Type: oid(7), Value: "t"}, {Type: oid(2), Value: "3"}, {Type: oid(3), Value: "3"}}, "recipientNonce"},
		{"FAILURE without failInfo", []pkcs7.Attribute{{Type: oid(7), Value: "t"}, {Type: oid(2), Value: "3"}, {Type: oid(3), Value: "2"}, {Type: oid(6), Value: nonce}}, "failInfo"},
		{"unknown pkiStatus", []pkcs7.Attribute{{Type: oid(7), Value: "t"}, {Type: oid(2), Value: "3"}, {Type: oid(3), Value: "1"}, {Type: oid(6), Value: nonce}}, "pkiStatus"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			sd, err := pkcs7.NewSignedData(nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := sd.AddSigner(device.cert, device.key, pkcs7.SignerInfoConfig{ExtraSignedAttributes: tt.attrs}); err != nil {
				t.Fatal(err)
			}
			raw, err := sd.Finish()
			if err != nil {
				t.Fatal(err)
			}
			_, err = scep.ParsePKIMessage(raw, scep.ParseOptions{})
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("ParsePKIMessage = %v, want an error about %s", err, tt.wantErr)
			}
		})
	}
	_ = ca
}

func TestStringsOfUnknownValues(t *testing.T) {
	for _, s := range []string{scep.MessageType("99").String(), scep.PKIStatus("9").String(), scep.FailInfo("9").String()} {
		if !strings.HasPrefix(s, "unknown") {
			t.Fatalf("got %q, want an unknown value description", s)
		}
	}
	if scep.CertPoll.String() != "CertPoll (20)" {
		t.Fatalf("got %q", scep.CertPoll.String())
	}
}

// TestParseFixtures reads messages produced by other SCEP implementations.
func TestParseFixtures(t *testing.T) {
	cacert, cakey := loadCACredentials(t)
	pkcsReq, err := scep.ParsePKIMessage(readTestFile(t, "PKCSReq.der"), scep.ParseOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if pkcsReq.MessageType != scep.PKCSReq || len(pkcsReq.SenderNonce) == 0 {
		t.Fatalf("parsed %s", pkcsReq.MessageType)
	}
	if err := pkcsReq.DecryptPKIEnvelope(cacert, cakey, pkcs7.DecryptOptions{}); err != nil {
		t.Fatal(err)
	}
	if pkcsReq.CSR == nil {
		t.Fatal("the PKCSReq fixture has no CSR")
	}

	certRep, err := scep.ParsePKIMessage(readTestFile(t, "CertRep.der"), scep.ParseOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if certRep.MessageType != scep.CertRep || len(certRep.RecipientNonce) == 0 {
		t.Fatalf("parsed %s", certRep.MessageType)
	}

	noCerts := readTestFile(t, "testca2/CertRep_NoCertificatesForSigners.der")
	if _, err := scep.ParsePKIMessage(noCerts, scep.ParseOptions{}); err == nil {
		t.Fatal("parsed a CertRep without signer certificates")
	}
	ra := decodePEMCert(t, readTestFile(t, "testca2/ca2.pem"))
	if _, err := scep.ParsePKIMessage(noCerts, scep.ParseOptions{Signers: []*x509.Certificate{ra}}); err != nil {
		t.Fatal(err)
	}
}

// TestEnvelopeRecipients checks that a parsed request lists the CA certificate as its recipient
// and that a built message, which keeps no parsed envelope, is refused.
func TestEnvelopeRecipients(t *testing.T) {
	t.Parallel()
	ca := newTestCA(t)
	requester := newTestRequester(t, "")
	msg, err := scep.NewCSRRequest(scep.PKCSReq, requester.csr, requester.requestOptions(ca))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := msg.EnvelopeRecipients(); err == nil {
		t.Error("EnvelopeRecipients succeeded on a built message")
	}
	parsed, err := scep.ParsePKIMessage(msg.Raw, scep.ParseOptions{})
	if err != nil {
		t.Fatal(err)
	}
	recipients, err := parsed.EnvelopeRecipients()
	if err != nil {
		t.Fatal(err)
	}
	if len(recipients) != 1 || !bytes.Equal(recipients[0].Issuer, ca.cert.RawIssuer) ||
		recipients[0].SerialNumber.Cmp(ca.cert.SerialNumber) != 0 {
		t.Errorf("EnvelopeRecipients = %v, want the CA certificate", recipients)
	}
	if err := parsed.DecryptPKIEnvelope(ca.cert, ca.key, pkcs7.DecryptOptions{}); err != nil {
		t.Errorf("DecryptPKIEnvelope after EnvelopeRecipients: %v", err)
	}
}

// TestCSRTransactionID checks that the derived transactionID is stable and is the one
// NewCSRRequest uses.
func TestCSRTransactionID(t *testing.T) {
	t.Parallel()
	ca := newTestCA(t)
	requester := newTestRequester(t, "")
	id, err := scep.CSRTransactionID(requester.csr)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := scep.NewCSRRequest(scep.PKCSReq, requester.csr, requester.requestOptions(ca))
	if err != nil {
		t.Fatal(err)
	}
	if msg.TransactionID != id || len(id) != 40 {
		t.Errorf("transactionID %q, derived %q", msg.TransactionID, id)
	}
	if _, err := scep.CSRTransactionID(nil); err == nil {
		t.Error("CSRTransactionID accepted no CSR")
	}
}

// TestSignedCertificates checks the GetNextCACert encoding: it verifies against the current CA,
// announces only the new certificates and is refused for any other signer.
func TestSignedCertificates(t *testing.T) {
	t.Parallel()
	current := newTestCA(t)
	next := newTestCA(t)
	der, err := scep.SignedCertificates([]*x509.Certificate{next.cert}, current.cert, current.key, 0)
	if err != nil {
		t.Fatal(err)
	}
	announced, err := scep.ParseSignedCertificates(der, []*x509.Certificate{current.cert})
	if err != nil {
		t.Fatal(err)
	}
	if len(announced) != 1 || !announced[0].Equal(next.cert) {
		t.Errorf("ParseSignedCertificates returned %d certificates", len(announced))
	}
	other := newTestCA(t)
	if _, err := scep.ParseSignedCertificates(der, []*x509.Certificate{other.cert}); err == nil {
		t.Error("ParseSignedCertificates accepted another signer")
	}
	if _, err := scep.ParseSignedCertificates(der, nil); err == nil {
		t.Error("ParseSignedCertificates accepted no signers")
	}
	if _, err := scep.SignedCertificates(nil, current.cert, current.key, 0); err == nil {
		t.Error("SignedCertificates accepted no certificates")
	}
	if _, err := scep.SignedCertificates([]*x509.Certificate{next.cert}, current.cert, current.key, crypto.BLAKE2b_256); err == nil {
		t.Error("SignedCertificates accepted an unsupported digest")
	}
}

// TestDecryptPKIEnvelopeKeys checks that decryption refuses a missing certificate or key, a
// non-RSA key and a key the envelope is not addressed to.
func TestDecryptPKIEnvelopeKeys(t *testing.T) {
	ca := newTestCA(t)
	device := newTestRequester(t, "")
	req, err := scep.NewCSRRequest(scep.PKCSReq, device.csr, device.requestOptions(ca))
	if err != nil {
		t.Fatal(err)
	}
	msg, err := scep.ParsePKIMessage(req.Raw, scep.ParseOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := msg.DecryptPKIEnvelope(nil, ca.key, pkcs7.DecryptOptions{}); err == nil {
		t.Fatal("decrypted without a certificate")
	}
	if err := msg.DecryptPKIEnvelope(ca.cert, nil, pkcs7.DecryptOptions{}); err == nil {
		t.Fatal("decrypted without a key")
	}
	if err := msg.DecryptPKIEnvelope(ca.cert, &nonRSADecrypter{}, pkcs7.DecryptOptions{}); err == nil {
		t.Fatal("decrypted with a non-RSA key")
	}
	if err := msg.DecryptPKIEnvelope(device.cert, device.key, pkcs7.DecryptOptions{}); err == nil {
		t.Fatal("decrypted with a key the envelope is not addressed to")
	}
}

// nonRSADecrypter is a decrypter whose public key is not RSA.
type nonRSADecrypter struct{}

// Public returns a value that is not an RSA public key.
func (d *nonRSADecrypter) Public() crypto.PublicKey {
	return struct{}{}
}

// Decrypt always fails.
func (d *nonRSADecrypter) Decrypt(_ io.Reader, _ []byte, _ crypto.DecrypterOpts) ([]byte, error) {
	return nil, errors.New("not implemented")
}

// newRSAKey creates an RSA private key.
func newRSAKey(t testing.TB, bits int) *rsa.PrivateKey {
	t.Helper()
	private, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	return private
}

// readTestFile reads a file under testdata.
func readTestFile(t testing.TB, filepath string) []byte {
	t.Helper()
	data, err := os.ReadFile(path.Join("testdata", filepath))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// createCaCertWithKeyUsage generates a self-signed CA key and certificate with keyUsage.
func createCaCertWithKeyUsage(t testing.TB, keyUsage x509.KeyUsage) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key := newRSAKey(t, 2048)
	template := &x509.Certificate{
		Subject: pkix.Name{
			CommonName:   "SCEP TEST CA",
			Country:      []string{"US"},
			Organization: []string{"Example"},
		},
		SerialNumber:          big.NewInt(1),
		KeyUsage:              keyUsage,
		NotBefore:             time.Now().Add(-10 * time.Minute),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

// loadCACredentials loads the CA of the fixtures.
func loadCACredentials(t testing.TB) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	return decodePEMCert(t, readTestFile(t, "testca/ca.crt")), loadKeyFromFile(t, "testca/ca.key")
}

// loadKeyFromFile loads a PKCS #1 key, decrypting the legacy PEM encryption of the fixture CA key.
func loadKeyFromFile(t testing.TB, filepath string) *rsa.PrivateKey {
	t.Helper()
	block, _ := pem.Decode(readTestFile(t, filepath))
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		t.Fatalf("%s holds no RSA private key", filepath)
	}
	der := block.Bytes
	if len(block.Headers) > 0 {
		var err error
		//nolint:staticcheck // The fixture key uses legacy PEM encryption with an empty password.
		if der, err = x509.DecryptPEMBlock(block, []byte("")); err != nil {
			t.Fatal(err)
		}
	}
	key, err := x509.ParsePKCS1PrivateKey(der)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// decodePEMCert parses one PEM certificate.
func decodePEMCert(t testing.TB, data []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("PEM data holds no certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

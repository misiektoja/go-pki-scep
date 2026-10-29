package scepserver_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/misiektoja/go-pkcs7"

	"github.com/misiektoja/go-scep"
	"github.com/misiektoja/go-scep/internal/testca"
	"github.com/misiektoja/go-scep/scepserver"
)

// newHandler returns a handler for ca or fails the test.
func newHandler(t testing.TB, ca scepserver.CA, opts scepserver.Options) *scepserver.Handler {
	t.Helper()
	handler, err := scepserver.NewHandler(ca, opts)
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

// serve sends one request to the handler.
func serve(handler http.Handler, method, target string, body []byte) *httptest.ResponseRecorder {
	req := httptest.NewRequestWithContext(context.Background(), method, target, bytes.NewReader(body))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

// pkcsReq builds a PKCSReq from a new requester to the CA certificate.
func pkcsReq(t testing.TB, ca *testca.CA, encryption pkcs7.EncryptOptions) *scep.PKIMessage {
	t.Helper()
	requester := testca.NewRequester(t, "device-1", "")
	msg, err := scep.NewCSRRequest(scep.PKCSReq, requester.CSR, scep.RequestOptions{
		Recipients:        []*x509.Certificate{ca.Certificate},
		SignerCertificate: requester.Certificate,
		SignerKey:         requester.Key,
		Encryption:        encryption,
	})
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

// certRep parses an answer as the requester does.
func certRep(t *testing.T, ca *testca.CA, rec *httptest.ResponseRecorder) *scep.PKIMessage {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("HTTP %d: %s", rec.Code, rec.Body)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/x-pki-message" {
		t.Fatalf("Content-Type = %q", got)
	}
	rep, err := scep.ParsePKIMessage(rec.Body.Bytes(), scep.ParseOptions{Signers: []*x509.Certificate{ca.Certificate}})
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

// TestNewHandler covers the option checks.
func TestNewHandler(t *testing.T) {
	t.Parallel()
	ca := testca.New(t, testca.Options{})
	if _, err := scepserver.NewHandler(nil, scepserver.Options{}); err == nil {
		t.Error("NewHandler accepted no CA")
	}
	if _, err := scepserver.NewHandler(ca, scepserver.Options{MaxMessageBytes: -1}); err == nil {
		t.Error("NewHandler accepted a negative MaxMessageBytes")
	}
	for _, caps := range [][]string{{""}, {"AES\nRenewal"}} {
		if _, err := scepserver.NewHandler(ca, scepserver.Options{Capabilities: caps}); err == nil {
			t.Errorf("NewHandler accepted capabilities %q", caps)
		}
	}
}

// TestGetCACaps covers the default capabilities, which follow the accepted ciphers and the
// optional CA interfaces, and a replaced list.
func TestGetCACaps(t *testing.T) {
	t.Parallel()
	ca := testca.New(t, testca.Options{})
	caps := func(handler http.Handler) []string {
		rec := serve(handler, http.MethodGet, "/scep?operation=GetCACaps", nil)
		if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/plain") {
			t.Fatalf("GetCACaps: HTTP %d, %s", rec.Code, rec.Header().Get("Content-Type"))
		}
		return strings.Fields(rec.Body.String())
	}

	got := caps(newHandler(t, ca, scepserver.Options{}))
	for _, want := range []string{"AES", "DES3", "GetNextCACert", "POSTPKIOperation", "Renewal", "SCEPStandard", "SHA-256"} {
		if !slices.Contains(got, want) {
			t.Errorf("default capabilities %v miss %s", got, want)
		}
	}
	got = caps(newHandler(t, minimalCA{ca}, scepserver.Options{
		Decrypt: pkcs7.DecryptOptions{ContentEncryptionAlgorithms: []pkcs7.ContentEncryptionAlgorithm{pkcs7.DESEDE3CBC}},
	}))
	for _, unwanted := range []string{"AES", "SCEPStandard", "GetNextCACert"} {
		if slices.Contains(got, unwanted) {
			t.Errorf("capabilities %v list %s for a 3DES-only CA without rollover", got, unwanted)
		}
	}
	if got = caps(newHandler(t, ca, scepserver.Options{Capabilities: []string{"POSTPKIOperation"}})); !slices.Equal(got, []string{"POSTPKIOperation"}) {
		t.Errorf("replaced capabilities = %v", got)
	}
}

// TestGetCACert covers a single CA certificate, a CA with RA certificates and an unknown name.
func TestGetCACert(t *testing.T) {
	t.Parallel()
	ca := testca.New(t, testca.Options{Name: "issuing"})
	rec := serve(newHandler(t, ca, scepserver.Options{}), http.MethodGet, "/scep?operation=GetCACert&message=issuing", nil)
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/x-x509-ca-cert" ||
		!bytes.Equal(rec.Body.Bytes(), ca.Certificate.Raw) {
		t.Errorf("GetCACert: HTTP %d, %s", rec.Code, rec.Header().Get("Content-Type"))
	}
	rec = serve(newHandler(t, ca, scepserver.Options{}), http.MethodGet, "/scep?operation=GetCACert&message=other", nil)
	if rec.Code != http.StatusNotFound {
		t.Errorf("GetCACert for an unknown name: HTTP %d", rec.Code)
	}

	ra := testca.New(t, testca.Options{RA: true})
	rec = serve(newHandler(t, ra, scepserver.Options{}), http.MethodGet, "/scep?operation=GetCACert", nil)
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/x-x509-ca-ra-cert" {
		t.Fatalf("GetCACert with an RA: HTTP %d, %s", rec.Code, rec.Header().Get("Content-Type"))
	}
	certs, err := scep.CACerts(rec.Body.Bytes())
	if err != nil || len(certs) != 3 {
		t.Errorf("GetCACert with an RA returned %d certificates: %v", len(certs), err)
	}
}

// TestGetCACertChain covers a chain up to a root, a single self-signed CA, an unknown name and a
// POST.
func TestGetCACertChain(t *testing.T) {
	t.Parallel()
	ca := testca.New(t, testca.Options{Name: "issuing", Root: true})
	handler := newHandler(t, ca, scepserver.Options{})
	rec := serve(handler, http.MethodGet, "/scep?operation=GetCACertChain&message=issuing", nil)
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/x-x509-ca-ra-cert" {
		t.Fatalf("GetCACertChain: HTTP %d, %s", rec.Code, rec.Header().Get("Content-Type"))
	}
	certs, err := scep.CACerts(rec.Body.Bytes())
	if err != nil || len(certs) != 2 || !certs[0].Equal(ca.Certificate) || !certs[1].Equal(ca.Root) {
		t.Errorf("GetCACertChain returned %d certificates: %v", len(certs), err)
	}
	if rec := serve(handler, http.MethodGet, "/scep?operation=GetCACertChain&message=other", nil); rec.Code != http.StatusNotFound {
		t.Errorf("GetCACertChain for an unknown name: HTTP %d", rec.Code)
	}
	if rec := serve(handler, http.MethodPost, "/scep?operation=GetCACertChain&message=issuing", nil); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST GetCACertChain: HTTP %d", rec.Code)
	}

	// A single certificate is still sent as a SignedData, unlike GetCACert.
	root := testca.New(t, testca.Options{})
	rec = serve(newHandler(t, root, scepserver.Options{}), http.MethodGet, "/scep?operation=GetCACertChain", nil)
	certs, err = scep.CACerts(rec.Body.Bytes())
	if rec.Code != http.StatusOK || err != nil || len(certs) != 1 || !certs[0].Equal(root.Certificate) {
		t.Errorf("GetCACertChain for a self-signed CA: HTTP %d, %d certificates, %v", rec.Code, len(certs), err)
	}
}

// TestOperationAndMethod covers unknown operations and methods an operation does not take.
func TestOperationAndMethod(t *testing.T) {
	t.Parallel()
	handler := newHandler(t, testca.New(t, testca.Options{}), scepserver.Options{})
	if rec := serve(handler, http.MethodGet, "/scep", nil); rec.Code != http.StatusBadRequest {
		t.Errorf("no operation: HTTP %d", rec.Code)
	}
	if rec := serve(handler, http.MethodPost, "/scep?operation=GetCACaps", nil); rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != "GET" {
		t.Errorf("POST GetCACaps: HTTP %d, Allow %q", rec.Code, rec.Header().Get("Allow"))
	}
	if rec := serve(handler, http.MethodPut, "/scep?operation=PKIOperation", nil); rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != "GET, POST" {
		t.Errorf("PUT PKIOperation: HTTP %d, Allow %q", rec.Code, rec.Header().Get("Allow"))
	}
}

// TestPKIOperationTransports covers POST, GET with an escaped message parameter and GET from a
// client that leaves '+' unescaped.
func TestPKIOperationTransports(t *testing.T) {
	t.Parallel()
	ca := testca.New(t, testca.Options{})
	handler := newHandler(t, ca, scepserver.Options{})
	send := map[string]func(msg *scep.PKIMessage) *httptest.ResponseRecorder{
		"POST": func(msg *scep.PKIMessage) *httptest.ResponseRecorder {
			return serve(handler, http.MethodPost, "/scep?operation=PKIOperation", msg.Raw)
		},
		"GET escaped": func(msg *scep.PKIMessage) *httptest.ResponseRecorder {
			query := url.Values{"operation": {"PKIOperation"}, "message": {base64.StdEncoding.EncodeToString(msg.Raw)}}
			return serve(handler, http.MethodGet, "/scep?"+query.Encode(), nil)
		},
		"GET unescaped plus": func(msg *scep.PKIMessage) *httptest.ResponseRecorder {
			encoded := base64.StdEncoding.EncodeToString(msg.Raw)
			encoded = strings.NewReplacer("/", "%2F", "=", "%3D").Replace(encoded)
			return serve(handler, http.MethodGet, "/scep?operation=PKIOperation&message="+encoded, nil)
		},
	}
	for name, fn := range send {
		msg := pkcsReq(t, ca, pkcs7.EncryptOptions{})
		rep := certRep(t, ca, fn(msg))
		if err := rep.MatchesRequest(msg); err != nil || rep.PKIStatus != scep.SUCCESS {
			t.Errorf("%s: %s, %v", name, rep.PKIStatus, err)
		}
	}
}

// TestPKIOperationRefusals covers requests answered with an HTTP error instead of a CertRep.
func TestPKIOperationRefusals(t *testing.T) {
	t.Parallel()
	ca := testca.New(t, testca.Options{})
	handler := newHandler(t, ca, scepserver.Options{MaxMessageBytes: 1024})
	msg := pkcsReq(t, ca, pkcs7.EncryptOptions{})

	other := testca.New(t, testca.Options{})
	misaddressed := pkcsReq(t, other, pkcs7.EncryptOptions{})

	parsed, err := scep.ParsePKIMessage(msg.Raw, scep.ParseOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := parsed.DecryptPKIEnvelope(ca.Certificate, ca.Key, pkcs7.DecryptOptions{}); err != nil {
		t.Fatal(err)
	}
	rep, err := parsed.Pending(scep.ResponseOptions{SignerCertificate: ca.Certificate, SignerKey: ca.Key})
	if err != nil {
		t.Fatal(err)
	}

	large := newHandler(t, ca, scepserver.Options{})
	cases := []struct {
		name    string
		handler http.Handler
		method  string
		target  string
		body    []byte
		want    int
	}{
		{"empty POST", handler, http.MethodPost, "/scep?operation=PKIOperation", nil, http.StatusBadRequest},
		{"POST over the limit", handler, http.MethodPost, "/scep?operation=PKIOperation", msg.Raw, http.StatusRequestEntityTooLarge},
		{"GET over the limit", handler, http.MethodGet, "/scep?operation=PKIOperation&message=" + url.QueryEscape(base64.StdEncoding.EncodeToString(msg.Raw)), nil, http.StatusRequestURITooLong},
		{"GET without message", handler, http.MethodGet, "/scep?operation=PKIOperation", nil, http.StatusBadRequest},
		{"GET with bad base64", handler, http.MethodGet, "/scep?operation=PKIOperation&message=%21%21", nil, http.StatusBadRequest},
		{"garbage", large, http.MethodPost, "/scep?operation=PKIOperation", []byte("not a pkiMessage"), http.StatusBadRequest},
		{"another CA", large, http.MethodPost, "/scep?operation=PKIOperation", misaddressed.Raw, http.StatusBadRequest},
		{"a CertRep", large, http.MethodPost, "/scep?operation=PKIOperation", rep.Raw, http.StatusBadRequest},
	}
	for _, tc := range cases {
		if rec := serve(tc.handler, tc.method, tc.target, tc.body); rec.Code != tc.want {
			t.Errorf("%s: HTTP %d, want %d", tc.name, rec.Code, tc.want)
		}
	}
}

// TestDecryptFailInfo covers a cipher the handler does not accept, answered with badAlg, and the
// option that accepts it.
func TestDecryptFailInfo(t *testing.T) {
	t.Parallel()
	ca := testca.New(t, testca.Options{})
	des := pkcs7.EncryptOptions{ContentEncryption: pkcs7.DESCBC}

	msg := pkcsReq(t, ca, des)
	rep := certRep(t, ca, serve(newHandler(t, ca, scepserver.Options{}), http.MethodPost, "/scep?operation=PKIOperation", msg.Raw))
	if rep.PKIStatus != scep.FAILURE || rep.FailInfo != scep.BadAlg {
		t.Errorf("single DES by default: %s %s, want FAILURE badAlg", rep.PKIStatus, rep.FailInfo)
	}

	allowDES := scepserver.Options{Decrypt: pkcs7.DecryptOptions{ContentEncryptionAlgorithms: []pkcs7.ContentEncryptionAlgorithm{pkcs7.DESCBC}}}
	msg = pkcsReq(t, ca, des)
	rep = certRep(t, ca, serve(newHandler(t, ca, allowDES), http.MethodPost, "/scep?operation=PKIOperation", msg.Raw))
	if rep.PKIStatus != scep.SUCCESS {
		t.Errorf("single DES when allowed: %s", rep.PKIStatus)
	}
}

// TestNonRSARequester covers a requester whose certificate the answer cannot be encrypted for.
func TestNonRSARequester(t *testing.T) {
	t.Parallel()
	ca := testca.New(t, testca.Options{})
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ec-device"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	csr := testca.NewRequester(t, "ec-device", "").CSR
	msg, err := scep.NewCSRRequest(scep.PKCSReq, csr, scep.RequestOptions{
		Recipients:        []*x509.Certificate{ca.Certificate},
		SignerCertificate: cert,
		SignerKey:         key,
	})
	if err != nil {
		t.Fatal(err)
	}
	rep := certRep(t, ca, serve(newHandler(t, ca, scepserver.Options{}), http.MethodPost, "/scep?operation=PKIOperation", msg.Raw))
	if rep.PKIStatus != scep.FAILURE || rep.FailInfo != scep.BadAlg {
		t.Errorf("EC requester: %s %s, want FAILURE badAlg", rep.PKIStatus, rep.FailInfo)
	}
}

// outcomeCA answers every enrollment with a fixed outcome.
type outcomeCA struct {
	*testca.CA
	certs []*x509.Certificate
	err   error
}

// Enroll returns the fixed outcome.
func (ca outcomeCA) Enroll(context.Context, *scepserver.Request) ([]*x509.Certificate, error) {
	return ca.certs, ca.err
}

// TestCAOutcomes covers how the handler answers each kind of CA result.
func TestCAOutcomes(t *testing.T) {
	t.Parallel()
	ca := testca.New(t, testca.Options{})
	cases := []struct {
		name       string
		err        error
		wantCode   int
		retryAfter string
		status     scep.PKIStatus
		failInfo   scep.FailInfo
	}{
		{"failure", &scepserver.Failure{Info: scep.BadTime, Err: errors.New("clock skew")}, http.StatusOK, "", scep.FAILURE, scep.BadTime},
		{"wrapped failure", errors.Join(errors.New("context"), &scepserver.Failure{Info: scep.BadRequest}), http.StatusOK, "", scep.FAILURE, scep.BadRequest},
		{"pending", scepserver.ErrPending, http.StatusOK, "", scep.PENDING, ""},
		{"busy with delay", &scepserver.Busy{RetryAfter: 1500 * time.Millisecond}, http.StatusServiceUnavailable, "2", "", ""},
		{"busy without delay", &scepserver.Busy{}, http.StatusServiceUnavailable, "", "", ""},
		{"internal error", errors.New("database unavailable"), http.StatusInternalServerError, "", "", ""},
		{"no certificates", nil, http.StatusInternalServerError, "", "", ""},
		{"invalid failInfo", &scepserver.Failure{Info: "9"}, http.StatusInternalServerError, "", "", ""},
	}
	for _, tc := range cases {
		handler := newHandler(t, outcomeCA{CA: ca, err: tc.err}, scepserver.Options{})
		rec := serve(handler, http.MethodPost, "/scep?operation=PKIOperation", pkcsReq(t, ca, pkcs7.EncryptOptions{}).Raw)
		if rec.Code != tc.wantCode || rec.Header().Get("Retry-After") != tc.retryAfter {
			t.Errorf("%s: HTTP %d, Retry-After %q", tc.name, rec.Code, rec.Header().Get("Retry-After"))
			continue
		}
		if tc.wantCode != http.StatusOK {
			continue
		}
		if rep := certRep(t, ca, rec); rep.PKIStatus != tc.status || rep.FailInfo != tc.failInfo {
			t.Errorf("%s: %s %s", tc.name, rep.PKIStatus, rep.FailInfo)
		}
	}
	if !strings.Contains((&scepserver.Failure{Info: scep.BadTime, Err: errors.New("clock skew")}).Error(), "clock skew") {
		t.Error("Failure.Error does not include the cause")
	}
}

// minimalCA implements only the required CA methods.
type minimalCA struct {
	ca *testca.CA
}

// CACertificates forwards to the test CA.
func (m minimalCA) CACertificates(ctx context.Context, name string) ([]*x509.Certificate, error) {
	return m.ca.CACertificates(ctx, name)
}

// Responder forwards to the test CA.
func (m minimalCA) Responder(ctx context.Context, recipient scep.IssuerAndSerial) (*scepserver.Responder, error) {
	return m.ca.Responder(ctx, recipient)
}

// Enroll forwards to the test CA.
func (m minimalCA) Enroll(ctx context.Context, req *scepserver.Request) ([]*x509.Certificate, error) {
	return m.ca.Enroll(ctx, req)
}

// Poll forwards to the test CA.
func (m minimalCA) Poll(ctx context.Context, req *scepserver.Request) ([]*x509.Certificate, error) {
	return m.ca.Poll(ctx, req)
}

// TestOptionalOperations covers a CA that answers neither GetCert, GetCRL, GetNextCACert nor
// GetCACertChain.
func TestOptionalOperations(t *testing.T) {
	t.Parallel()
	ca := testca.New(t, testca.Options{})
	handler := newHandler(t, minimalCA{ca}, scepserver.Options{})
	requester := testca.NewRequester(t, "device-1", "")
	opts := scep.RequestOptions{
		Recipients:        []*x509.Certificate{ca.Certificate},
		SignerCertificate: requester.Certificate,
		SignerKey:         requester.Key,
	}
	getCert, err := scep.NewGetCertRequest(ca.Certificate.RawSubject, big.NewInt(5), opts)
	if err != nil {
		t.Fatal(err)
	}
	getCRL, err := scep.NewGetCRLRequest(ca.Certificate.RawSubject, big.NewInt(5), opts)
	if err != nil {
		t.Fatal(err)
	}
	for _, msg := range []*scep.PKIMessage{getCert, getCRL} {
		rep := certRep(t, ca, serve(handler, http.MethodPost, "/scep?operation=PKIOperation", msg.Raw))
		if rep.PKIStatus != scep.FAILURE || rep.FailInfo != scep.BadRequest {
			t.Errorf("%s without support: %s %s", msg.MessageType, rep.PKIStatus, rep.FailInfo)
		}
	}
	for _, operation := range []string{"GetNextCACert", "GetCACertChain"} {
		if rec := serve(handler, http.MethodGet, "/scep?operation="+operation, nil); rec.Code != http.StatusNotImplemented {
			t.Errorf("%s without support: HTTP %d", operation, rec.Code)
		}
	}
}

// recordingHandler collects the levels of the records it receives.
type recordingHandler struct {
	mu     sync.Mutex
	levels []slog.Level
}

// Enabled accepts every level.
func (*recordingHandler) Enabled(context.Context, slog.Level) bool { return true }

// Handle records the level.
func (h *recordingHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.levels = append(h.levels, r.Level)
	return nil
}

// WithAttrs returns the same handler.
func (h *recordingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }

// WithGroup returns the same handler.
func (h *recordingHandler) WithGroup(string) slog.Handler { return h }

// TestLogger covers the log levels of an answer, a refusal and an internal error.
func TestLogger(t *testing.T) {
	t.Parallel()
	ca := testca.New(t, testca.Options{})
	logs := &recordingHandler{}
	opts := scepserver.Options{Logger: slog.New(logs)}
	serve(newHandler(t, ca, opts), http.MethodPost, "/scep?operation=PKIOperation", pkcsReq(t, ca, pkcs7.EncryptOptions{}).Raw)
	serve(newHandler(t, ca, opts), http.MethodPost, "/scep?operation=PKIOperation", []byte("garbage"))
	serve(newHandler(t, outcomeCA{CA: ca, err: errors.New("down")}, opts), http.MethodPost, "/scep?operation=PKIOperation", pkcsReq(t, ca, pkcs7.EncryptOptions{}).Raw)
	want := []slog.Level{slog.LevelInfo, slog.LevelWarn, slog.LevelError}
	if !slices.Equal(logs.levels, want) {
		t.Errorf("log levels = %v, want %v", logs.levels, want)
	}
}

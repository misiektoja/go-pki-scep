package scepclient_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"maps"
	"math/big"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/misiektoja/go-pkcs7"

	"github.com/misiektoja/go-scep"
	"github.com/misiektoja/go-scep/internal/testca"
	"github.com/misiektoja/go-scep/scepclient"
	"github.com/misiektoja/go-scep/scepserver"
)

// testServer runs a scepserver handler for ca and records the HTTP methods of PKIOperation.
type testServer struct {
	*httptest.Server
	mu      sync.Mutex
	methods []string
}

// newTestServer starts a server for ca with the handler options.
func newTestServer(t *testing.T, ca scepserver.CA, opts scepserver.Options) *testServer {
	t.Helper()
	handler, err := scepserver.NewHandler(ca, opts)
	if err != nil {
		t.Fatal(err)
	}
	ts := &testServer{}
	ts.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("operation") == "PKIOperation" {
			ts.mu.Lock()
			ts.methods = append(ts.methods, r.Method)
			ts.mu.Unlock()
		}
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(ts.Close)
	return ts
}

// pkiMethods returns the HTTP methods of the PKIOperation requests so far.
func (ts *testServer) pkiMethods() []string {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	return slices.Clone(ts.methods)
}

// newClient returns a client for the server with short busy delays.
func newClient(t *testing.T, url string, opts scepclient.Options) *scepclient.Client {
	t.Helper()
	if opts.BusyDelay == 0 {
		opts.BusyDelay = 10 * time.Millisecond
	}
	client, err := scepclient.New(url, opts)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

// enrollRequest returns a PKCSReq for the requester.
func enrollRequest(r *testca.Requester) scepclient.EnrollRequest {
	return scepclient.EnrollRequest{CSR: r.CSR, SignerCertificate: r.Certificate, SignerKey: r.Key}
}

// TestEnroll covers a PKCSReq that a CA without an RA issues at once, sent with POST.
func TestEnroll(t *testing.T) {
	t.Parallel()
	ca := testca.New(t, testca.Options{Password: "secret"})
	ts := newTestServer(t, ca, scepserver.Options{})
	client := newClient(t, ts.URL, scepclient.Options{})
	ctx := t.Context()

	caps, err := client.GetCACaps(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"POSTPKIOperation", "SHA-256", "AES", "Renewal"} {
		if !caps.Has(strings.ToLower(want)) {
			t.Errorf("capabilities %v miss %s", caps, want)
		}
	}
	certs, err := client.GetCACert(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !certs.CA.Equal(ca.Certificate) || len(certs.Recipients) != 1 || len(certs.Signers) != 1 {
		t.Fatalf("GetCACert sorted %d recipients and %d signers", len(certs.Recipients), len(certs.Signers))
	}

	requester := testca.NewRequester(t, "device-1", "secret")
	res, err := client.Enroll(ctx, certs, enrollRequest(requester))
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != scep.SUCCESS || res.Certificate == nil {
		t.Fatalf("Enroll = %s, certificate %v", res.Status, res.Certificate)
	}
	if !requester.Key.PublicKey.Equal(res.Certificate.PublicKey) || len(res.Certificates) != 2 {
		t.Errorf("Enroll returned the wrong certificate or %d certificates", len(res.Certificates))
	}
	if err := res.Certificate.CheckSignatureFrom(ca.Certificate); err != nil {
		t.Errorf("issued certificate: %v", err)
	}
	if got := ts.pkiMethods(); !slices.Equal(got, []string{http.MethodPost}) {
		t.Errorf("PKIOperation methods = %v, want one POST", got)
	}
}

// TestEnrollRefused covers a FAILURE answer, which is a result rather than an error.
func TestEnrollRefused(t *testing.T) {
	t.Parallel()
	ca := testca.New(t, testca.Options{Password: "secret"})
	ts := newTestServer(t, ca, scepserver.Options{})
	client := newClient(t, ts.URL, scepclient.Options{})
	certs, err := client.GetCACert(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	res, err := client.Enroll(t.Context(), certs, enrollRequest(testca.NewRequester(t, "device-1", "wrong")))
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != scep.FAILURE || res.FailInfo != scep.BadRequest || res.Certificate != nil {
		t.Errorf("Enroll = %s %s, want FAILURE badRequest", res.Status, res.FailInfo)
	}
}

// TestEnrollThroughRA covers an RA with separate signing and encryption certificates.
func TestEnrollThroughRA(t *testing.T) {
	t.Parallel()
	ca := testca.New(t, testca.Options{RA: true, Name: "issuing"})
	ts := newTestServer(t, ca, scepserver.Options{})
	ctx := t.Context()

	if _, err := newClient(t, ts.URL, scepclient.Options{CAName: "other"}).GetCACert(ctx); !isHTTPStatus(err, http.StatusNotFound) {
		t.Errorf("GetCACert for an unknown CA name: error = %v, want HTTP 404", err)
	}
	client := newClient(t, ts.URL, scepclient.Options{CAName: "issuing"})
	certs, err := client.GetCACert(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !certs.CA.Equal(ca.Certificate) || len(certs.All) != 3 {
		t.Fatalf("GetCACert CA %v, %d certificates", certs.CA.Subject, len(certs.All))
	}
	if !slices.EqualFunc(certs.Recipients, []*x509.Certificate{ca.RAEncrypter}, (*x509.Certificate).Equal) {
		t.Errorf("recipients are not the RA encryption certificate")
	}
	if !slices.EqualFunc(certs.Signers, []*x509.Certificate{ca.RASigner, ca.Certificate}, (*x509.Certificate).Equal) {
		t.Errorf("signers are not the RA signing certificate and the CA certificate")
	}
	res, err := client.Enroll(ctx, certs, enrollRequest(testca.NewRequester(t, "device-1", "")))
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != scep.SUCCESS || !res.Response.SignerCertificate.Equal(ca.RASigner) {
		t.Errorf("Enroll = %s, want SUCCESS signed by the RA", res.Status)
	}
}

// TestEnrollAndWait covers manual approval: PENDING, CertPoll and SUCCESS.
func TestEnrollAndWait(t *testing.T) {
	t.Parallel()
	ca := testca.New(t, testca.Options{Manual: true, ApproveAfterPolls: 2})
	ts := newTestServer(t, ca, scepserver.Options{})
	client := newClient(t, ts.URL, scepclient.Options{})
	certs, err := client.GetCACert(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	res, err := client.EnrollAndWait(ctx, certs, enrollRequest(testca.NewRequester(t, "device-1", "")), 10*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != scep.SUCCESS || res.Certificate == nil {
		t.Fatalf("EnrollAndWait = %s", res.Status)
	}
	want := []scep.MessageType{scep.PKCSReq, scep.CertPoll, scep.CertPoll}
	if got := ca.Requests(); !slices.Equal(got, want) {
		t.Errorf("requests = %v, want %v", got, want)
	}
}

// TestPollDerivesTransactionID covers a poll that sends no transaction ID after a restart.
func TestPollDerivesTransactionID(t *testing.T) {
	t.Parallel()
	ca := testca.New(t, testca.Options{Manual: true})
	ts := newTestServer(t, ca, scepserver.Options{})
	client := newClient(t, ts.URL, scepclient.Options{})
	ctx := t.Context()
	certs, err := client.GetCACert(ctx)
	if err != nil {
		t.Fatal(err)
	}
	req := enrollRequest(testca.NewRequester(t, "device-1", ""))
	res, err := client.Enroll(ctx, certs, req)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != scep.PENDING {
		t.Fatalf("Enroll = %s, want PENDING", res.Status)
	}
	if res, err = client.Poll(ctx, certs, req); err != nil || res.Status != scep.PENDING {
		t.Fatalf("Poll before approval = %v, %v", res, err)
	}
	ca.Approve(res.TransactionID)
	if res, err = client.Poll(ctx, certs, req); err != nil || res.Status != scep.SUCCESS {
		t.Fatalf("Poll after approval = %v, %v", res, err)
	}

	other := enrollRequest(testca.NewRequester(t, "device-2", ""))
	if res, err = client.Poll(ctx, certs, other); err != nil || res.FailInfo != scep.BadCertID {
		t.Errorf("Poll for an unknown transaction = %v, %v, want FAILURE badCertID", res, err)
	}
	ctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := client.EnrollAndWait(ctx, certs, other, time.Millisecond); !errors.Is(err, context.Canceled) {
		t.Errorf("EnrollAndWait with a cancelled context: error = %v", err)
	}
}

// TestRenewal covers a RenewalReq signed with the certificate being renewed.
func TestRenewal(t *testing.T) {
	t.Parallel()
	ca := testca.New(t, testca.Options{})
	ts := newTestServer(t, ca, scepserver.Options{})
	client := newClient(t, ts.URL, scepclient.Options{})
	ctx := t.Context()
	certs, err := client.GetCACert(ctx)
	if err != nil {
		t.Fatal(err)
	}
	requester := testca.NewRequester(t, "device-1", "")
	first, err := client.Enroll(ctx, certs, enrollRequest(requester))
	if err != nil || first.Status != scep.SUCCESS {
		t.Fatalf("Enroll = %v, %v", first, err)
	}

	newKey := testca.NewRequester(t, "device-1", "")
	renewal := scepclient.EnrollRequest{
		MessageType:       scep.RenewalReq,
		CSR:               newKey.CSR,
		SignerCertificate: first.Certificate,
		SignerKey:         requester.Key,
	}
	res, err := client.Enroll(ctx, certs, renewal)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != scep.SUCCESS || !newKey.Key.PublicKey.Equal(res.Certificate.PublicKey) {
		t.Errorf("renewal = %s, want SUCCESS for the new key", res.Status)
	}

	renewal.SignerCertificate, renewal.SignerKey = newKey.Certificate, newKey.Key
	if res, err = client.Enroll(ctx, certs, renewal); err != nil || res.Status != scep.FAILURE {
		t.Errorf("renewal signed by a self-signed certificate = %v, %v, want FAILURE", res, err)
	}
	renewal.MessageType = scep.GetCert
	if _, err := client.Enroll(ctx, certs, renewal); err == nil {
		t.Error("Enroll accepted a GetCert message type")
	}
}

// TestGetCertAndGetCRL covers the certificate and CRL queries.
func TestGetCertAndGetCRL(t *testing.T) {
	t.Parallel()
	ca := testca.New(t, testca.Options{})
	ts := newTestServer(t, ca, scepserver.Options{})
	client := newClient(t, ts.URL, scepclient.Options{})
	ctx := t.Context()
	certs, err := client.GetCACert(ctx)
	if err != nil {
		t.Fatal(err)
	}
	requester := testca.NewRequester(t, "device-1", "")
	res, err := client.Enroll(ctx, certs, enrollRequest(requester))
	if err != nil {
		t.Fatal(err)
	}
	query := scepclient.QueryRequest{
		SerialNumber:      res.Certificate.SerialNumber,
		SignerCertificate: res.Certificate,
		SignerKey:         requester.Key,
	}
	got, err := client.GetCert(ctx, certs, query)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || !got[0].Equal(res.Certificate) {
		t.Errorf("GetCert returned %d certificates, want the issued one", len(got))
	}
	der, err := client.GetCRL(ctx, certs, query)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatal(err)
	}
	if err := crl.CheckSignatureFrom(ca.Certificate); err != nil {
		t.Errorf("CRL signature: %v", err)
	}

	query.SerialNumber = big.NewInt(999)
	var failure *scepclient.FailureError
	if _, err := client.GetCert(ctx, certs, query); !errors.As(err, &failure) || failure.FailInfo != scep.BadCertID {
		t.Errorf("GetCert for an unknown serial: error = %v, want FAILURE badCertID", err)
	}
}

// TestGetNextCACert covers a CA rollover announcement and its signature check.
func TestGetNextCACert(t *testing.T) {
	t.Parallel()
	ca := testca.New(t, testca.Options{Rollover: true})
	ts := newTestServer(t, ca, scepserver.Options{})
	client := newClient(t, ts.URL, scepclient.Options{})
	ctx := t.Context()
	caps, err := client.GetCACaps(ctx)
	if err != nil || !caps.Has("GetNextCACert") {
		t.Fatalf("capabilities %v miss GetNextCACert: %v", caps, err)
	}
	current, err := client.GetCACert(ctx)
	if err != nil {
		t.Fatal(err)
	}
	next, err := client.GetNextCACert(ctx, current)
	if err != nil {
		t.Fatal(err)
	}
	if !next.CA.Equal(ca.NextCertificate) {
		t.Errorf("GetNextCACert returned %v", next.CA.Subject)
	}

	stranger := testca.New(t, testca.Options{})
	forged, err := scepclient.SortCACertificates([]*x509.Certificate{stranger.Certificate})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.GetNextCACert(ctx, forged); err == nil {
		t.Error("GetNextCACert accepted an answer signed by an unexpected key")
	}

	plain := newTestServer(t, testca.New(t, testca.Options{}), scepserver.Options{})
	if _, err := newClient(t, plain.URL, scepclient.Options{}).GetNextCACert(ctx, current); !isHTTPStatus(err, http.StatusNotFound) {
		t.Errorf("GetNextCACert without a rollover: error = %v, want HTTP 404", err)
	}
}

// TestGetCACertChain covers a chain up to a root and an unknown CA name.
func TestGetCACertChain(t *testing.T) {
	t.Parallel()
	ca := testca.New(t, testca.Options{Name: "issuing", Root: true})
	ts := newTestServer(t, ca, scepserver.Options{})
	ctx := t.Context()
	chain, err := newClient(t, ts.URL, scepclient.Options{CAName: "issuing"}).GetCACertChain(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(chain) != 2 || !chain[0].Equal(ca.Certificate) || !chain[1].Equal(ca.Root) {
		t.Errorf("GetCACertChain returned %d certificates", len(chain))
	}
	if _, err := newClient(t, ts.URL, scepclient.Options{CAName: "other"}).GetCACertChain(ctx); !isHTTPStatus(err, http.StatusNotFound) {
		t.Errorf("GetCACertChain for an unknown CA name: error = %v, want HTTP 404", err)
	}
}

// TestCertRepFromUnexpectedSigner covers a CertRep that a key outside Signers signed.
func TestCertRepFromUnexpectedSigner(t *testing.T) {
	t.Parallel()
	ca := testca.New(t, testca.Options{})
	ts := newTestServer(t, ca, scepserver.Options{})
	client := newClient(t, ts.URL, scepclient.Options{})
	certs, err := client.GetCACert(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	certs.Signers = []*x509.Certificate{testca.New(t, testca.Options{}).Certificate}
	if _, err := client.Enroll(t.Context(), certs, enrollRequest(testca.NewRequester(t, "device-1", ""))); err == nil {
		t.Error("Enroll accepted a CertRep signed by an unexpected key")
	}
}

// TestGETWithoutPOSTCapability covers a server that lists neither POSTPKIOperation nor
// SCEPStandard, and the algorithms picked from its capabilities.
func TestGETWithoutPOSTCapability(t *testing.T) {
	t.Parallel()
	ca := testca.New(t, testca.Options{})
	ts := newTestServer(t, ca, scepserver.Options{Capabilities: []string{"DES3", "SHA-1"}})
	client := newClient(t, ts.URL, scepclient.Options{})
	certs, err := client.GetCACert(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	res, err := client.Enroll(t.Context(), certs, enrollRequest(testca.NewRequester(t, "device-1", "")))
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != scep.SUCCESS {
		t.Fatalf("Enroll = %s", res.Status)
	}
	if got := ts.pkiMethods(); !slices.Equal(got, []string{http.MethodGet}) {
		t.Errorf("PKIOperation methods = %v, want one GET", got)
	}
	if res.Response.Digest.String() != "SHA-1" || res.Response.ContentEncryption != pkcs7.DESEDE3CBC {
		t.Errorf("answer used %v and %v, want SHA-1 and DES-EDE3-CBC", res.Response.Digest, res.Response.ContentEncryption)
	}
}

// TestBusyRetry covers HTTP 503 answers, which the client retries a bounded number of times.
func TestBusyRetry(t *testing.T) {
	t.Parallel()
	ca := testca.New(t, testca.Options{})
	ts := newTestServer(t, ca, scepserver.Options{})
	ctx := t.Context()
	var mu sync.Mutex
	var waits []time.Duration
	client := newClient(t, ts.URL, scepclient.Options{OnBusy: func(answer *scepclient.HTTPError, delay time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		if answer.StatusCode != http.StatusServiceUnavailable {
			t.Errorf("OnBusy got HTTP %d, want 503", answer.StatusCode)
		}
		waits = append(waits, delay)
	}})
	certs, err := client.GetCACert(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ca.SetBusy(2)
	res, err := client.Enroll(ctx, certs, enrollRequest(testca.NewRequester(t, "device-1", "")))
	if err != nil || res.Status != scep.SUCCESS {
		t.Fatalf("Enroll after two busy answers = %v, %v", res, err)
	}
	if got := len(ts.pkiMethods()); got != 3 {
		t.Errorf("sent %d PKIOperation requests, want 3", got)
	}
	mu.Lock()
	if !slices.Equal(waits, []time.Duration{10 * time.Millisecond, 10 * time.Millisecond}) {
		t.Errorf("OnBusy waits = %v, want two of the busy delay", waits)
	}
	mu.Unlock()

	noRetry := newClient(t, ts.URL, scepclient.Options{BusyRetries: -1})
	ca.SetBusy(1)
	if _, err := noRetry.Enroll(ctx, certs, enrollRequest(testca.NewRequester(t, "device-2", ""))); !isHTTPStatus(err, http.StatusServiceUnavailable) {
		t.Errorf("Enroll without retries: error = %v, want HTTP 503", err)
	}
}

// TestBusyCapabilities covers a server that stays busy for GetCACaps. The client reports the busy
// answer instead of taking it for a server without capabilities and falling back to GET.
func TestBusyCapabilities(t *testing.T) {
	t.Parallel()
	ca := testca.New(t, testca.Options{})
	handler, err := scepserver.NewHandler(ca, scepserver.Options{})
	if err != nil {
		t.Fatal(err)
	}
	var pkiOperations atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("operation") {
		case "GetCACaps":
			http.Error(w, "busy", http.StatusServiceUnavailable)
		case "PKIOperation":
			pkiOperations.Add(1)
			handler.ServeHTTP(w, r)
		default:
			handler.ServeHTTP(w, r)
		}
	}))
	t.Cleanup(ts.Close)
	client := newClient(t, ts.URL, scepclient.Options{BusyRetries: -1})
	certs, err := client.GetCACert(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Enroll(t.Context(), certs, enrollRequest(testca.NewRequester(t, "device-1", "")))
	if !isHTTPStatus(err, http.StatusServiceUnavailable) {
		t.Errorf("Enroll while GetCACaps is busy: error = %v, want HTTP 503", err)
	}
	if n := pkiOperations.Load(); n != 0 {
		t.Errorf("sent %d PKIOperation requests without the capabilities, want none", n)
	}
}

// TestRetryAfterHeader covers the Retry-After delay of a 503 answer.
func TestRetryAfterHeader(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Retry-After", "1")
		http.Error(w, "busy", http.StatusServiceUnavailable)
	}))
	t.Cleanup(ts.Close)
	client := newClient(t, ts.URL, scepclient.Options{BusyRetries: 1})
	start := time.Now()
	_, err := client.GetCACaps(t.Context())
	var httpErr *scepclient.HTTPError
	if !errors.As(err, &httpErr) || httpErr.RetryAfter != time.Second || httpErr.Body != "busy" {
		t.Fatalf("GetCACaps: error = %v", err)
	}
	if elapsed := time.Since(start); elapsed < time.Second || calls.Load() != 2 {
		t.Errorf("waited %s over %d calls, want one retry after 1s", elapsed, calls.Load())
	}
}

// TestResponseLimit covers an answer larger than MaxResponseBytes.
func TestResponseLimit(t *testing.T) {
	t.Parallel()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("A", 2048)))
	}))
	t.Cleanup(ts.Close)
	client := newClient(t, ts.URL, scepclient.Options{MaxResponseBytes: 1024})
	if _, err := client.GetCACaps(t.Context()); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("GetCACaps with a large answer: error = %v", err)
	}
}

// TestPEMCACert covers a GetCACert answer that a server sends as PEM.
func TestPEMCACert(t *testing.T) {
	t.Parallel()
	ca := testca.New(t, testca.Options{})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/x-x509-ca-cert")
		_ = pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: ca.Certificate.Raw})
	}))
	t.Cleanup(ts.Close)
	certs, err := newClient(t, ts.URL, scepclient.Options{}).GetCACert(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !certs.CA.Equal(ca.Certificate) {
		t.Error("GetCACert did not return the PEM certificate")
	}
}

// TestServerQuirks covers a capability list that ends with a NUL byte and an empty answer to an
// operation the server does not support.
func TestServerQuirks(t *testing.T) {
	t.Parallel()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("operation") == "GetCACaps" {
			_, _ = w.Write([]byte("AES\r\nPOSTPKIOperation\n\x00"))
		}
	}))
	t.Cleanup(ts.Close)
	client := newClient(t, ts.URL, scepclient.Options{})
	caps, err := client.GetCACaps(t.Context())
	if err != nil || !slices.Equal(caps, scepclient.Capabilities{"AES", "POSTPKIOperation"}) {
		t.Errorf("GetCACaps = %q, %v", caps, err)
	}
	if _, err := client.GetCACert(t.Context()); !errors.Is(err, scepclient.ErrEmptyResponse) {
		t.Errorf("GetCACert with an empty answer: error = %v, want ErrEmptyResponse", err)
	}
	if _, err := client.GetCACertChain(t.Context()); !errors.Is(err, scepclient.ErrEmptyResponse) {
		t.Errorf("GetCACertChain with an empty answer: error = %v, want ErrEmptyResponse", err)
	}
	current, err := scepclient.SortCACertificates([]*x509.Certificate{testca.New(t, testca.Options{}).Certificate})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.GetNextCACert(t.Context(), current); !errors.Is(err, scepclient.ErrEmptyResponse) {
		t.Errorf("GetNextCACert with an empty answer: error = %v, want ErrEmptyResponse", err)
	}
}

// TestSingleDESAnswer covers a server that answers with single DES whatever the request used,
// which Options.Decrypt has to allow.
func TestSingleDESAnswer(t *testing.T) {
	t.Parallel()
	ca := testca.New(t, testca.Options{})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("operation") {
		case "GetCACaps":
			_, _ = w.Write([]byte("AES\nPOSTPKIOperation\n"))
		case "GetCACert":
			_, _ = w.Write(ca.Certificate.Raw)
		default:
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Error(err)
				return
			}
			msg, err := scep.ParsePKIMessage(body, scep.ParseOptions{})
			if err == nil {
				err = msg.DecryptPKIEnvelope(ca.Certificate, ca.Key, pkcs7.DecryptOptions{})
			}
			var certs []*x509.Certificate
			if err == nil {
				certs, err = ca.Enroll(r.Context(), &scepserver.Request{Message: msg, HTTPRequest: r})
			}
			var rep *scep.PKIMessage
			if err == nil {
				rep, err = msg.Success(certs, scep.ResponseOptions{
					SignerCertificate: ca.Certificate,
					SignerKey:         ca.Key,
					ContentEncryption: pkcs7.DESCBC,
				})
			}
			if err != nil {
				t.Error(err)
				http.Error(w, "test server failed", http.StatusInternalServerError)
				return
			}
			_, _ = w.Write(rep.Raw)
		}
	}))
	t.Cleanup(ts.Close)
	ctx := t.Context()

	strict := newClient(t, ts.URL, scepclient.Options{BusyRetries: -1})
	certs, err := strict.GetCACert(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := strict.Enroll(ctx, certs, enrollRequest(testca.NewRequester(t, "device-1", ""))); !errors.Is(err, pkcs7.ErrContentEncryptionNotAllowed) {
		t.Errorf("single DES answer by default: error = %v", err)
	}
	lenient := newClient(t, ts.URL, scepclient.Options{Decrypt: pkcs7.DecryptOptions{
		ContentEncryptionAlgorithms: []pkcs7.ContentEncryptionAlgorithm{pkcs7.DESCBC},
	}})
	res, err := lenient.Enroll(ctx, certs, enrollRequest(testca.NewRequester(t, "device-2", "")))
	if err != nil || res.Status != scep.SUCCESS || res.Response.ContentEncryption != pkcs7.DESCBC {
		t.Errorf("single DES answer when allowed: %v, %v", res, err)
	}
}

// TestNew covers the URL and option checks.
func TestNew(t *testing.T) {
	t.Parallel()
	for _, url := range []string{"ftp://ca.example.com/scep", "http:///scep", "://bad"} {
		if _, err := scepclient.New(url, scepclient.Options{}); err == nil {
			t.Errorf("New(%q) succeeded", url)
		}
	}
	if _, err := scepclient.New("http://ca.example.com/scep", scepclient.Options{MaxResponseBytes: -1}); err == nil {
		t.Error("New accepted a negative MaxResponseBytes")
	}
}

// TestRequestChecks covers requests the client refuses to build.
func TestRequestChecks(t *testing.T) {
	t.Parallel()
	ca := testca.New(t, testca.Options{})
	ts := newTestServer(t, ca, scepserver.Options{})
	client := newClient(t, ts.URL, scepclient.Options{})
	ctx := t.Context()
	certs, err := client.GetCACert(ctx)
	if err != nil {
		t.Fatal(err)
	}
	requester := testca.NewRequester(t, "device-1", "")
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]scepclient.EnrollRequest{
		"no CSR":           {SignerCertificate: requester.Certificate, SignerKey: requester.Key},
		"no signer":        {CSR: requester.CSR},
		"non-RSA key":      {CSR: requester.CSR, SignerCertificate: requester.Certificate, SignerKey: ecKey},
		"unsorted CA":      enrollRequest(requester),
		"wrong type value": {MessageType: scep.CertPoll, CSR: requester.CSR},
	}
	for name, req := range cases {
		target := certs
		if name == "unsorted CA" {
			target = &scepclient.CACertificates{}
		}
		if _, err := client.Enroll(ctx, target, req); err == nil {
			t.Errorf("%s: Enroll succeeded", name)
		}
	}
	if _, err := client.EnrollAndWait(ctx, certs, enrollRequest(requester), 0); err == nil {
		t.Error("EnrollAndWait accepted a zero interval")
	}
	if _, err := client.GetNextCACert(ctx, nil); err == nil {
		t.Error("GetNextCACert accepted no current certificates")
	}
}

// TestSortCACertificates covers the role sorting of GetCACert answers.
func TestSortCACertificates(t *testing.T) {
	t.Parallel()
	if _, err := scepclient.SortCACertificates(nil); err == nil {
		t.Error("sorted an empty answer")
	}

	ra := testca.New(t, testca.Options{RA: true})
	sorted, err := scepclient.SortCACertificates([]*x509.Certificate{ra.RAEncrypter, ra.RASigner, ra.Certificate})
	if err != nil {
		t.Fatal(err)
	}
	if !sorted.CA.Equal(ra.Certificate) {
		t.Error("the CA certificate is not the issuing CA when it follows the RA certificates")
	}
	if _, err := scepclient.SortCACertificates([]*x509.Certificate{ra.RAEncrypter, ra.RASigner}); err == nil {
		t.Error("sorted two RA certificates without a CA certificate")
	}

	// A chain of a root and an issuing CA without an RA.
	root := testca.New(t, testca.Options{})
	issuing := issueSubCA(t, root)
	sorted, err = scepclient.SortCACertificates([]*x509.Certificate{root.Certificate, issuing})
	if err != nil {
		t.Fatal(err)
	}
	if !sorted.CA.Equal(issuing) || !slices.EqualFunc(sorted.Recipients, []*x509.Certificate{issuing}, (*x509.Certificate).Equal) {
		t.Error("the issuing CA of a root and sub CA chain is not the sub CA")
	}

	// An RSA RA under an ECDSA root, as OpenXPKI serves it, encrypts for the RA.
	ecRoot, ecRootKey := newECDSACertificate(t, "ECDSA Root", true, nil, nil)
	rsaRA := issueRSARA(t, ecRoot, ecRootKey)
	sorted, err = scepclient.SortCACertificates([]*x509.Certificate{rsaRA, ecRoot})
	if err != nil {
		t.Fatal(err)
	}
	if !sorted.CA.Equal(ecRoot) || !slices.EqualFunc(sorted.Recipients, []*x509.Certificate{rsaRA}, (*x509.Certificate).Equal) {
		t.Error("an RSA RA under an ECDSA root is not the recipient")
	}

	// An ECDSA RA cannot decrypt RSA key transport, so the RSA CA certificate is the recipient.
	ecRA, _ := newECDSACertificate(t, "ECDSA RA", false, root.Certificate, root.Key)
	sorted, err = scepclient.SortCACertificates([]*x509.Certificate{ecRA, root.Certificate})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.EqualFunc(sorted.Recipients, []*x509.Certificate{root.Certificate}, (*x509.Certificate).Equal) {
		t.Error("an ECDSA RA certificate is a recipient")
	}
	if !slices.ContainsFunc(sorted.Signers, ecRA.Equal) {
		t.Error("an ECDSA RA certificate may not sign CertReps")
	}
}

// TestEnrollWithoutRSARecipient covers CA certificates that hold no RSA key to encrypt for. The
// answer still sorts, so a caller can read it, and Enroll refuses before sending anything.
func TestEnrollWithoutRSARecipient(t *testing.T) {
	t.Parallel()
	ecCA, _ := newECDSACertificate(t, "ECDSA CA", true, nil, nil)
	sorted, err := scepclient.SortCACertificates([]*x509.Certificate{ecCA})
	if err != nil {
		t.Fatal(err)
	}
	if len(sorted.Recipients) != 0 {
		t.Errorf("an ECDSA CA certificate is a recipient")
	}

	var requests atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		http.Error(w, "unexpected request", http.StatusTeapot)
	}))
	t.Cleanup(ts.Close)
	client := newClient(t, ts.URL, scepclient.Options{})
	requester := testca.NewRequester(t, "device-1", "secret")
	manual := &scepclient.CACertificates{All: sorted.All, CA: ecCA, Recipients: []*x509.Certificate{ecCA}, Signers: []*x509.Certificate{ecCA}}
	for name, certs := range map[string]*scepclient.CACertificates{"sorted": sorted, "manual recipients": manual} {
		if _, err := client.Enroll(t.Context(), certs, enrollRequest(requester)); !errors.Is(err, scepclient.ErrNoRSARecipient) {
			t.Errorf("%s: Enroll error = %v, want ErrNoRSARecipient", name, err)
		}
	}
	if n := requests.Load(); n != 0 {
		t.Errorf("Enroll sent %d requests to the server", n)
	}
}

// newECDSACertificate returns a P-256 certificate and its key. Without an issuer it is
// self-signed. A certificate that is not a CA has no key usage extension, so its key usage does not
// rule it out as a recipient.
func newECDSACertificate(t *testing.T, name string, isCA bool, issuer *x509.Certificate, issuerKey any) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(60),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  isCA,
		BasicConstraintsValid: true,
	}
	if isCA {
		template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature
	}
	if issuer == nil {
		issuer, issuerKey = template, key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, key.Public(), issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

// issueRSARA issues an RSA RA certificate that allows key encipherment under issuer.
func issueRSARA(t *testing.T, issuer *x509.Certificate, issuerKey any) *x509.Certificate {
	t.Helper()
	key := testca.NewRequester(t, "ra", "").Key
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(61),
		Subject:      pkix.Name{CommonName: "RSA RA"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}, issuer, key.Public(), issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// issueSubCA issues a CA certificate under root.
func issueSubCA(t *testing.T, root *testca.CA) *x509.Certificate {
	t.Helper()
	key := testca.NewRequester(t, "sub", "").Key
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber:          big.NewInt(50),
		Subject:               pkix.Name{CommonName: "SCEP Test Sub CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}, root.Certificate, key.Public(), root.Key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// isHTTPStatus reports whether err is an *HTTPError with the status.
func isHTTPStatus(err error, status int) bool {
	var httpErr *scepclient.HTTPError
	return errors.As(err, &httpErr) && httpErr.StatusCode == status
}

// pkiStatusAsHTTPStatus answers a PENDING CertRep with HTTP 202 and a FAILURE CertRep with HTTP
// 400, as OpenXPKI does.
func pkiStatusAsHTTPStatus(ca *testca.CA, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := httptest.NewRecorder()
		next.ServeHTTP(rec, r)
		status := rec.Code
		if r.URL.Query().Get("operation") == "PKIOperation" && status == http.StatusOK {
			rep, err := scep.ParsePKIMessage(rec.Body.Bytes(), scep.ParseOptions{Signers: []*x509.Certificate{ca.Certificate}})
			switch {
			case err != nil:
			case rep.PKIStatus == scep.PENDING:
				status = http.StatusAccepted
			case rep.PKIStatus == scep.FAILURE:
				status = http.StatusBadRequest
			}
		}
		maps.Copy(w.Header(), rec.Header())
		w.WriteHeader(status)
		_, _ = w.Write(rec.Body.Bytes())
	})
}

// TestCertRepWithErrorStatus covers a server that sends PENDING and FAILURE CertReps with an HTTP
// error status, and answers without a CertRep that must stay an HTTPError.
func TestCertRepWithErrorStatus(t *testing.T) {
	t.Parallel()
	ca := testca.New(t, testca.Options{Password: "secret", Manual: true, ApproveAfterPolls: 2})
	handler, err := scepserver.NewHandler(ca, scepserver.Options{})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(pkiStatusAsHTTPStatus(ca, handler))
	t.Cleanup(ts.Close)
	client := newClient(t, ts.URL, scepclient.Options{})
	certs, err := client.GetCACert(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	req := enrollRequest(testca.NewRequester(t, "device-1", "secret"))
	if res, err := client.Enroll(ctx, certs, req); err != nil || res.Status != scep.PENDING {
		t.Fatalf("Enroll with HTTP 202 = %v, %v, want PENDING", res, err)
	}
	if res, err := client.EnrollAndWait(ctx, certs, req, 10*time.Millisecond); err != nil || res.Status != scep.SUCCESS {
		t.Fatalf("EnrollAndWait with HTTP 202 = %v, %v, want SUCCESS", res, err)
	}
	res, err := client.Enroll(ctx, certs, enrollRequest(testca.NewRequester(t, "device-2", "wrong")))
	if err != nil || res.Status != scep.FAILURE || res.FailInfo != scep.BadRequest {
		t.Errorf("Enroll with HTTP 400 = %v, %v, want FAILURE badRequest", res, err)
	}

	refusals := []struct {
		name, contentType, body string
	}{
		{"text", "text/plain", "No password in request"},
		{"broken pki-message", "application/x-pki-message", "not a pkiMessage"},
	}
	for _, tt := range refusals {
		refusing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Query().Get("operation") != "PKIOperation" {
				handler.ServeHTTP(w, r)
				return
			}
			w.Header().Set("Content-Type", tt.contentType)
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(tt.body))
		}))
		client := newClient(t, refusing.URL, scepclient.Options{})
		_, err := client.Enroll(ctx, certs, enrollRequest(testca.NewRequester(t, "device-3", "secret")))
		var httpErr *scepclient.HTTPError
		if !errors.As(err, &httpErr) || httpErr.StatusCode != http.StatusBadRequest || httpErr.Body != tt.body {
			t.Errorf("%s: Enroll error = %v, want HTTPError 400", tt.name, err)
		}
		refusing.Close()
	}
}

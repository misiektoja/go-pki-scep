// Package scepclient is a SCEP (RFC 8894) client over HTTP.
//
// A requester fetches the CA certificates with GetCACert and checks them against a fingerprint it
// trusts before using them. It then enrolls with a PKCSReq, renews with a RenewalReq and polls with
// CertPoll while the CA keeps the request pending. GetCert and GetCRL read an issued certificate
// and a CRL. GetCACertChain reads the CA chain from servers that offer it. Every CertRep must be
// signed by one of the CA or RA certificates.
package scepclient

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/misiektoja/go-pkcs7"

	"github.com/misiektoja/go-scep"
)

// Defaults for Options fields left at zero.
const (
	DefaultTimeout          = 60 * time.Second
	DefaultMaxResponseBytes = 8 << 20
	DefaultBusyRetries      = 3
	DefaultBusyDelay        = 5 * time.Second
)

// maxBusyDelay caps the Retry-After delay a server can ask for.
const maxBusyDelay = 5 * time.Minute

// Options configures a Client. The zero value is usable.
type Options struct {
	// HTTPClient sends the requests. The default has a DefaultTimeout timeout.
	HTTPClient *http.Client

	// CAName is the message parameter of GetCACaps, GetCACert, GetCACertChain and GetNextCACert.
	// Servers that serve several CAs on one URL pick the CA by this name.
	CAName string

	// MaxResponseBytes bounds a response body. Zero selects DefaultMaxResponseBytes, which leaves
	// room for large CRLs.
	MaxResponseBytes int64

	// BusyRetries is how often a request is sent again after HTTP 503 Service Unavailable, which
	// servers return to throttle clients. Zero selects DefaultBusyRetries. A negative value turns
	// retries off.
	BusyRetries int

	// BusyDelay is the wait before a retry when the 503 answer has no Retry-After header. Zero
	// selects DefaultBusyDelay.
	BusyDelay time.Duration

	// Decrypt lists the content ciphers accepted in SUCCESS answers, next to the cipher of the
	// request, which is always accepted. The zero value accepts AES-CBC and DES-EDE3-CBC. Add
	// pkcs7.DESCBC for servers that answer with single DES whatever the request used.
	Decrypt pkcs7.DecryptOptions

	// OnBusy, when set, is called before each wait that follows an HTTP 503 answer, with that answer
	// and the delay, so a caller can tell its user why the request pauses.
	OnBusy func(answer *HTTPError, delay time.Duration)
}

// Client talks to one SCEP URL. It is safe for concurrent use.
type Client struct {
	url         *url.URL
	http        *http.Client
	caName      string
	limit       int64
	busyRetries int
	busyDelay   time.Duration
	onBusy      func(*HTTPError, time.Duration)
	decrypt     []pkcs7.ContentEncryptionAlgorithm

	mu   sync.Mutex
	caps Capabilities
	got  bool
}

// New returns a client for the SCEP URL, such as https://ca.example.com/scep.
func New(serverURL string, opts Options) (*Client, error) {
	u, err := url.Parse(serverURL)
	if err != nil {
		return nil, fmt.Errorf("scepclient: server URL: %w", err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("scepclient: server URL %q needs an http or https scheme and a host", serverURL)
	}
	if opts.MaxResponseBytes < 0 {
		return nil, errors.New("scepclient: MaxResponseBytes must not be negative")
	}
	c := &Client{
		url:         u,
		http:        opts.HTTPClient,
		caName:      opts.CAName,
		limit:       opts.MaxResponseBytes,
		busyRetries: opts.BusyRetries,
		busyDelay:   opts.BusyDelay,
		onBusy:      opts.OnBusy,
		decrypt:     opts.Decrypt.ContentEncryptionAlgorithms,
	}
	if len(c.decrypt) == 0 {
		c.decrypt = pkcs7.DefaultContentDecryptionAlgorithms
	}
	if c.http == nil {
		c.http = &http.Client{Timeout: DefaultTimeout}
	}
	if c.limit == 0 {
		c.limit = DefaultMaxResponseBytes
	}
	switch {
	case c.busyRetries == 0:
		c.busyRetries = DefaultBusyRetries
	case c.busyRetries < 0:
		c.busyRetries = 0
	}
	if c.busyDelay <= 0 {
		c.busyDelay = DefaultBusyDelay
	}
	return c, nil
}

// ErrEmptyResponse reports a 200 OK answer without a body to GetCACert, GetCACertChain or
// GetNextCACert. Some servers answer that way for an operation they lack or for a missing or
// unknown CA name.
var ErrEmptyResponse = errors.New("scepclient: the server sent an empty answer")

// HTTPError is an HTTP answer other than 200 OK. A PKIOperation answer with that status that
// carries a CertRep is parsed instead.
type HTTPError struct {
	StatusCode int
	// RetryAfter is the delay of a Retry-After header in seconds, or zero.
	RetryAfter time.Duration
	// Body is the start of the response body.
	Body string
}

// Error describes the answer.
func (e *HTTPError) Error() string {
	if e.Body == "" {
		return fmt.Sprintf("scepclient: server answered HTTP %d", e.StatusCode)
	}
	return fmt.Sprintf("scepclient: server answered HTTP %d: %s", e.StatusCode, e.Body)
}

// Capabilities is a GetCACaps answer.
type Capabilities []string

// Has reports whether the server lists the capability. Names are compared without case
// (RFC 8894 section 3.5.2).
func (caps Capabilities) Has(name string) bool {
	return slices.ContainsFunc(caps, func(c string) bool { return strings.EqualFold(c, name) })
}

// GetCACaps fetches the server capabilities. The answer is cached for later PKIOperation calls.
func (c *Client) GetCACaps(ctx context.Context) (Capabilities, error) {
	body, _, err := c.get(ctx, "GetCACaps", c.caName)
	if err != nil {
		return nil, err
	}
	var caps Capabilities
	for line := range strings.SplitSeq(string(body), "\n") {
		// Some servers end the list with a NUL byte.
		line = strings.TrimFunc(line, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) })
		if line != "" {
			caps = append(caps, line)
		}
	}
	c.mu.Lock()
	c.caps, c.got = caps, true
	c.mu.Unlock()
	return caps, nil
}

// capabilities returns the cached capabilities and fetches them once. A server that answers
// GetCACaps with an HTTP error is treated as listing none, except for HTTP 503, which says the
// server is busy rather than that it lacks the operation.
func (c *Client) capabilities(ctx context.Context) (Capabilities, error) {
	c.mu.Lock()
	caps, got := c.caps, c.got
	c.mu.Unlock()
	if got {
		return caps, nil
	}
	caps, err := c.GetCACaps(ctx)
	if httpErr, ok := errors.AsType[*HTTPError](err); ok && httpErr.StatusCode != http.StatusServiceUnavailable {
		c.mu.Lock()
		c.caps, c.got = nil, true
		c.mu.Unlock()
		return nil, nil
	}
	return caps, err
}

// GetCACert fetches the CA and RA certificates. The caller must check them, such as against a
// pinned fingerprint of the CA certificate, before it trusts them.
func (c *Client) GetCACert(ctx context.Context) (*CACertificates, error) {
	body, header, err := c.get(ctx, "GetCACert", c.caName)
	if err != nil {
		return nil, err
	}
	if len(body) == 0 {
		return nil, fmt.Errorf("%w to GetCACert, so it may need a CA name", ErrEmptyResponse)
	}
	certs, err := parseCACertBody("GetCACert", body, header.Get("Content-Type"))
	if err != nil {
		return nil, err
	}
	return SortCACertificates(certs)
}

// GetCACertChain fetches the CA certificate and the certificates that issued it, up to the root, in
// the order the server sends them. RFC 8894 does not define the operation, but some CAs serve it.
// The answer carries no RA certificates, so enrollment needs the GetCACert answer. The caller must
// check the chain before it trusts it.
func (c *Client) GetCACertChain(ctx context.Context) ([]*x509.Certificate, error) {
	body, header, err := c.get(ctx, "GetCACertChain", c.caName)
	if err != nil {
		return nil, err
	}
	if len(body) == 0 {
		return nil, fmt.Errorf("%w to GetCACertChain, so it lacks the operation or needs a CA name", ErrEmptyResponse)
	}
	return parseCACertBody("GetCACertChain", body, header.Get("Content-Type"))
}

// parseCACertBody reads one DER or PEM certificate or a certificate-only SignedData from the answer
// to operation. The content type picks the form first, and the other forms are tried after it
// because servers label them inconsistently.
func parseCACertBody(operation string, body []byte, contentType string) ([]*x509.Certificate, error) {
	mediaType, _, _ := mime.ParseMediaType(contentType)
	single := func() ([]*x509.Certificate, error) {
		der := body
		if block, _ := pem.Decode(body); block != nil && block.Type == "CERTIFICATE" {
			der = block.Bytes
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		return []*x509.Certificate{cert}, nil
	}
	degenerate := func() ([]*x509.Certificate, error) { return scep.CACerts(body) }
	parsers := []func() ([]*x509.Certificate, error){single, degenerate}
	if mediaType == "application/x-x509-ca-ra-cert" {
		slices.Reverse(parsers)
	}
	var errs []error
	for _, parse := range parsers {
		certs, err := parse()
		if err == nil {
			return certs, nil
		}
		errs = append(errs, err)
	}
	return nil, fmt.Errorf("scepclient: parse %s answer: %w", operation, errors.Join(errs...))
}

// GetNextCACert fetches the CA certificates that will replace current ones. The answer must be
// signed by one of current.Signers.
func (c *Client) GetNextCACert(ctx context.Context, current *CACertificates) (*CACertificates, error) {
	if current == nil {
		return nil, errors.New("scepclient: GetNextCACert needs the current CA certificates")
	}
	body, _, err := c.get(ctx, "GetNextCACert", c.caName)
	if err != nil {
		return nil, err
	}
	if len(body) == 0 {
		// Some servers answer operations they do not support with an empty 200 OK.
		return nil, fmt.Errorf("%w to GetNextCACert, so it likely lacks the operation", ErrEmptyResponse)
	}
	certs, err := scep.ParseSignedCertificates(body, current.Signers)
	if err != nil {
		return nil, err
	}
	return SortCACertificates(certs)
}

// get sends a GET operation with a message parameter and returns the body of a 200 OK answer.
func (c *Client) get(ctx context.Context, operation, message string) ([]byte, http.Header, error) {
	a, err := c.do(ctx, func() (*http.Request, error) {
		return http.NewRequestWithContext(ctx, http.MethodGet, c.operationURL(operation, message), nil)
	})
	if err != nil {
		return nil, nil, err
	}
	if a.status != http.StatusOK {
		return nil, nil, a.httpError()
	}
	return a.body, a.header, nil
}

// operationURL returns the server URL with the operation and, when set, the message parameter.
func (c *Client) operationURL(operation, message string) string {
	u := *c.url
	query := u.Query()
	query.Set("operation", operation)
	if message != "" {
		query.Set("message", message)
	}
	u.RawQuery = query.Encode()
	return u.String()
}

// pkiOperation sends a pkiMessage with POST when the server lists POSTPKIOperation and with GET
// otherwise, and returns the answer whatever its HTTP status.
func (c *Client) pkiOperation(ctx context.Context, msg *scep.PKIMessage) (*answer, error) {
	caps, err := c.capabilities(ctx)
	if err != nil {
		return nil, err
	}
	post := caps.Has("POSTPKIOperation") || caps.Has("SCEPStandard")
	return c.do(ctx, func() (*http.Request, error) {
		if !post {
			target := c.operationURL("PKIOperation", base64.StdEncoding.EncodeToString(msg.Raw))
			return http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		}
		target := c.operationURL("PKIOperation", "")
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(msg.Raw))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", pkiMessageType)
		return req, nil
	})
}

// pkiMessageType is the media type of a pkiMessage (RFC 8894 section 4.3).
const pkiMessageType = "application/x-pki-message"

// answer is a server response with its body read.
type answer struct {
	status int
	header http.Header
	body   []byte
}

// httpError describes an answer that is not 200 OK.
func (a *answer) httpError() *HTTPError {
	return &HTTPError{
		StatusCode: a.status,
		RetryAfter: retryAfter(a.header.Get("Retry-After")),
		Body:       errorBody(a.body),
	}
}

// pkiMessage reports whether the answer carries a pkiMessage. Some servers send a PENDING or FAILURE
// CertRep with an HTTP error status, such as 202 or 400. RFC 8894 does not tie the pkiStatus to the
// HTTP status, so the media type decides.
func (a *answer) pkiMessage() bool {
	if a.status == http.StatusOK {
		return true
	}
	mediaType, _, err := mime.ParseMediaType(a.header.Get("Content-Type"))
	return err == nil && mediaType == pkiMessageType && len(a.body) > 0
}

// do sends a request, retries after HTTP 503 and returns the answer, which may have any status. A
// retried request is the same message, which a server that answered 503 has not processed.
func (c *Client) do(ctx context.Context, newRequest func() (*http.Request, error)) (*answer, error) {
	for attempt := 0; ; attempt++ {
		req, err := newRequest()
		if err != nil {
			return nil, fmt.Errorf("scepclient: build request: %w", err)
		}
		resp, err := c.http.Do(req)
		if err != nil {
			return nil, fmt.Errorf("scepclient: %w", err)
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, c.limit+1))
		_ = resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("scepclient: read response: %w", err)
		}
		if int64(len(body)) > c.limit {
			return nil, fmt.Errorf("scepclient: response exceeds %d bytes", c.limit)
		}
		a := &answer{status: resp.StatusCode, header: resp.Header, body: body}
		if a.status != http.StatusServiceUnavailable || attempt >= c.busyRetries {
			return a, nil
		}
		httpErr := a.httpError()
		delay := httpErr.RetryAfter
		if delay == 0 {
			delay = c.busyDelay
		}
		delay = min(delay, maxBusyDelay)
		if c.onBusy != nil {
			c.onBusy(httpErr, delay)
		}
		if err := sleep(ctx, delay); err != nil {
			return nil, errors.Join(httpErr, err)
		}
	}
}

// retryAfter reads a Retry-After header given in seconds. HTTP dates are ignored.
func retryAfter(value string) time.Duration {
	seconds, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || seconds <= 0 {
		return 0
	}
	return time.Duration(min(seconds, int(maxBusyDelay/time.Second))) * time.Second
}

// errorBody returns the start of an error body as printable text.
func errorBody(body []byte) string {
	const limit = 256
	text := strings.Map(func(r rune) rune {
		if r < ' ' || r == 0x7f {
			return ' '
		}
		return r
	}, string(body[:min(len(body), limit)]))
	return strings.Join(strings.Fields(text), " ")
}

// sleep waits for d or until ctx ends.
func sleep(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// requestOptions returns the message options for a request to ca. A zero digest or cipher is
// chosen from the server capabilities.
func (c *Client) requestOptions(ctx context.Context, ca *CACertificates, signerCert *x509.Certificate, signerKey crypto.Signer, digest crypto.Hash, encryption pkcs7.EncryptOptions) (scep.RequestOptions, crypto.Decrypter, error) {
	if ca == nil || ca.CA == nil || len(ca.Recipients) == 0 || len(ca.Signers) == 0 {
		return scep.RequestOptions{}, nil, errors.New("scepclient: the request needs sorted CA certificates")
	}
	if signerCert == nil || signerKey == nil {
		return scep.RequestOptions{}, nil, errors.New("scepclient: the request needs a signer certificate and key")
	}
	decrypter, ok := signerKey.(crypto.Decrypter)
	if !ok {
		return scep.RequestOptions{}, nil, errors.New("scepclient: the signer key must be an RSA crypto.Decrypter")
	}
	caps, err := c.capabilities(ctx)
	if err != nil {
		return scep.RequestOptions{}, nil, err
	}
	if digest == 0 {
		digest = pickDigest(caps)
	}
	if encryption.ContentEncryption == 0 {
		encryption.ContentEncryption = pickCipher(caps)
	}
	return scep.RequestOptions{
		Recipients:        ca.Recipients,
		SignerCertificate: signerCert,
		SignerKey:         signerKey,
		Digest:            digest,
		Encryption:        encryption,
	}, decrypter, nil
}

// pickDigest returns the strongest digest the server lists. SHA-256 is used when it lists none,
// because RFC 8894 makes it mandatory.
func pickDigest(caps Capabilities) crypto.Hash {
	switch {
	case caps.Has("SHA-256") || caps.Has("SCEPStandard"):
		return crypto.SHA256
	case caps.Has("SHA-512"):
		return crypto.SHA512
	case caps.Has("SHA-1"):
		return crypto.SHA1
	default:
		return crypto.SHA256
	}
}

// pickCipher returns AES-128-CBC unless the server lists only DES3.
func pickCipher(caps Capabilities) pkcs7.ContentEncryptionAlgorithm {
	if caps.Has("DES3") && !caps.Has("AES") && !caps.Has("SCEPStandard") {
		return pkcs7.DESEDE3CBC
	}
	return pkcs7.AES128CBC
}

// exchange sends a request, verifies that the CertRep answers it and decrypts the content of a
// SUCCESS answer.
func (c *Client) exchange(ctx context.Context, ca *CACertificates, req *scep.PKIMessage, key crypto.Decrypter) (*scep.PKIMessage, error) {
	a, err := c.pkiOperation(ctx, req)
	if err != nil {
		return nil, err
	}
	if !a.pkiMessage() {
		return nil, a.httpError()
	}
	rep, err := scep.ParsePKIMessage(a.body, scep.ParseOptions{Signers: ca.Signers, AllowMD5: req.Digest == crypto.MD5})
	if err != nil {
		if a.status != http.StatusOK {
			return nil, errors.Join(a.httpError(), err)
		}
		return nil, err
	}
	if err := rep.MatchesRequest(req); err != nil {
		return nil, err
	}
	if rep.PKIStatus != scep.SUCCESS {
		return rep, nil
	}
	accept := slices.Clone(c.decrypt)
	if !slices.Contains(accept, req.ContentEncryption) {
		accept = append(accept, req.ContentEncryption)
	}
	decryptOpts := pkcs7.DecryptOptions{ContentEncryptionAlgorithms: accept}
	if err := rep.DecryptPKIEnvelope(req.SignerCertificate, key, decryptOpts); err != nil {
		return nil, err
	}
	return rep, nil
}

// Package scepserver serves SCEP (RFC 8894) over HTTP for a CA that the caller implements.
//
// The Handler answers GetCACaps, GetCACert, GetNextCACert and PKIOperation, plus GetCACertChain for
// a CA that implements ChainGetter. PKIOperation accepts GET with a base64 message parameter and
// POST with a binary body. The handler verifies the signature
// of each pkiMessage, finds the responder its pkiEnvelope is addressed to, decrypts it and passes it
// to the CA. The CA issues the certificate, keeps the request pending or refuses it.
//
// The handler does not authorize requesters. The CA checks the challenge password of a PKCSReq and
// the signer certificate of a RenewalReq. Rate limits per client belong in middleware around the
// handler. A CA can also return a *Busy to throttle one transaction.
package scepserver

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/misiektoja/go-pkcs7"

	"github.com/misiektoja/go-scep"
)

// HTTP content types from RFC 8894 section 4.
const (
	contentTypeCACert     = "application/x-x509-ca-cert"
	contentTypeCARACert   = "application/x-x509-ca-ra-cert"
	contentTypeNextCACert = "application/x-x509-next-ca-cert"
	contentTypePKIMessage = "application/x-pki-message"
)

// DefaultMaxMessageBytes bounds a PKIOperation message when Options sets no limit. A PKCSReq with
// a 4096-bit RSA key and its self-signed certificate takes about 6 KiB.
const DefaultMaxMessageBytes = 64 << 10

// Options configures a Handler. The zero value is usable.
type Options struct {
	// Capabilities replaces the GetCACaps answer. The default lists AES and DES3 when Decrypt
	// accepts them, GetNextCACert when the CA implements NextCAGetter, POSTPKIOperation, Renewal,
	// SCEPStandard with AES, SHA-1, SHA-256 and SHA-512.
	Capabilities []string

	// Decrypt lists the content ciphers accepted in pkiEnvelopes. The zero value accepts AES-CBC
	// and DES-EDE3-CBC. Add pkcs7.DESCBC only for clients that cannot send anything stronger.
	Decrypt pkcs7.DecryptOptions

	// AllowMD5 accepts requests signed with the MD5 digest, which some network devices still send.
	AllowMD5 bool

	// LegacyCertificateParser accepts requester certificates that mark the authority key
	// identifier critical, which some Windows SCEP clients send.
	LegacyCertificateParser bool

	// Digest is the signature digest of CertRep messages and GetNextCACert answers. The zero value
	// follows the request digest, or SHA-256 when the request used another one.
	Digest crypto.Hash

	// MaxMessageBytes bounds a PKIOperation message in bytes, before base64 encoding for GET. Zero
	// selects DefaultMaxMessageBytes.
	MaxMessageBytes int64

	// Logger receives a record for every PKIOperation answer, refusal and internal error. The
	// default discards them.
	Logger *slog.Logger
}

// Handler serves the SCEP operations of one URL. It is safe for concurrent use.
type Handler struct {
	ca   CA
	opts Options
	caps []byte
	log  *slog.Logger
}

// NewHandler returns a Handler that serves ca.
func NewHandler(ca CA, opts Options) (*Handler, error) {
	if ca == nil {
		return nil, errors.New("scepserver: the handler needs a CA")
	}
	if opts.MaxMessageBytes < 0 {
		return nil, errors.New("scepserver: MaxMessageBytes must not be negative")
	}
	if opts.MaxMessageBytes == 0 {
		opts.MaxMessageBytes = DefaultMaxMessageBytes
	}
	caps := opts.Capabilities
	if caps == nil {
		caps = defaultCapabilities(ca, opts.Decrypt)
	}
	for _, c := range caps {
		if c == "" || strings.ContainsAny(c, "\r\n") {
			return nil, fmt.Errorf("scepserver: capability %q must be one non-empty line", c)
		}
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &Handler{
		ca:   ca,
		opts: opts,
		caps: []byte(strings.Join(caps, "\n") + "\n"),
		log:  logger,
	}, nil
}

// defaultCapabilities lists what the handler supports for ca with the accepted ciphers.
func defaultCapabilities(ca CA, decrypt pkcs7.DecryptOptions) []string {
	accepted := decrypt.ContentEncryptionAlgorithms
	if len(accepted) == 0 {
		accepted = pkcs7.DefaultContentDecryptionAlgorithms
	}
	aes := slices.ContainsFunc(accepted, func(alg pkcs7.ContentEncryptionAlgorithm) bool {
		return alg == pkcs7.AES128CBC || alg == pkcs7.AES192CBC || alg == pkcs7.AES256CBC
	})
	var caps []string
	if aes {
		caps = append(caps, "AES")
	}
	if slices.Contains(accepted, pkcs7.DESEDE3CBC) {
		caps = append(caps, "DES3")
	}
	if _, ok := ca.(NextCAGetter); ok {
		caps = append(caps, "GetNextCACert")
	}
	caps = append(caps, "POSTPKIOperation", "Renewal")
	if aes {
		// SCEPStandard implies AES, POSTPKIOperation and SHA-256 (RFC 8894 section 3.5.2).
		caps = append(caps, "SCEPStandard")
	}
	return append(caps, "SHA-1", "SHA-256", "SHA-512")
}

// ServeHTTP dispatches on the operation query parameter.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	operation := query.Get("operation")
	switch operation {
	case "GetCACaps", "GetCACert", "GetCACertChain", "GetNextCACert":
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
	case "PKIOperation":
		if r.Method != http.MethodGet && r.Method != http.MethodPost {
			w.Header().Set("Allow", "GET, POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
	default:
		http.Error(w, "unknown SCEP operation", http.StatusBadRequest)
		return
	}
	switch operation {
	case "GetCACaps":
		writeBody(w, "text/plain; charset=utf-8", h.caps)
	case "GetCACert":
		h.getCACert(w, r, query.Get("message"))
	case "GetCACertChain":
		h.getCACertChain(w, r, query.Get("message"))
	case "GetNextCACert":
		h.getNextCACert(w, r, query.Get("message"))
	default:
		h.pkiOperation(w, r, query)
	}
}

// getCACert answers GetCACert with one DER certificate or a certificate-only SignedData.
func (h *Handler) getCACert(w http.ResponseWriter, r *http.Request, name string) {
	certs, err := h.ca.CACertificates(r.Context(), name)
	switch {
	case errors.Is(err, ErrNotFound):
		h.refuse(w, r, http.StatusNotFound, "unknown CA", err)
		return
	case err != nil:
		h.internalError(w, r, fmt.Errorf("CA certificates: %w", err))
		return
	case len(certs) == 0:
		h.internalError(w, r, errors.New("the CA returned no certificates"))
		return
	case len(certs) == 1:
		writeBody(w, contentTypeCACert, certs[0].Raw)
		return
	}
	body, err := scep.DegenerateCertificates(certs)
	if err != nil {
		h.internalError(w, r, err)
		return
	}
	writeBody(w, contentTypeCARACert, body)
}

// getCACertChain answers GetCACertChain with a certificate-only SignedData, also for a single
// certificate. It is labelled application/x-x509-ca-ra-cert, the type of a GetCACert answer with
// several certificates.
func (h *Handler) getCACertChain(w http.ResponseWriter, r *http.Request, name string) {
	getter, ok := h.ca.(ChainGetter)
	if !ok {
		h.refuse(w, r, http.StatusNotImplemented, "GetCACertChain is not supported", nil)
		return
	}
	certs, err := getter.CACertificateChain(r.Context(), name)
	switch {
	case errors.Is(err, ErrNotFound):
		h.refuse(w, r, http.StatusNotFound, "unknown CA", err)
		return
	case err != nil:
		h.internalError(w, r, fmt.Errorf("CA certificate chain: %w", err))
		return
	case len(certs) == 0:
		h.internalError(w, r, errors.New("the CA returned no certificate chain"))
		return
	}
	body, err := scep.DegenerateCertificates(certs)
	if err != nil {
		h.internalError(w, r, err)
		return
	}
	writeBody(w, contentTypeCARACert, body)
}

// getNextCACert answers GetNextCACert with the next CA certificates, signed by the current
// responder.
func (h *Handler) getNextCACert(w http.ResponseWriter, r *http.Request, name string) {
	getter, ok := h.ca.(NextCAGetter)
	if !ok {
		h.refuse(w, r, http.StatusNotImplemented, "GetNextCACert is not supported", nil)
		return
	}
	certs, responder, err := getter.NextCACertificates(r.Context(), name)
	switch {
	case errors.Is(err, ErrNotFound):
		h.refuse(w, r, http.StatusNotFound, "no next CA certificate", err)
		return
	case err != nil:
		h.internalError(w, r, fmt.Errorf("next CA certificates: %w", err))
		return
	case responder == nil:
		h.internalError(w, r, errors.New("the CA returned no responder for GetNextCACert"))
		return
	}
	body, err := scep.SignedCertificates(certs, responder.SignerCertificate, responder.SignerKey, h.opts.Digest)
	if err != nil {
		h.internalError(w, r, err)
		return
	}
	writeBody(w, contentTypeNextCACert, body)
}

// result is what the CA answers a PKIOperation with: certificates, or a CRL for GetCRL.
type result struct {
	certs []*x509.Certificate
	crl   []byte
}

// pkiOperation verifies, decrypts and dispatches a pkiMessage and writes the CertRep.
func (h *Handler) pkiOperation(w http.ResponseWriter, r *http.Request, query url.Values) {
	data, status, err := h.readMessage(w, r, query)
	if err != nil {
		h.refuse(w, r, status, "malformed PKIOperation request", err)
		return
	}
	msg, err := scep.ParsePKIMessage(data, scep.ParseOptions{
		AllowMD5:                h.opts.AllowMD5,
		LegacyCertificateParser: h.opts.LegacyCertificateParser,
	})
	if err != nil {
		h.refuse(w, r, http.StatusBadRequest, "malformed or unverifiable pkiMessage", err)
		return
	}
	if msg.MessageType == scep.CertRep {
		h.refuse(w, r, http.StatusBadRequest, "a CertRep is not a request", nil)
		return
	}
	responder, err := h.responder(r, msg)
	switch {
	case errors.Is(err, ErrNotFound):
		h.refuse(w, r, http.StatusBadRequest, "the pkiEnvelope is not addressed to this CA", err)
		return
	case err != nil:
		h.internalError(w, r, err)
		return
	}
	req := &Request{Message: msg, Responder: responder, HTTPRequest: r}
	if _, ok := msg.SignerCertificate.PublicKey.(*rsa.PublicKey); !ok {
		// The answer is encrypted for the signer certificate, which needs an RSA key.
		err := errors.New("the requester certificate has no RSA key")
		h.answer(w, r, req, result{}, &Failure{Info: scep.BadAlg, Err: err})
		return
	}
	cert, key, err := responder.decrypter()
	if err != nil {
		h.internalError(w, r, err)
		return
	}
	if err := msg.DecryptPKIEnvelope(cert, key, h.opts.Decrypt); err != nil {
		h.answer(w, r, req, result{}, &Failure{Info: decryptFailInfo(err), Err: err})
		return
	}
	res, err := h.dispatch(req)
	h.answer(w, r, req, res, err)
}

// readMessage returns the DER pkiMessage of a POST body or of the GET message parameter, or the
// HTTP status that refuses the request.
func (h *Handler) readMessage(w http.ResponseWriter, r *http.Request, query url.Values) ([]byte, int, error) {
	limit := h.opts.MaxMessageBytes
	if r.Method == http.MethodPost {
		data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
		var tooLarge *http.MaxBytesError
		switch {
		case errors.As(err, &tooLarge):
			return nil, http.StatusRequestEntityTooLarge, err
		case err != nil:
			return nil, http.StatusBadRequest, err
		case len(data) == 0:
			return nil, http.StatusBadRequest, errors.New("empty PKIOperation body")
		}
		return data, 0, nil
	}
	encoded := query.Get("message")
	// The margin covers line breaks that some clients put into the base64 text.
	if int64(len(encoded)) > limit/3*4+limit/32+8 {
		return nil, http.StatusRequestURITooLong, errors.New("message parameter exceeds the size limit")
	}
	// Clients that do not escape the query send '+' as a space.
	encoded = strings.NewReplacer(" ", "+", "\r", "", "\n", "").Replace(encoded)
	data, err := base64.StdEncoding.DecodeString(encoded)
	switch {
	case err != nil:
		return nil, http.StatusBadRequest, fmt.Errorf("message parameter: %w", err)
	case len(data) == 0:
		return nil, http.StatusBadRequest, errors.New("missing message parameter")
	case int64(len(data)) > limit:
		return nil, http.StatusRequestURITooLong, errors.New("message parameter exceeds the size limit")
	}
	return data, 0, nil
}

// responder asks the CA for the identity that one of the envelope recipients names.
func (h *Handler) responder(r *http.Request, msg *scep.PKIMessage) (*Responder, error) {
	recipients, err := msg.EnvelopeRecipients()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNotFound, err)
	}
	for _, recipient := range recipients {
		responder, err := h.ca.Responder(r.Context(), recipient)
		switch {
		case errors.Is(err, ErrNotFound):
			continue
		case err != nil:
			return nil, fmt.Errorf("responder: %w", err)
		case responder == nil || responder.SignerCertificate == nil || responder.SignerKey == nil:
			return nil, errors.New("the CA returned a responder without a signer certificate and key")
		}
		return responder, nil
	}
	return nil, ErrNotFound
}

// decryptFailInfo maps a decryption error to the failInfo sent to the client.
func decryptFailInfo(err error) scep.FailInfo {
	switch {
	case errors.Is(err, pkcs7.ErrContentEncryptionNotAllowed),
		errors.Is(err, pkcs7.ErrUnsupportedAlgorithm),
		errors.Is(err, pkcs7.ErrUnsupportedAsymmetricEncryptionAlgorithm):
		return scep.BadAlg
	case errors.Is(err, pkcs7.ErrDecryptionFailed):
		return scep.BadMessageCheck
	default:
		return scep.BadRequest
	}
}

// dispatch passes a decrypted request to the CA method for its message type.
func (h *Handler) dispatch(req *Request) (result, error) {
	ctx := req.HTTPRequest.Context()
	switch req.Message.MessageType {
	case scep.PKCSReq, scep.RenewalReq, scep.UpdateReq:
		certs, err := h.ca.Enroll(ctx, req)
		return result{certs: certs}, err
	case scep.CertPoll:
		certs, err := h.ca.Poll(ctx, req)
		return result{certs: certs}, err
	case scep.GetCert:
		getter, ok := h.ca.(CertificateGetter)
		if !ok {
			return result{}, &Failure{Info: scep.BadRequest, Err: errors.New("GetCert is not supported")}
		}
		certs, err := getter.GetCert(ctx, req)
		return result{certs: certs}, err
	case scep.GetCRL:
		getter, ok := h.ca.(CRLGetter)
		if !ok {
			return result{}, &Failure{Info: scep.BadRequest, Err: errors.New("GetCRL is not supported")}
		}
		crl, err := getter.GetCRL(ctx, req)
		return result{crl: crl}, err
	default:
		return result{}, &Failure{Info: scep.BadRequest, Err: fmt.Errorf("%s is not a request", req.Message.MessageType)}
	}
}

// answer writes the CertRep for the CA outcome, an HTTP 503 for a *Busy or an HTTP 500 for any
// other error.
func (h *Handler) answer(w http.ResponseWriter, r *http.Request, req *Request, res result, outcome error) {
	msg := req.Message
	opts := scep.ResponseOptions{
		SignerCertificate: req.Responder.SignerCertificate,
		SignerKey:         req.Responder.SignerKey,
		Certificates:      req.Responder.Certificates,
		Digest:            h.opts.Digest,
	}
	var (
		rep     *scep.PKIMessage
		err     error
		failure *Failure
		busy    *Busy
	)
	switch {
	case outcome == nil && msg.MessageType == scep.GetCRL:
		rep, err = msg.SuccessCRL(res.crl, opts)
	case outcome == nil:
		rep, err = msg.Success(res.certs, opts)
	case errors.Is(outcome, ErrPending):
		rep, err = msg.Pending(opts)
	case errors.As(outcome, &failure):
		rep, err = msg.Fail(failure.Info, opts)
	case errors.As(outcome, &busy):
		if busy.RetryAfter > 0 {
			seconds := (busy.RetryAfter + time.Second - 1) / time.Second
			w.Header().Set("Retry-After", strconv.FormatInt(int64(seconds), 10))
		}
		h.log.LogAttrs(r.Context(), slog.LevelInfo, "scep request deferred",
			slog.String("message_type", msg.MessageType.String()),
			slog.String("transaction_id", string(msg.TransactionID)),
			slog.Duration("retry_after", busy.RetryAfter))
		http.Error(w, "busy, retry later", http.StatusServiceUnavailable)
		return
	default:
		h.internalError(w, r, fmt.Errorf("%s: %w", msg.MessageType, outcome))
		return
	}
	if err != nil {
		h.internalError(w, r, fmt.Errorf("build CertRep for %s: %w", msg.MessageType, err))
		return
	}
	attrs := []slog.Attr{
		slog.String("message_type", msg.MessageType.String()),
		slog.String("transaction_id", string(msg.TransactionID)),
		slog.String("status", rep.PKIStatus.String()),
	}
	if failure != nil {
		attrs = append(attrs, slog.String("fail_info", failure.Info.String()))
		if failure.Err != nil {
			attrs = append(attrs, slog.String("cause", failure.Err.Error()))
		}
	}
	h.log.LogAttrs(r.Context(), slog.LevelInfo, "scep request answered", attrs...)
	writeBody(w, contentTypePKIMessage, rep.Raw)
}

// refuse answers with an HTTP error and logs the cause, which is not sent to the client.
func (h *Handler) refuse(w http.ResponseWriter, r *http.Request, status int, reason string, cause error) {
	attrs := []slog.Attr{
		slog.String("operation", r.URL.Query().Get("operation")),
		slog.Int("status", status),
		slog.String("reason", reason),
	}
	if cause != nil {
		attrs = append(attrs, slog.String("cause", cause.Error()))
	}
	h.log.LogAttrs(r.Context(), slog.LevelWarn, "scep request refused", attrs...)
	http.Error(w, reason, status)
}

// internalError answers HTTP 500 and logs the cause.
func (h *Handler) internalError(w http.ResponseWriter, r *http.Request, err error) {
	h.log.LogAttrs(r.Context(), slog.LevelError, "scep request failed",
		slog.String("operation", r.URL.Query().Get("operation")),
		slog.String("error", err.Error()))
	http.Error(w, "internal error", http.StatusInternalServerError)
}

// writeBody writes a successful answer.
func writeBody(w http.ResponseWriter, contentType string, body []byte) {
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	// The bodies are DER or capability lines sent with non-HTML content types.
	_, _ = w.Write(body) //nolint:gosec // G705: not rendered as HTML.
}

# Pending requests and throttling

A CA does not have to decide at once. It can keep an enrollment pending until an operator or a
backend approves it. It can also ask a client to come back later.

## Keeping a request pending

When `Enroll` returns `scepserver.ErrPending`, the handler answers PENDING. The client then sends
CertPoll messages with the transaction ID of the enrollment. The handler passes each one to
`Poll`. `Poll` answers like `Enroll`:

| `Poll` returns | Answer |
| --- | --- |
| The issued certificate, optionally followed by its chain | SUCCESS |
| `scepserver.ErrPending` | PENDING. The client polls again |
| `*scepserver.Failure`, such as `scep.BadCertID` for an unknown transaction | FAILURE |

A CertPoll carries no CSR. It names the enrollment with these fields:

| Field | Content |
| --- | --- |
| `Message.TransactionID` | The transaction ID of the enrollment |
| `Message.PollRequest.Issuer` | The DER encoded name of the CA |
| `Message.PollRequest.Subject` | The DER encoded subject of the CSR |
| `Message.SignerCertificate` | The certificate that signed the CertPoll, which the answer is encrypted for |

Keep the CSR with the transaction ID and check the subject when the client polls. The answer is
encrypted for the certificate that signs the CertPoll, so also check that its key signed the
enrollment. This CA keeps every authorized enrollment until `approve` is called. `ca.authorize`
and `ca.issue` stand for the checks and the issuing of your CA:

```go
// pendingRequest is an enrollment that waits for approval.
type pendingRequest struct {
	csr       *x509.CertificateRequest
	signerKey *rsa.PublicKey
	approved  bool
}

// Enroll keeps every authorized enrollment pending. The handler has checked that the signer key
// is RSA.
func (ca *pendingCA) Enroll(_ context.Context, req *scepserver.Request) ([]*x509.Certificate, error) {
	msg := req.Message
	if err := ca.authorize(msg); err != nil {
		return nil, err
	}
	ca.mu.Lock()
	defer ca.mu.Unlock()
	ca.pending[msg.TransactionID] = &pendingRequest{
		csr:       msg.CSR,
		signerKey: msg.SignerCertificate.PublicKey.(*rsa.PublicKey),
	}
	return nil, scepserver.ErrPending
}

// Poll issues the certificate of an approved enrollment.
func (ca *pendingCA) Poll(_ context.Context, req *scepserver.Request) ([]*x509.Certificate, error) {
	msg := req.Message
	ca.mu.Lock()
	p, ok := ca.pending[msg.TransactionID]
	approved := ok && p.approved
	ca.mu.Unlock()
	switch {
	case !ok || !bytes.Equal(msg.PollRequest.Subject, p.csr.RawSubject) || !p.signerKey.Equal(msg.SignerCertificate.PublicKey):
		return nil, &scepserver.Failure{Info: scep.BadCertID, Err: errors.New("unknown transaction")}
	case !approved:
		return nil, scepserver.ErrPending
	}
	return ca.issue(p.csr)
}

// approve lets the next CertPoll of the enrollment collect its certificate.
func (ca *pendingCA) approve(id scep.TransactionID) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	if p, ok := ca.pending[id]; ok {
		p.approved = true
	}
}
```

A real CA keeps pending requests in durable storage and removes them once they are issued, refused
or expired.

## Transaction IDs

The client chooses the transaction ID and repeats it in every CertPoll. Treat it as an opaque
string. The parser accepts 1 to 256 characters. `scepclient` and `scep.NewCSRRequest` derive it
from the CSR public key with `scep.CSRTransactionID`: the hex encoded leftmost 160 bits of the
SHA-256 hash of the key, method 1 of RFC 7093. Other clients use other derivations, so do not
recompute it on the server.

## Throttling with Busy

Return `*scepserver.Busy` to ask the client to send the same request again later, for example
when it polls more often than the CA allows. Here `p.lastPoll` is a `time.Time` field that `Poll`
sets on the pending request:

```go
if time.Since(p.lastPoll) < time.Minute {
	return nil, &scepserver.Busy{RetryAfter: time.Minute - time.Since(p.lastPoll)}
}
```

The handler answers HTTP 503 with `RetryAfter` rounded up to whole seconds in a Retry-After
header. It leaves the header out when `RetryAfter` is zero. It logs the deferral at the Info level
as `scep request deferred`.

`scepclient` sends the same message again after the delay, as many times as
`Options.BusyRetries` allows. A CA that returns `*Busy` must therefore not have acted on the
request. To refuse it for good, return a `*Failure` instead.

`*Busy` throttles one transaction. Rate limits per client address or per device belong in HTTP
middleware in front of the handler, which sees every request before it is parsed.

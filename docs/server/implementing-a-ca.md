# Implementing a CA

The handler does the protocol work and calls your CA for every decision. A CA implements
`scepserver.CA`, shown here without its comments:

```go
type CA interface {
	CACertificates(ctx context.Context, name string) ([]*x509.Certificate, error)
	Responder(ctx context.Context, recipient scep.IssuerAndSerial) (*Responder, error)
	Enroll(ctx context.Context, req *Request) ([]*x509.Certificate, error)
	Poll(ctx context.Context, req *Request) ([]*x509.Certificate, error)
}
```

| Method | Called for | Returns |
| --- | --- | --- |
| `CACertificates` | GetCACert | The CA certificate first, then the RA certificates when an RA answers for the CA |
| `Responder` | Every PKIOperation | The identity whose decrypter certificate has the issuer and serial number the pkiEnvelope names |
| `Enroll` | PKCSReq, RenewalReq and UpdateReq | The issued certificate first, optionally followed by its chain |
| `Poll` | CertPoll | The certificate of an earlier enrollment once it is issued |

Optional interfaces add GetCert, GetCRL, GetNextCACert and GetCACertChain, as
[Optional operations](optional-operations.md) describes. The handler calls the CA methods
concurrently, so the CA guards its own state.

## What the CA returns

`Enroll`, `Poll`, `GetCert` and `GetCRL` decide the answer through their return values:

| Return | Answer |
| --- | --- |
| Certificates. A CRL for GetCRL | CertRep SUCCESS with the certificates encrypted for the requester |
| `scepserver.ErrPending` | CertRep PENDING. Only `Enroll` and `Poll` may return it |
| `*scepserver.Failure` | CertRep FAILURE with `Failure.Info` as the failInfo. `Failure.Err` is logged and not sent |
| `*scepserver.Busy` | HTTP 503, with `Busy.RetryAfter` rounded up to whole seconds in a Retry-After header |
| Any other error | HTTP 500 with the body `internal error`. The error is logged |

The handler finds these values with `errors.Is` and `errors.As`, so a wrapped `*Failure` still
gives a FAILURE answer. A SUCCESS without certificates, an invalid failInfo and `ErrPending` from
`GetCert` or `GetCRL` cannot be encoded and become HTTP 500. Unlike a FAILURE answer, an HTTP 500
does not end the transaction, so the client can send the request again later.

## The quickstart CA

The [Getting started](../getting-started.md) program implements the interface with one RSA key:

```go
--8<-- "examples/quickstart/main.go:ca"
```

## Authorizing requests

The handler verifies the signature of a request, decrypts it and checks the CSR signature. It does
not decide who may enroll. `Enroll` receives a `*scepserver.Request` with what it needs to decide:

| Field | Content |
| --- | --- |
| `Message.MessageType` | `scep.PKCSReq`, `scep.RenewalReq` or `scep.UpdateReq` |
| `Message.CSR` | The parsed CSR, whose signature the handler has checked |
| `Message.ChallengePassword` | The challengePassword attribute of the CSR. Empty without one |
| `Message.SignerCertificate` | The certificate that signed the request. The handler has checked that the requester holds its key and that the signing-time of the request, when present, falls within the certificate validity |
| `Message.TransactionID` | The transaction ID the client chose, which its CertPoll messages repeat |
| `Responder` | The identity the request was encrypted for, which tells a CA with several identities which one the client addressed |
| `HTTPRequest` | The client address, the headers and the TLS state |

A PKCSReq is signed with a self-signed certificate, so the challenge password is usually the only
proof the requester gives. Compare it in constant time with `crypto/subtle`, issue one password per
device where you can and check that the CSR asks for a subject the password allows.

A RenewalReq is signed with the certificate being renewed. Check that your CA issued it, that it
is valid now and not revoked and that the CSR asks for the same subject. The handler already
refuses a request whose signing-time falls outside the validity of the signer certificate with
HTTP 400. `scepclient` always sets that time, so a RenewalReq it signs with an expired certificate
never reaches `Enroll`. Other clients may leave the attribute out or choose its value, so the CA
checks the validity against the current time as well. In the examples on these
pages `myCA` is your CA type and `ca.cert`, `ca.key` and helpers such as `ca.revoked` are its own
state:

```go
// authorizeRenewal accepts a RenewalReq signed with a valid certificate the CA issued for the
// subject the CSR asks for.
func (ca *myCA) authorizeRenewal(msg *scep.PKIMessage) error {
	signer := msg.SignerCertificate
	if err := signer.CheckSignatureFrom(ca.cert); err != nil {
		return &scepserver.Failure{Info: scep.BadRequest, Err: fmt.Errorf("renewal signer: %w", err)}
	}
	if now := time.Now(); now.Before(signer.NotBefore) || now.After(signer.NotAfter) {
		return &scepserver.Failure{Info: scep.BadRequest, Err: errors.New("renewal signer is not valid now")}
	}
	if ca.revoked(signer.SerialNumber) {
		return &scepserver.Failure{Info: scep.BadRequest, Err: errors.New("renewal signer is revoked")}
	}
	if !bytes.Equal(msg.CSR.RawSubject, signer.RawSubject) {
		return &scepserver.Failure{Info: scep.BadRequest, Err: errors.New("renewal asks for another subject")}
	}
	return nil
}
```

The default capabilities list Renewal, so clients may send a RenewalReq. A CA that does not renew
this way can refuse it with a `*Failure` or replace the list through `Options.Capabilities`.

## Responders and RAs

`Responder` returns the identity that decrypts a request and signs its answer. The handler calls it
with each recipient the pkiEnvelope names and uses the first identity it returns. Return
`scepserver.ErrNotFound` for a recipient you do not hold. When no recipient matches, the handler
answers HTTP 400.

The simplest responder is the CA itself. `SignerKey` then also decrypts, so it must implement
`crypto.Decrypter`, as `*rsa.PrivateKey` does:

```go
return &scepserver.Responder{SignerCertificate: ca.cert, SignerKey: ca.key}, nil
```

An RA answers for the CA with its own certificates, for example to keep the CA key offline or
because the CA key is not RSA. With separate RA certificates for signing and encryption, return
all of them from `CACertificates` and match the encryption certificate in `Responder`:

```go
// CACertificates returns the CA certificate followed by the RA certificates.
func (ca *raCA) CACertificates(context.Context, string) ([]*x509.Certificate, error) {
	return []*x509.Certificate{ca.cert, ca.raSigner, ca.raEncrypter}, nil
}

// Responder returns the RA when the request is encrypted for its encryption certificate.
func (ca *raCA) Responder(_ context.Context, recipient scep.IssuerAndSerial) (*scepserver.Responder, error) {
	if !bytes.Equal(recipient.Issuer, ca.raEncrypter.RawIssuer) || recipient.SerialNumber.Cmp(ca.raEncrypter.SerialNumber) != 0 {
		return nil, scepserver.ErrNotFound
	}
	return &scepserver.Responder{
		SignerCertificate:    ca.raSigner,
		SignerKey:            ca.raSignerKey,
		DecrypterCertificate: ca.raEncrypter,
		DecrypterKey:         ca.raEncrypterKey,
		Certificates:         []*x509.Certificate{ca.cert},
	}, nil
}
```

`Certificates` travel in each CertRep next to the signer certificate, here the CA certificate. The
client encrypts for RA certificates whose key usage allows key or data encipherment and accepts
answers from RA certificates whose key usage allows digital signatures, as
[CA certificates and trust](../client/ca-certificates.md#how-the-answer-is-sorted) describes. Set
the key usage of the RA certificates to match their role.

SCEP encrypts with RSA key transport, so the decrypter certificate and its key are RSA. The signer
may be RSA or ECDSA. The keys are a `crypto.Signer` and a `crypto.Decrypter`, so they can stay in
an HSM.

## Several CAs on one URL

GetCACert carries a `message` parameter that clients set to a CA name or leave empty.
`CACertificates` receives it as `name`. Return `scepserver.ErrNotFound` for a name you do not
serve, which the handler answers with HTTP 404.

PKIOperation requests carry no CA name. The handler finds the CA through the recipient of the
pkiEnvelope, so give each CA its own decrypter certificate and read `Request.Responder` in
`Enroll` to tell them apart.

## Mounting the handler

The handler serves every SCEP operation of one URL and picks the operation from the `operation`
query parameter. Mount it at the path your clients are configured with:

```go
--8<-- "examples/quickstart/main.go:handler"
```

Serve it from an `http.Server` with timeouts, such as `ReadHeaderTimeout`. PKIOperation messages
are limited to `Options.MaxMessageBytes`, 64 KiB by default. The handler does not rate limit
clients, so add middleware for that.

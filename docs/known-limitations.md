# Known limitations

## RSA keys for encryption

Requests are encrypted for an RSA CA or RA certificate and answers for the request signer
certificate, both with RSA key transport. A device must therefore sign its requests with an RSA
key. A CA with an ECDSA or Ed25519 key needs an RSA RA certificate to receive requests. The
handler answers a request signed with another key type with badAlg and the cause
`ErrSignerNotRSA`. The client returns `ErrNoRSARecipient` when the CA certificates hold no RSA
certificate.

SCEP can also encrypt answers for a non-RSA requester with the challenge password through
PasswordRecipientInfo. go-pki-scep does not support that. A CSR may still carry an ECDSA key when
an RSA certificate signs the request.

## No storage

The library keeps no state between requests. The CA implementation keeps pending requests, issued
certificates, revocation state and CRLs.

## No trust decisions in the client

The client does not validate the GetCACert answer against any trust anchor. The caller decides
whether to trust it, for example by a pinned fingerprint, as
[CA certificates and trust](client/ca-certificates.md) shows.

## No automatic CA rollover

`GetNextCACert` returns the next CA certificates. The caller stores them and switches to them.

## Algorithms

* No AES-GCM content encryption and no AuthEnvelopedData.
* Answers from the handler always use RSA PKCS #1 v1.5 key transport, even for a request that used
  RSAES-OAEP.

## Client

* `Enroll` sends PKCSReq and RenewalReq. An UpdateReq needs the message layer.
* Retry-After is read in seconds. HTTP dates are ignored and the delay is capped at five minutes.

## Server

* No rate limiting per client. Put middleware in front of the handler.
* The handler does not check a capability list set through `Options.Capabilities` against what it
  supports.

# CA certificates and trust

Every request is encrypted for a CA or RA certificate. Every answer must be signed by one. A
client gets these certificates with GetCACert. The answer is not signed, so the client checks it
before it trusts it.

## Fetching the certificates

```go
client, err := scepclient.New("https://ca.example.com/scep", scepclient.Options{})
if err != nil {
	return err
}
ca, err := client.GetCACert(ctx)
if err != nil {
	return err
}
```

`New` needs an `http` or `https` URL with a host. A server that serves several CAs on one URL picks
the CA by name, which the client sends from `Options.CAName`. A server that needs a name may answer
an empty 200 OK without one, which `GetCACert` returns as `scepclient.ErrEmptyResponse`.

The client reads a single DER or PEM certificate or a certificate-only SignedData, whatever content
type the server sets.

## How the answer is sorted

`GetCACert` returns a `*scepclient.CACertificates`:

| Field | Content |
| --- | --- |
| `All` | Every certificate of the answer in server order |
| `CA` | The issuing CA certificate, which CertPoll, GetCert and GetCRL name as the issuer |
| `Recipients` | The certificates requests are encrypted for |
| `Signers` | The certificates allowed to sign CertRep messages |

The certificates are sorted by these rules:

* A certificate with the CA flag in its basic constraints is a CA certificate. Every other
  certificate is an RA certificate. A single certificate without basic constraints counts as the
  CA.
* The issuing CA is the CA certificate that issued the RA certificates. Without RA certificates it
  is the CA certificate that issued none of the others, so in a root and intermediate chain it is
  the intermediate. Issuers are matched by name and key identifier, not by signature.
* `Recipients` are the RA certificates with an RSA key whose key usage allows key or data
  encipherment or is absent. Without such an RA it is the CA certificate when its key is RSA.
* `Signers` are the RA certificates whose key usage allows digital signatures or is absent, plus
  the issuing CA.

When no certificate has an RSA key, `Recipients` is empty and `Enroll`, `Poll`, `GetCert` and
`GetCRL` return `scepclient.ErrNoRSARecipient` before they send anything.

When a server sends an RA certificate and the root but not the intermediate CA that issued the RA,
no CA certificate issued the RA and the root becomes `CA`. Enrollment still works, because the RA
certificate encrypts and signs, but a certificate issued under the intermediate does not verify
against `CA`.

## Checking the certificates

The client never decides on its own whether a CA is genuine. Compare the CA certificate with a
fingerprint the device received out of band, for example through provisioning or an MDM profile.
Then check that the RA certificates were issued by that CA. The quickstart does both:

```go
--8<-- "examples/quickstart/main.go:trust"
```

`CheckSignatureFrom` refuses SHA-1 signatures, which some older CAs still put on their RA
certificates. Pin the fingerprint of such an RA certificate as well or verify it with a library
that accepts SHA-1.

A device that ships with its CA certificates can skip GetCACert. `SortCACertificates` sorts a list
it loads itself into the same structure:

```go
ca, err := scepclient.SortCACertificates([]*x509.Certificate{caCert, raCert})
if err != nil {
	return err
}
```

## Restricting the answer signers

The client verifies every CertRep against `Signers` only. A certificate the CertRep carries itself
is ignored, so an answer signed by any other key is refused even when it names an expected signer.
An answer that carries no certificates verifies too.

## GetCACertChain

```go
chain, err := client.GetCACertChain(ctx)
```

`GetCACertChain` returns the CA certificate and its issuers in server order. RFC 8894 does not
define the operation and its answer carries no RA certificates, so enroll with the GetCACert
answer. Check the chain before you trust it, for example by verifying `chain[0]` against a pinned
root with `x509.Certificate.Verify`.

## CA rollover

A CA can announce the certificates that replace the current ones before they expire:

```go
next, err := client.GetNextCACert(ctx, ca)
if err != nil {
	return err
}
```

The answer must be signed by one of `ca.Signers`, the certificates the device already trusts.
`GetNextCACert` returns the new certificates sorted like a GetCACert answer. The client does not
switch to them by itself. Store them and switch when the CA rolls over.

Servers without the operation answer in different ways. The handler of this module answers
HTTP 501, which the client returns as `*scepclient.HTTPError`. A server that answers an empty
200 OK gives `scepclient.ErrEmptyResponse`.

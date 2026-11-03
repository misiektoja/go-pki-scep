# Optional operations

The handler checks whether the CA implements these interfaces and serves the matching operation
only when it does.

| Interface | Operation | Without the interface |
| --- | --- | --- |
| `CertificateGetter` | GetCert, a PKIOperation | FAILURE with badRequest |
| `CRLGetter` | GetCRL, a PKIOperation | FAILURE with badRequest |
| `NextCAGetter` | GetNextCACert and the GetNextCACert capability | HTTP 501 |
| `ChainGetter` | GetCACertChain | HTTP 501 |

A CA that implements [RefusalRecorder](refusals-and-logging.md#recording-refusals) is told about
the GetCert and GetCRL requests refused this way.

## GetCert

GetCert fetches a certificate by its issuer and serial number. `ca.lookup` stands for the
certificate store of your CA.

```go
// GetCert returns the certificate with the issuer and serial number the request names.
func (ca *myCA) GetCert(_ context.Context, req *scepserver.Request) ([]*x509.Certificate, error) {
	id := req.Message.CertificateID
	cert, ok := ca.lookup(id.SerialNumber)
	if !ok || !bytes.Equal(id.Issuer, ca.cert.RawSubject) {
		return nil, &scepserver.Failure{Info: scep.BadCertID, Err: errors.New("unknown certificate")}
	}
	return []*x509.Certificate{cert}, nil
}
```

`Message.CertificateID` holds the DER encoded issuer name and the serial number. Return the
certificate first, optionally followed by its chain. The answer is encrypted for the certificate
that signed the request, which is usually one the CA issued earlier. The handler does not check it,
so decide in `GetCert` whether that signer may read the certificate.

## GetCRL

GetCRL names a certificate the same way and asks for the CRL that covers it. Return the DER encoded
CRL. The handler sends it in a SUCCESS answer.

```go
// GetCRL returns the current CRL of the CA.
func (ca *myCA) GetCRL(context.Context, *scepserver.Request) ([]byte, error) {
	return ca.currentCRL()
}
```

## GetNextCACert

Before a CA certificate expires, a CA can announce the certificate that replaces it. Clients fetch
it with GetNextCACert and switch to it after the rollover.

```go
// NextCACertificates announces the next CA certificate, signed by the current CA.
func (ca *myCA) NextCACertificates(_ context.Context, name string) ([]*x509.Certificate, *scepserver.Responder, error) {
	if ca.next == nil {
		return nil, nil, scepserver.ErrNotFound
	}
	return []*x509.Certificate{ca.next}, &scepserver.Responder{SignerCertificate: ca.cert, SignerKey: ca.key}, nil
}
```

The handler signs the certificates with the current responder, which clients already trust from
GetCACert. The signature digest is `Options.Digest`. SHA-256 when it is zero. Return
`scepserver.ErrNotFound` while no rollover is planned, which the handler answers with HTTP 404. A
nil responder without an error is answered with HTTP 500.

When the CA implements `NextCAGetter`, the default capabilities list GetNextCACert.

## GetCACertChain

RFC 8894 does not define GetCACertChain, but some CAs serve it and their clients still send it. It
returns the CA certificate followed by the certificates that issued it, up to the root.

```go
// CACertificateChain returns the issuing CA certificate followed by its root.
func (ca *myCA) CACertificateChain(context.Context, string) ([]*x509.Certificate, error) {
	return []*x509.Certificate{ca.cert, ca.root}, nil
}
```

`name` is the `message` parameter, as for `CACertificates`. Return `scepserver.ErrNotFound` for a
name you do not serve, which gives HTTP 404.

## Answer formats

| Operation | Body | Content type |
| --- | --- | --- |
| GetCACert with one certificate | The DER certificate | `application/x-x509-ca-cert` |
| GetCACert with several certificates | A certificate-only SignedData | `application/x-x509-ca-ra-cert` |
| GetCACertChain | A certificate-only SignedData, also for one certificate | `application/x-x509-ca-ra-cert` |
| GetNextCACert | A SignedData that the current responder signs and that carries only the next certificates | `application/x-x509-next-ca-cert` |
| GetCACaps | One capability per line, each ending with a line feed | `text/plain; charset=utf-8` |
| PKIOperation | The CertRep pkiMessage | `application/x-pki-message` |

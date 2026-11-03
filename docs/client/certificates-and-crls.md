# Certificates and CRLs

GetCert fetches a certificate by its issuer and serial number. GetCRL fetches the CRL that covers a
certificate. Both are PKIOperation requests, signed and encrypted like an enrollment. Both need a
server that implements them.

## Fetching a certificate

```go
certs, err := client.GetCert(ctx, ca, scepclient.QueryRequest{
	SerialNumber:      cert.SerialNumber,
	SignerCertificate: cert,
	SignerKey:         key,
})
if err != nil {
	return err
}
fetched := certs[0]
```

`QueryRequest` names the certificate and the requester:

| Field | Meaning |
| --- | --- |
| `Issuer` | The DER encoded name of the issuing CA. The zero value takes the subject of `ca.CA` |
| `SerialNumber` | The serial number of the certificate |
| `SignerCertificate`, `SignerKey` | Sign the request. The key decrypts the answer, so it must be an RSA `crypto.Decrypter`. Servers usually expect a certificate the CA issued |
| `Digest`, `Encryption` | As in `EnrollRequest` |

`GetCert` returns the certificates of the answer in server order. The handler of this module sends
the requested certificate first.

## Fetching a CRL

```go
der, err := client.GetCRL(ctx, ca, scepclient.QueryRequest{
	SerialNumber:      cert.SerialNumber,
	SignerCertificate: cert,
	SignerKey:         key,
})
if err != nil {
	return err
}
crl, err := x509.ParseRevocationList(der)
if err != nil {
	return err
}
if err := crl.CheckSignatureFrom(ca.CA); err != nil {
	return err
}
```

`GetCRL` returns the DER encoded CRL. The CertRep that carries it is signed by a trusted CA or RA
certificate, but the client does not check the CRL itself. Check its signature and its
`NextUpdate` before you rely on it.

## Refusals

A FAILURE answer returns a `*scepclient.FailureError` with the failInfo. A PENDING answer, which
these requests do not expect, returns the same error type with `Status` set to PENDING:

```go
var failure *scepclient.FailureError
if errors.As(err, &failure) && failure.FailInfo == scep.BadCertID {
	return fmt.Errorf("the CA does not know serial %s: %w", cert.SerialNumber, err)
}
```

A server without the operation may answer FAILURE with badRequest, as the handler of this module
does. Other servers answer with an HTTP error, which the client returns as
`*scepclient.HTTPError`.

# Enrollment and renewal

A device enrolls with a PKCSReq, waits while the CA keeps the request pending and later renews
with a RenewalReq. Each request needs the sorted CA certificates from
[CA certificates and trust](ca-certificates.md).

## Creating the CSR

A PKCSReq usually carries a challenge password in the CSR, which `crypto/x509` cannot add.
`x509util.CreateCertificateRequest` creates the CSR with it:

```go
der, err := x509util.CreateCertificateRequest(rand.Reader, &x509util.CertificateRequest{
	Subject:           pkix.Name{CommonName: "device-42"},
	DNSNames:          []string{"device-42.example.com"},
	ChallengePassword: password,
}, key)
if err != nil {
	return err
}
csr, err := x509.ParseCertificateRequest(der)
if err != nil {
	return err
}
```

`CertificateRequest` embeds `x509.CertificateRequest`, so the usual template fields apply. With a
challenge password the key must be RSA or ECDSA on P-224, P-256, P-384 or P-521. The template
`SignatureAlgorithm` is honored, including the RSA-PSS algorithms. Without a password the function
returns the CSR `crypto/x509` creates.

## Enrolling with a PKCSReq

The quickstart enrolls a new RSA key:

```go
--8<-- "examples/quickstart/main.go:enroll"
```

`EnrollRequest` describes the request:

| Field | Meaning |
| --- | --- |
| `MessageType` | `scep.PKCSReq` (the default) or `scep.RenewalReq` |
| `CSR` | The certificate request. Its public key identifies the issued certificate in the answer |
| `SignerCertificate`, `SignerKey` | Sign the request. The key also decrypts the answer, so it must be an RSA `crypto.Decrypter`. A PKCSReq uses a self-signed certificate for the CSR key |
| `TransactionID` | Identifies the enrollment. The zero value derives it from the CSR key with `scep.CSRTransactionID` |
| `Digest`, `Encryption` | The signature digest and the content cipher and key transport. Zero values follow the server capabilities, see [Capabilities, answers and retries](answers-and-retries.md#algorithms) |

`Enroll` and `EnrollAndWait` return a `*scepclient.Result`:

| Field | Content |
| --- | --- |
| `Status` | `scep.SUCCESS`, `scep.PENDING` or `scep.FAILURE` |
| `FailInfo` | The reason of a FAILURE |
| `Certificate` | The issued certificate, the one whose public key is the CSR key |
| `Certificates` | Every certificate of a SUCCESS answer in server order, such as the chain |
| `TransactionID` | The transaction ID, which `Poll` needs |
| `Response` | The verified CertRep |

A FAILURE answer is a result, not an error. The error is set when the request could not be sent,
the server answered without a CertRep or the answer did not verify. A SUCCESS answer without a
certificate for the CSR key is an error too.

## Devices with ECDSA keys

The answer is encrypted for the certificate that signs the request, with RSA key transport. A
device whose CSR key is ECDSA signs the PKCSReq with a separate RSA key and a self-signed
certificate for it. The CA issues the certificate for the ECDSA key in the CSR:

```go
res, err := client.Enroll(ctx, ca, scepclient.EnrollRequest{
	CSR:               ecdsaCSR,
	SignerCertificate: rsaSignerCert,
	SignerKey:         rsaSignerKey,
})
```

`res.Certificate` then holds the ECDSA key. With a `SignerKey` that is not RSA, `Enroll` sends
nothing and returns `scepclient: the signer key must be an RSA crypto.Decrypter`. The handler of
this module answers FAILURE with badAlg when another client signs a request with such a key.

## Waiting for approval

`EnrollAndWait` sends the request and, while the CA answers PENDING, polls with CertPoll every
interval:

```go
ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
defer cancel()
res, err := client.EnrollAndWait(ctx, ca, req, time.Minute)
```

It returns the first SUCCESS or FAILURE result. When the context ends first, it returns the last
PENDING result together with the context error, so set a deadline that matches how long an
approval may take. The interval must be positive.

A device that stops and polls later keeps the CSR, the signer certificate and key and the
transaction ID, then sends one CertPoll at a time with `Poll`:

```go
res, err := client.Poll(ctx, ca, scepclient.EnrollRequest{
	CSR:               csr,
	SignerCertificate: signerCert,
	SignerKey:         signerKey,
	TransactionID:     savedTransactionID,
})
```

`Poll` derives the transaction ID from the CSR when `TransactionID` is empty, which matches an
enrollment that used the default.

## Renewing with a RenewalReq

A RenewalReq is signed with the certificate being renewed and its key, which the CA uses to
authorize the request. The quickstart renews for a new key:

```go
--8<-- "examples/quickstart/main.go:renew"
```

The current key decrypts the answer, so it must be RSA. The CSR may carry a new key or the current
one. The client sends a RenewalReq whether or not the server lists the Renewal capability. Check
`GetCACaps` first when you need to fall back to a PKCSReq with a new challenge password.

`Enroll` sends PKCSReq and RenewalReq only. Build an UpdateReq from earlier SCEP drafts with
`scep.NewCSRRequest` from the [message layer](../message-layer.md).

## Choosing the algorithms

The client picks the digest and the cipher from the server capabilities. Set them on the request
to override that choice, for example AES-256-CBC with RSAES-OAEP key transport for a server that
accepts both:

```go
req.Encryption = pkcs7.EncryptOptions{
	ContentEncryption: pkcs7.AES256CBC,
	KeyEncryption:     pkcs7.RSAOAEP,
}
```

The answer comes back with RSA PKCS #1 v1.5 key transport from the handler of this module, which
always uses it for answers.

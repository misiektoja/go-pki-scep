# Message layer

The `scep` package builds, parses and answers pkiMessages without any transport. `scepserver` and
`scepclient` use it. So can code with another HTTP stack, tools that inspect captured messages and
tests that need SCEP messages.

The steps below are taken from `Example` in the package documentation, which the tests run. It
builds a PKCSReq, answers it as a CA and reads the answer as the requester.

## Building a request

```go
--8<-- "example_test.go:request"
```

| Function | Message | Content |
| --- | --- | --- |
| `NewCSRRequest` | PKCSReq, RenewalReq or UpdateReq | The CSR |
| `NewCertPollRequest` | CertPoll | The DER encoded CA name and CSR subject. `RequestOptions.TransactionID` must name the enrollment |
| `NewGetCertRequest` | GetCert | The DER encoded issuer name and the serial number |
| `NewGetCRLRequest` | GetCRL | The DER encoded issuer name and the serial number |

`RequestOptions` sets what every request needs:

| Field | Meaning | Default |
| --- | --- | --- |
| `Recipients` | The CA or RA certificates the pkiEnvelope is encrypted for | Required |
| `SignerCertificate`, `SignerKey` | The certificate and key that sign the request | Required |
| `TransactionID` | The transaction ID | Derived from the CSR key by `NewCSRRequest`. Required by `NewCertPollRequest`. Random for `NewGetCertRequest` and `NewGetCRLRequest` |
| `Digest` | The signature digest | SHA-256 |
| `Encryption` | The content cipher, key transport and OAEP hash | AES-128-CBC with RSA PKCS #1 v1.5 |

The built message has `Raw`, the DER encoded pkiMessage to send. Its `SenderNonce` is the nonce an
answer must repeat.

## Answering a request

```go
--8<-- "example_test.go:respond"
```

`ParsePKIMessage` reads DER or BER and verifies the signature. The message must have exactly one
signer. Without `ParseOptions.Signers`, the signature is checked with the certificate the message
carries, which proves only that the sender holds that key. Authorize the sender separately, by
the challenge password of a PKCSReq or the signer certificate of a RenewalReq.

`DecryptPKIEnvelope` decrypts the content with an RSA key and parses it by message type:

| Message | Field set after decryption |
| --- | --- |
| PKCSReq, RenewalReq, UpdateReq | `CSR`, `ChallengePassword` and `RawDecrypted` through the embedded `*CSRReqMessage`. The CSR signature is checked |
| CertPoll | `PollRequest` with the issuer and subject |
| GetCert, GetCRL | `CertificateID` with the issuer and serial number |
| CertRep with SUCCESS | `CertRepMessage.Certificates` or `CRL` |

`EnvelopeRecipients` lists the issuer and serial number of each recipient before decryption, so a
server with several keys can pick the one to decrypt with.

An answer is built from the parsed request:

| Method | Answers | Content |
| --- | --- | --- |
| `Success` | Enrollments, CertPoll and GetCert | The certificates, the issued or requested one first |
| `SuccessCRL` | GetCRL | The DER encoded CRL |
| `Pending` | Enrollments and CertPoll | None |
| `Fail` | Any request | None. The failInfo must be one RFC 8894 defines |

`ResponseOptions` names the signer and the algorithms:

| Field | Meaning | Default |
| --- | --- | --- |
| `SignerCertificate`, `SignerKey` | The CA or RA certificate and key that sign the answer | Required |
| `Certificates` | Certificates carried next to the signer certificate, such as the CA certificate when an RA signs | None |
| `Digest` | The signature digest | The request digest when it is MD5, SHA-1, SHA-256, SHA-384 or SHA-512, otherwise SHA-256 |
| `ContentEncryption` | The cipher of the encrypted content | The request cipher. AES-128-CBC when the request was not decrypted |

The content of a SUCCESS answer is encrypted for the certificate that signed the request, with RSA
PKCS #1 v1.5 key transport.

## Reading an answer

```go
--8<-- "example_test.go:answer"
```

A requester sets `ParseOptions.Signers` to the CA and RA certificates it trusts. Only those
certificates take part in the signature check, so a certificate the answer carries cannot stand in
for them. An answer that carries no certificates still verifies. `MatchesRequest` checks that
the transactionID matches and that the recipientNonce repeats the senderNonce of the request.

## Pitfalls

* `PKIMessage` embeds `*CertRepMessage` and `*CSRReqMessage`, so their fields are promoted.
  Reading `msg.PKIStatus` on a message that is not a CertRep or `msg.CSR` before decryption
  dereferences a nil pointer and panics. Check `MessageType` first.
* `msg.Certificates` holds the certificates the SignedData carries. The certificates of a SUCCESS
  answer are `msg.CertRepMessage.Certificates`.
* MD5 signatures are refused unless `ParseOptions.AllowMD5` is set.
* `ParseOptions.LegacyCertificateParser` accepts certificates that mark the authority key
  identifier critical, which some Windows SCEP clients send.

## Other helpers

| Function | Purpose |
| --- | --- |
| `CSRTransactionID` | The transaction ID `NewCSRRequest` derives from a CSR key, so a requester can poll without storing it |
| `DegenerateCertificates` | Encodes certificates as a certificate-only SignedData, the body of a GetCACert answer with several certificates |
| `CACerts` | Reads the certificates of a certificate-only SignedData |
| `SignedCertificates` | Builds a GetNextCACert answer signed by the current CA or RA |
| `ParseSignedCertificates` | Verifies a GetNextCACert answer against the current certificates and returns the announced ones |
| `FingerprintCertsSelector`, `EnciphermentCertsSelector`, `NopCertsSelector` | Filter certificates by fingerprint or by key usage. `NopCertsSelector` passes them through unchanged |

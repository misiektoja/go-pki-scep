# Support matrix

What the handler, the client and the message layer support. [Known limitations](known-limitations.md)
lists what they do not.

## Operations

| Operation | Server handler | Client |
| --- | --- | --- |
| GetCACaps | Lists the capabilities derived from the options and the CA. `Options.Capabilities` replaces the list | `GetCACaps`, fetched once and used to pick POST, the digest and the cipher |
| GetCACert | One DER certificate. The CA and RA certificates in a certificate-only message when there are several | `GetCACert`, which sorts the answer into the CA, the encryption recipients and the allowed CertRep signers |
| GetNextCACert | The next CA certificates, signed by the current CA or RA, when the CA implements `NextCAGetter` | `GetNextCACert`, which verifies the signature against the current certificates |
| GetCACertChain | The CA certificate and its issuers up to the root, when the CA implements `ChainGetter` | `GetCACertChain`, which returns the chain in server order |
| PKIOperation | GET with a base64 `message` parameter and POST with a binary body | POST when the server lists POSTPKIOperation or SCEPStandard, GET otherwise |

GetCACertChain is not part of RFC 8894. Some CAs serve it and their clients still send it. Its
answer carries no RA certificates, so a client enrolls with the GetCACert answer.

## Message types

| Message type | Built with | Client | Handler passes it to | Possible answers |
| --- | --- | --- | --- | --- |
| PKCSReq (19) | `NewCSRRequest` | `Enroll`, `EnrollAndWait` | `CA.Enroll` | SUCCESS, PENDING, FAILURE |
| RenewalReq (17) | `NewCSRRequest` | `Enroll` with `MessageType: scep.RenewalReq` | `CA.Enroll` | SUCCESS, PENDING, FAILURE |
| UpdateReq (18) | `NewCSRRequest` | Not sent | `CA.Enroll` | SUCCESS, PENDING, FAILURE |
| CertPoll (20) | `NewCertPollRequest` | `Poll`, `EnrollAndWait` | `CA.Poll` | SUCCESS, PENDING, FAILURE |
| GetCert (21) | `NewGetCertRequest` | `GetCert` | `CertificateGetter.GetCert` | SUCCESS with certificates, FAILURE |
| GetCRL (22) | `NewGetCRLRequest` | `GetCRL` | `CRLGetter.GetCRL` | SUCCESS with a CRL, FAILURE |
| CertRep (3) | `Success`, `SuccessCRL`, `Pending`, `Fail` | Parsed and matched to the request | Refused with HTTP 400 | None |

UpdateReq comes from SCEP drafts before RFC 8894. The handler and the message layer treat it like
a RenewalReq.

## Algorithms

| Area | Supported | Default |
| --- | --- | --- |
| Signature digest | SHA-256, SHA-384, SHA-512, SHA-224, SHA-1 and MD5 | SHA-256. The client picks SHA-256 when the server lists SHA-256 or SCEPStandard, then SHA-512, then SHA-1 |
| MD5 signatures | The handler accepts them with `Options.AllowMD5`, the client only in the answer to a request it signed with MD5 and the message layer with `ParseOptions.AllowMD5` | Refused |
| Answer digest | Any of the above | The request digest when it is MD5, SHA-1, SHA-256, SHA-384 or SHA-512, otherwise SHA-256 |
| Content cipher | AES-128-CBC, AES-192-CBC, AES-256-CBC, DES-EDE3-CBC and DES-CBC | AES-128-CBC. The client picks DES-EDE3-CBC when the server lists DES3 without AES or SCEPStandard |
| Accepted on decryption | AES-CBC and DES-EDE3-CBC. DES-CBC only when `Decrypt` lists it. The client always accepts the cipher of its own request | |
| Answer cipher | Any of the above | The request cipher |
| Request key transport | RSA PKCS #1 v1.5 and RSAES-OAEP through `Encryption.KeyEncryption` | PKCS #1 v1.5 |
| Answer key transport | RSA PKCS #1 v1.5 | |

## Keys

| Key | Supported types |
| --- | --- |
| Request signer, which also decrypts the answer | RSA. The handler answers any other key with badAlg |
| CSR key | Any key `crypto/x509` parses and whose CSR signature it checks. `x509util.CreateCertificateRequest` adds a challenge password for RSA and ECDSA keys |
| Request recipient, the CA or RA certificate that decrypts requests | RSA |
| Answer signer, the CA or RA certificate that signs CertRep messages | RSA or ECDSA |

A device with an ECDSA key signs its PKCSReq with a separate RSA key and certificate. The CSR
keeps the ECDSA key and the CA issues the certificate for it. A CA with an ECDSA key needs an RSA
RA certificate to decrypt requests.

## Go and platforms

The module needs Go 1.27.3 or newer. CI tests every change on Linux and macOS with the Go version
in `go.mod` and builds it on Windows.

## Interoperability

The Interop workflow runs sscep v0.10.0 and the micromdm/scep v2.3.0 client against the handler,
and the client against the micromdm/scep v2.3.0 server and EJBCA Community Edition 9.6.3.
[Tested implementations](interoperability/tested-implementations.md) lists what each run covers.

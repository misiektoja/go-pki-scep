# Errors and status values

## Status values

A CertRep carries a pkiStatus and, on FAILURE, a failInfo. The `scep` package defines both as
string types holding the decimal value. Their `String` methods print the name and the number, as
in `FAILURE (2)`.

| pkiStatus | Value | Meaning |
| --- | --- | --- |
| `scep.SUCCESS` | 0 | The answer carries the certificates or the CRL |
| `scep.FAILURE` | 2 | The request was refused. The failInfo gives the reason |
| `scep.PENDING` | 3 | The CA has not decided. The requester polls with CertPoll |

| failInfo | Value | Sent by this module's handler for |
| --- | --- | --- |
| `scep.BadAlg` | 0 | A request signed with a key that is not RSA. A request encrypted with a cipher or key transport the handler does not accept |
| `scep.BadMessageCheck` | 1 | A pkiEnvelope that does not decrypt with the responder key |
| `scep.BadRequest` | 2 | A pkiEnvelope with an invalid CSR or query. GetCert or GetCRL to a CA without them |
| `scep.BadTime` | 3 | Only when the CA returns it |
| `scep.BadCertID` | 4 | Only when the CA returns it |

The CA can return any of the five values in a `*scepserver.Failure`. `Fail` refuses any other value.

## Message types

| Constant | Value |
| --- | --- |
| `scep.CertRep` | 3 |
| `scep.RenewalReq` | 17 |
| `scep.UpdateReq` | 18 |
| `scep.PKCSReq` | 19 |
| `scep.CertPoll` | 20 |
| `scep.GetCert` | 21 |
| `scep.GetCRL` | 22 |

`ParsePKIMessage` refuses any other message type.

## Server errors

| Error | Returned by | Answer |
| --- | --- | --- |
| `scepserver.ErrPending` | `Enroll`, `Poll` | CertRep PENDING |
| `*scepserver.Failure` | Any CA method that answers with a CertRep | CertRep FAILURE with `Info`. `Err` is logged only |
| `*scepserver.Busy` | Any CA method that answers with a CertRep | HTTP 503 with Retry-After |
| `scepserver.ErrNotFound` from `CACertificates`, `CACertificateChain` or `NextCACertificates` | The CA | HTTP 404 |
| `scepserver.ErrNotFound` from `Responder` for every recipient | The CA | HTTP 400 |
| `scepserver.ErrSignerNotRSA` | The handler, as `Failure.Err` | CertRep FAILURE with badAlg |
| Any other error | The CA | HTTP 500 with the body `internal error` |

## Client errors

| Error | Cause |
| --- | --- |
| `*scepclient.HTTPError` | An answer that is not 200 OK and carries no CertRep |
| `*scepclient.FailureError` | A FAILURE or PENDING answer to GetCert or GetCRL |
| `scepclient.ErrEmptyResponse` | A 200 OK without a body to GetCACert, GetCACertChain or GetNextCACert |
| `scepclient.ErrNoRSARecipient` | CA certificates without an RSA certificate to encrypt for. Returned before a request is sent |
| Wraps `pkcs7.ErrContentEncryptionNotAllowed` | A SUCCESS answer encrypted with a cipher that `Options.Decrypt` does not accept |
| Wraps `pkcs7.ErrDecryptionFailed` | A SUCCESS answer that does not decrypt with the requester key |
| `scep: verify pkiMessage` | An answer not signed by one of `CACertificates.Signers` |
| `scep: CertRep transactionID ... does not match` or `recipientNonce does not match` | An answer to another request |

`Enroll`, `Poll` and `EnrollAndWait` report FAILURE and PENDING in `Result.Status`, not as an
error.

## Errors of the message layer

`ParsePKIMessage`, `DecryptPKIEnvelope` and the request and answer builders return errors that
start with `scep:` and wrap the go-pkcs7 error where there is one. Use `errors.Is` with the
go-pkcs7 sentinel errors, such as `pkcs7.ErrDecryptionFailed` or
`pkcs7.ErrContentEncryptionNotAllowed`, to tell causes apart.

# Client options

`scepclient.New(serverURL, opts)` returns a client for one SCEP URL. The zero `Options` value is
usable. `New` returns an error for a URL without an `http` or `https` scheme or without a host and
for a negative `MaxResponseBytes`.

## Options

| Field | Type | Default | Effect |
| --- | --- | --- | --- |
| `HTTPClient` | `*http.Client` | A client with a `DefaultTimeout` timeout of 60 seconds | Sends the requests. Set it for proxies, TLS settings or another timeout |
| `CAName` | `string` | Empty | Sent as the `message` parameter of GetCACaps, GetCACert, GetCACertChain and GetNextCACert. Servers with several CAs on one URL pick the CA by it |
| `MaxResponseBytes` | `int64` | `DefaultMaxResponseBytes`, 8 MiB | The largest response body |
| `BusyRetries` | `int` | `DefaultBusyRetries`, 3 | How often a request is sent again after HTTP 503. A negative value turns retries off |
| `BusyDelay` | `time.Duration` | `DefaultBusyDelay`, 5 seconds | The wait after HTTP 503 without a Retry-After header in seconds |
| `Decrypt` | `pkcs7.DecryptOptions` | AES-128-CBC, AES-192-CBC, AES-256-CBC and DES-EDE3-CBC | The ciphers accepted in SUCCESS answers. The cipher of the request is always accepted. Add `pkcs7.DESCBC` for servers that answer with single DES |
| `OnBusy` | `func(*HTTPError, time.Duration)` | None | Called before each wait that follows HTTP 503 |

A Retry-After delay is capped at five minutes.

## Methods

| Method | Operation | Returns |
| --- | --- | --- |
| `GetCACaps(ctx)` | GetCACaps | `Capabilities`, which is also cached |
| `GetCACert(ctx)` | GetCACert | `*CACertificates` sorted by role |
| `GetCACertChain(ctx)` | GetCACertChain | The certificates in server order |
| `GetNextCACert(ctx, current)` | GetNextCACert | `*CACertificates` for the next CA, verified against `current.Signers` |
| `Enroll(ctx, ca, req)` | PKCSReq or RenewalReq | `*Result` |
| `Poll(ctx, ca, req)` | One CertPoll | `*Result` |
| `EnrollAndWait(ctx, ca, req, interval)` | The enrollment and CertPoll every interval while PENDING | `*Result` |
| `GetCert(ctx, ca, req)` | GetCert | The certificates of the answer |
| `GetCRL(ctx, ca, req)` | GetCRL | The DER encoded CRL |

`SortCACertificates(certs)` sorts certificates the caller loaded itself into a `*CACertificates`.

## EnrollRequest

| Field | Default | Meaning |
| --- | --- | --- |
| `MessageType` | `scep.PKCSReq` | `scep.PKCSReq` or `scep.RenewalReq` |
| `CSR` | Required | The certificate request |
| `SignerCertificate` | Required | A self-signed certificate for a PKCSReq, the certificate being renewed for a RenewalReq |
| `SignerKey` | Required | The key of the signer certificate. It must be an RSA `crypto.Decrypter` |
| `TransactionID` | `scep.CSRTransactionID(CSR)` | The transaction ID |
| `Digest` | Picked from the capabilities | The signature digest |
| `Encryption` | Cipher picked from the capabilities, PKCS #1 v1.5 key transport | The content cipher and key transport |

## QueryRequest

| Field | Default | Meaning |
| --- | --- | --- |
| `Issuer` | The subject of `ca.CA` | The DER encoded issuer name |
| `SerialNumber` | Required | The serial number of the certificate |
| `SignerCertificate`, `SignerKey` | Required | Sign the request. The key must be an RSA `crypto.Decrypter` |
| `Digest`, `Encryption` | As in `EnrollRequest` | The algorithms |

## Result

| Field | Content |
| --- | --- |
| `Status` | `scep.SUCCESS`, `scep.PENDING` or `scep.FAILURE` |
| `FailInfo` | The reason of a FAILURE |
| `Certificate` | The certificate for the CSR key |
| `Certificates` | Every certificate of a SUCCESS answer |
| `TransactionID` | The transaction ID for `Poll` |
| `Response` | The verified CertRep |

## Constants

| Name | Value |
| --- | --- |
| `DefaultTimeout` | 60 seconds |
| `DefaultMaxResponseBytes` | 8 MiB |
| `DefaultBusyRetries` | 3 |
| `DefaultBusyDelay` | 5 seconds |

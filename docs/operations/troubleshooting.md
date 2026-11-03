# Troubleshooting

Start with the handler log on the server side and the error text on the client side. The handler
logs the cause of every refusal, which it does not send to the client, as
[Refusals and logging](../server/refusals-and-logging.md#log-records) describes.

## Server side

| Symptom | Cause | Fix |
| --- | --- | --- |
| FAILURE with badAlg, cause `the request signer certificate has no RSA key` | The device signs with an ECDSA or other non-RSA key | The device must sign with an RSA key, see [Devices with ECDSA keys](../client/enrollment.md#devices-with-ecdsa-keys) |
| FAILURE with badAlg, cause `content encryption algorithm is not allowed` | The device encrypts with a cipher `Options.Decrypt` does not accept, usually single DES | Add `pkcs7.DESCBC` to `Options.Decrypt` for those devices |
| FAILURE with badMessageCheck | The pkiEnvelope does not decrypt with the responder key | Check that `Responder` returns the key of the certificate the device encrypted for |
| HTTP 400, reason `malformed or unverifiable pkiMessage` | The message does not parse, its signature does not verify, it is signed with MD5 or its certificate marks the authority key identifier critical. The cause `signing time ... is outside of certificate validity` means the signer certificate was expired or not yet valid at the signing-time, for example a RenewalReq signed with an expired certificate | Read the cause in the log. Set `Options.AllowMD5` for MD5 devices and `Options.LegacyCertificateParser` for the Windows clients that send such certificates. A device whose certificate expired enrolls again with a PKCSReq |
| HTTP 400, reason `the pkiEnvelope is not addressed to this CA` | `Responder` returned `ErrNotFound` for every recipient, often because the device still holds an old CA or RA certificate | Compare the recipient issuer and serial number with your certificates. Serve the old identity until devices have fetched the new one |
| HTTP 413 or 414 | The message is larger than `Options.MaxMessageBytes` | Raise the limit, for example for large RSA keys or long certificate chains |
| HTTP 500, log `scep request failed` | The CA returned no certificates or an error that is not `ErrPending`, `*Failure` or `*Busy` | Read the `error` attribute of the log record |
| HTTP 501 | GetCACertChain or GetNextCACert to a CA without the interface | Implement `ChainGetter` or `NextCAGetter`. Ignore it when the operation is not needed |

## Client side

| Error | Cause | Fix |
| --- | --- | --- |
| `scepclient.ErrEmptyResponse` from `GetCACert` | The server needs a CA name | Set `Options.CAName` |
| `scepclient.ErrNoRSARecipient` | No certificate in the GetCACert answer has an RSA key | The CA needs an RSA RA certificate |
| `scepclient: the signer key must be an RSA crypto.Decrypter` | `SignerKey` is not RSA | Sign with a separate RSA key and a self-signed certificate |
| `scep: verify pkiMessage` | The answer is not signed by a certificate in `CACertificates.Signers` | Fetch the CA certificates again. When you pin them, build the list with `SortCACertificates` and include the RA signing certificate |
| An error that wraps `pkcs7.ErrContentEncryptionNotAllowed` | The server answers with single DES | Add `pkcs7.DESCBC` to `Options.Decrypt` |
| `*scepclient.HTTPError` with status 503 | The server stayed busy longer than the retries | Raise `BusyRetries` or `BusyDelay` or try later |
| `*scepclient.HTTPError` with another status | The server refused without a CertRep. EJBCA, for example, answers a wrong challenge password with HTTP 401 and a missing one with HTTP 400 | Read `Body` and the server log |
| `the SUCCESS answer holds no certificate for the CSR key` | The server issued a certificate for another key | Check the CSR the device sent and the CA configuration |
| `Result.Status` FAILURE | The CA refused the request, for example for a wrong challenge password | Check the password and the subject with the CA operator |
| `EnrollAndWait` returns `context.DeadlineExceeded` with a PENDING result | Nobody approved the request in time | Extend the deadline or store the request and call `Poll` later |

## Gathering information

Before reporting a problem, collect:

* the go-pki-scep and Go versions
* the other side and its version
* the GetCACaps answer
* the handler log record or the client error text
* where possible, the request and the answer from a test with throwaway keys

Never share private keys, challenge passwords or messages captured from a production system.

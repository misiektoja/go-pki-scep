# Refusals and logging

The handler refuses some requests itself, before or instead of calling the CA. This page lists
those answers, the log records the handler writes and how a CA learns about refusals.

## HTTP refusals

These requests get an HTTP error and no CertRep. The body is a short reason and never contains the
cause.

| Request | Status | Body |
| --- | --- | --- |
| No `operation` parameter or an unknown operation | 400 | `unknown SCEP operation` |
| GetCACaps, GetCACert, GetCACertChain or GetNextCACert with a method other than GET | 405 with `Allow: GET` | `method not allowed` |
| PKIOperation with a method other than GET or POST | 405 with `Allow: GET, POST` | `method not allowed` |
| GetCACert or GetCACertChain for a name the CA returns `ErrNotFound` for | 404 | `unknown CA` |
| GetNextCACert while the CA returns `ErrNotFound` | 404 | `no next CA certificate` |
| GetCACertChain or GetNextCACert when the CA lacks the interface | 501 | `GetCACertChain is not supported` or `GetNextCACert is not supported` |
| PKIOperation POST with an empty body. GET without a valid base64 `message` | 400 | `malformed PKIOperation request` |
| PKIOperation POST over `MaxMessageBytes` | 413 | `malformed PKIOperation request` |
| PKIOperation GET with a `message` over `MaxMessageBytes` | 414 | `malformed PKIOperation request` |
| A message that does not parse or whose signature does not verify | 400 | `malformed or unverifiable pkiMessage` |
| A CertRep sent as a request | 400 | `a CertRep is not a request` |
| A pkiEnvelope for which `Responder` returns `ErrNotFound` for every recipient | 400 | `the pkiEnvelope is not addressed to this CA` |
| `*Busy` from the CA | 503 with Retry-After | `busy, retry later` |
| Any other error from the CA or an answer that cannot be built | 500 | `internal error` |

## FAILURE answers from the handler

These requests are answered with a FAILURE CertRep without reaching `Enroll`, `Poll`, `GetCert` or
`GetCRL`:

| Cause | failInfo | `Failure.Err` |
| --- | --- | --- |
| The signer certificate has no RSA key, so the answer could not be encrypted for it | badAlg | `scepserver.ErrSignerNotRSA` |
| The pkiEnvelope uses a cipher `Options.Decrypt` does not accept or an unsupported algorithm | badAlg | The go-pkcs7 error, such as `pkcs7.ErrContentEncryptionNotAllowed` |
| The pkiEnvelope does not decrypt with the responder key | badMessageCheck | Wraps `pkcs7.ErrDecryptionFailed` |
| The decrypted content is not a valid CSR, CSR signature or query | badRequest | The parse error |
| GetCert or GetCRL to a CA without `CertificateGetter` or `CRLGetter` | badRequest | `GetCert is not supported` or `GetCRL is not supported` |

`pkcs7.ErrDecryptionFailed` does not say whether the key or the padding was wrong, so a sender
cannot use the answer to probe the key.

## Recording refusals

A CA that implements `scepserver.RefusalRecorder` is called before each FAILURE answer in the
table above. Use it for audit records or to count devices that send what the CA cannot accept:

```go
// RecordRefusal writes an audit record for a request the handler refused on its own.
func (ca *myCA) RecordRefusal(ctx context.Context, req *scepserver.Request, failure *scepserver.Failure) {
	ca.audit.InfoContext(ctx, "scep request refused by the handler",
		"message_type", req.Message.MessageType.String(),
		"transaction_id", string(req.Message.TransactionID),
		"fail_info", failure.Info.String(),
		"signer_not_rsa", errors.Is(failure.Err, scepserver.ErrSignerNotRSA),
		"cause", failure.Err,
		"client", req.HTTPRequest.RemoteAddr)
}
```

The pkiEnvelope of the request may not be decrypted yet. Some refusals also concern messages
without a CSR, such as GetCert. `req.Message.CSRReqMessage`, `req.Message.PollRequest` and
`req.Message.CertificateID` can therefore be nil. `req.Message.CSR` is promoted from the embedded
`*CSRReqMessage`, so reading it while that pointer is nil panics. Check the pointer first. The handler does not call `RecordRefusal` for the outcomes the CA returns itself or for
the HTTP refusals.

## Log records

`Options.Logger` receives the records below. The default discards them.

| Message | Level | Attributes | Written for |
| --- | --- | --- | --- |
| `scep request answered` | Info | `message_type`, `transaction_id` and `status`. For FAILURE also `fail_info` and `cause` when there is one | Every CertRep, including FAILURE answers |
| `scep request deferred` | Info | `message_type`, `transaction_id`, `retry_after` | Every `*Busy` |
| `scep request refused` | Warn | `operation`, `status`, `reason`, `cause` when there is one | Every HTTP 404, 400, 413, 414 and 501 refusal except an unknown operation and a wrong method |
| `scep request failed` | Error | `operation`, `error` | Every HTTP 500 |

With `slog.NewTextHandler`, a refused request looks like this:

```text
time=2026-11-03T15:06:54.157+01:00 level=INFO msg="scep request answered" message_type="PKCSReq (19)" transaction_id=B485DB38004DF987172810E833FB1BB48D72867B status="FAILURE (2)" fail_info="badRequest (2)" cause="wrong challenge password"
```

The `cause` is `Failure.Err` of the CA or of the handler. Keep secrets such as the challenge
password out of it. The handler does not log the challenge password or the CSR.

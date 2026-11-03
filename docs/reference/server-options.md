# Server options

`scepserver.NewHandler(ca, opts)` returns the handler. The zero `Options` value is usable.

## Options

| Field | Type | Default | Effect |
| --- | --- | --- | --- |
| `Capabilities` | `[]string` | Derived, see [Capabilities](#capabilities) | Replaces the GetCACaps answer. Each entry must be one non-empty line |
| `Decrypt` | `pkcs7.DecryptOptions` | AES-128-CBC, AES-192-CBC, AES-256-CBC and DES-EDE3-CBC | The content ciphers accepted in requests. Add `pkcs7.DESCBC` only for clients that cannot send anything stronger |
| `AllowMD5` | `bool` | `false` | Accepts requests signed with the MD5 digest |
| `LegacyCertificateParser` | `bool` | `false` | Accepts requester certificates that mark the authority key identifier critical, which some Windows SCEP clients send |
| `Digest` | `crypto.Hash` | Follow the request, see below | The signature digest of CertRep messages and GetNextCACert answers |
| `ContentEncryption` | `pkcs7.ContentEncryptionAlgorithm` | Follow the request | The cipher of CertRep content. Set it for clients that send one cipher but decrypt another |
| `MaxMessageBytes` | `int64` | `DefaultMaxMessageBytes`, 64 KiB | The largest PKIOperation message, measured before base64 encoding for GET |
| `Logger` | `*slog.Logger` | Discards records | Receives the records listed in [Refusals and logging](../server/refusals-and-logging.md#log-records) |

With a zero `Digest`, a CertRep uses the request digest when it is MD5, SHA-1, SHA-256, SHA-384 or
SHA-512 and SHA-256 otherwise. A GetNextCACert answer uses SHA-256.

`NewHandler` returns an error for a nil CA, a negative `MaxMessageBytes` or a capability that is
empty or contains a line break.

A PKCSReq with a 4096-bit RSA key and its self-signed certificate takes about 6 KiB, so the default
limit leaves room. A GET request carries the message base64 encoded, so its `message` parameter may
be about a third longer than the limit, plus a margin for line breaks.

## Capabilities

Without `Options.Capabilities` the handler lists, in this order:

| Capability | Listed when |
| --- | --- |
| `AES` | `Decrypt` accepts an AES cipher, as it does by default |
| `DES3` | `Decrypt` accepts DES-EDE3-CBC, as it does by default |
| `GetNextCACert` | The CA implements `NextCAGetter` |
| `POSTPKIOperation` | Always |
| `Renewal` | Always |
| `SCEPStandard` | `Decrypt` accepts an AES cipher |
| `SHA-1`, `SHA-256`, `SHA-512` | Always |

The answer is one capability per line, each followed by a line feed, with the content type
`text/plain; charset=utf-8`. A replaced list is sent as given. The handler does not check that it
matches what the handler supports.

## HTTP interface

| Operation | Methods | Parameters |
| --- | --- | --- |
| GetCACaps | GET | `message` is ignored |
| GetCACert | GET | `message` is the CA name passed to `CACertificates` |
| GetCACertChain | GET | `message` is the CA name passed to `CACertificateChain` |
| GetNextCACert | GET | `message` is the CA name passed to `NextCACertificates` |
| PKIOperation | GET and POST | GET carries the base64 pkiMessage in `message`. POST carries the DER pkiMessage as the body |

In a GET `message`, a space is read as `+` and line breaks are removed, because some clients leave
the base64 text unescaped or split it into lines. [Optional operations](../server/optional-operations.md#answer-formats)
lists the answer formats and [Refusals and logging](../server/refusals-and-logging.md) the error
answers.

## Constants and errors

| Name | Meaning |
| --- | --- |
| `DefaultMaxMessageBytes` | 64 KiB, the default `MaxMessageBytes` |
| `ErrPending` | Returned by `Enroll` or `Poll` to answer PENDING |
| `ErrNotFound` | Returned for an unknown CA name, recipient or next CA certificate |
| `ErrSignerNotRSA` | The cause of the badAlg answer to a request signed with a key that is not RSA |
| `*Failure` | Refuses a request with a failInfo |
| `*Busy` | Asks the client to retry, answered with HTTP 503 |

[Errors and status values](errors.md) describes how each one reaches the client.

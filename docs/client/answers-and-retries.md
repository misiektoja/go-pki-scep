# Capabilities, answers and retries

The client adapts each request to the capabilities the server lists, verifies every answer and
retries when the server asks it to wait. This page explains those choices and the errors that come
out of them.

## Capabilities

```go
caps, err := client.GetCACaps(ctx)
if err != nil {
	return err
}
fmt.Println(caps.Has("Renewal"))
```

`GetCACaps` returns one entry per line of the answer with surrounding space and control characters
removed, including a NUL byte that some servers append. `Has` compares names without regard to
case. The client caches the list. The first PKIOperation fetches it when the program has not.

A server that answers GetCACaps with an HTTP error is treated as listing nothing. HTTP 503 is the
exception: it means the server is busy, so the client returns the error instead.

## Algorithms

With a zero `Digest` and `Encryption.ContentEncryption`, the client picks from the capabilities:

| Choice | Rule |
| --- | --- |
| HTTP method of PKIOperation | POST when the server lists POSTPKIOperation or SCEPStandard, otherwise GET with the base64 message in the `message` parameter |
| Signature digest | SHA-256 when the server lists SHA-256 or SCEPStandard, else SHA-512, else SHA-1, else SHA-256 |
| Content cipher | DES-EDE3-CBC when the server lists DES3 but neither AES nor SCEPStandard, otherwise AES-128-CBC |
| Key transport | RSA PKCS #1 v1.5 unless `Encryption.KeyEncryption` selects RSAES-OAEP |

A server that lists nothing gets GET, SHA-256 and AES-128-CBC.

## Verifying answers

For every PKIOperation answer the client:

1. Reads the CertRep from a 200 OK answer. It also reads it from any other status when the content
   type is `application/x-pki-message` and the body is not empty. Some servers send PENDING with
   HTTP 202 or FAILURE with HTTP 400.
2. Verifies the signature against `CACertificates.Signers` only. MD5 is accepted only when the
   request itself used MD5.
3. Checks that the transactionID matches the request and that the recipientNonce repeats its
   senderNonce. A CertRep without a senderNonce of its own is accepted.
4. Decrypts the content of a SUCCESS answer with the requester key. It accepts the ciphers in
   `Options.Decrypt`, AES-CBC and DES-EDE3-CBC by default, plus the cipher of the request.

A server that answers with single DES whatever the request used needs `pkcs7.DESCBC` in
`Options.Decrypt`. Without it the client returns an error that wraps
`pkcs7.ErrContentEncryptionNotAllowed`.

## HTTP errors

Any other answer becomes a `*scepclient.HTTPError`:

| Field | Content |
| --- | --- |
| `StatusCode` | The HTTP status |
| `RetryAfter` | The Retry-After header in seconds. Zero without the header |
| `Body` | Up to 256 bytes of the body on one line. It is empty when the body is not text, so binary data does not reach a terminal or a log |
| `ContentType` | The Content-Type header |

Many servers explain a refusal in the body, so show `Body` to the user:

```go
var httpErr *scepclient.HTTPError
if errors.As(err, &httpErr) {
	log.Printf("the server answered HTTP %d: %s", httpErr.StatusCode, httpErr.Body)
}
```

GetCACert, GetCACertChain and GetNextCACert return `scepclient.ErrEmptyResponse` for a 200 OK
answer without a body, which some servers send for a missing CA name or an operation they lack.

## Busy servers

A server answers HTTP 503 to make a client wait. The client then sends the same message again:

| Setting | Default | Effect |
| --- | --- | --- |
| `Options.BusyRetries` | 3 | How many times a request is sent again. A negative value turns retries off |
| Retry-After header | | The wait in seconds, capped at five minutes. HTTP dates are ignored |
| `Options.BusyDelay` | 5 seconds | The wait when the answer has no usable Retry-After header |
| `Options.OnBusy` | None | Called before each wait with the answer and the delay |

```go
client, err := scepclient.New(serverURL, scepclient.Options{
	BusyRetries: 5,
	OnBusy: func(answer *scepclient.HTTPError, delay time.Duration) {
		log.Printf("server busy (%s), retrying in %s", answer.Body, delay)
	},
})
```

When the retries run out, the 503 answer is returned as an `*HTTPError`. When the context ends
during a wait, the error joins the 503 answer and the context error.

## Transport

The default HTTP client has a 60-second timeout. Set `Options.HTTPClient` for proxies, TLS
settings or another timeout, for example to trust a private root for an `https` URL:

```go
roots := x509.NewCertPool()
roots.AddCert(tlsRoot)
client, err := scepclient.New("https://ca.example.com/scep", scepclient.Options{
	HTTPClient: &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}},
	},
})
```

Response bodies are limited to `Options.MaxResponseBytes`, 8 MiB by default, which leaves room for
large CRLs. A larger answer is an error.

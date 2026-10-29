# Changelog

Notable changes to go-scep. The library continues
[smallstep/scep](https://github.com/smallstep/scep), which has no tagged releases, so the first
release lists its changes relative to smallstep/scep commit 63893da.

## [Unreleased] - TBD

The module is now `github.com/misiektoja/go-scep` and needs Go 1.27.3. It adds an HTTP server
handler and an HTTP client next to the message layer, and the message layer covers every RFC 8894
message type. Options are passed per call through option structs. Defaults move to SHA-256
signing and AES-128-CBC encryption, and weak or malformed input is refused. Callers need code
changes, which the Changed and Removed sections list.

### Added
- **`scepserver`** serves SCEP over HTTP for a CA the caller implements: GetCACaps, GetCACert,
  GetNextCACert, GetCACertChain and PKIOperation over GET and POST. A CA can answer PENDING and
  complete the request on a later CertPoll, return a failInfo, or ask the client to retry later
  with HTTP 503 and `Retry-After`. GetCert, GetCRL, GetNextCACert and GetCACertChain are optional
  interfaces. Request bodies are limited to 64 KiB by default. Answers use the request digest and
  cipher unless `Options.Digest` or `Options.ContentEncryption` sets one.
- **`scepclient`** enrolls, renews, polls and queries a SCEP server: `Enroll`, `Poll`,
  `EnrollAndWait`, `GetCert`, `GetCRL`, `GetCACaps`, `GetCACert`, `GetCACertChain` and
  `GetNextCACert`. It picks the digest, cipher and HTTP method from the server capabilities,
  retries HTTP 503 answers and limits response size. `SortCACertificates` sorts a GetCACert
  answer into the CA, the encryption recipients and the certificates allowed to sign answers.
- **Every RFC 8894 message type.** `NewCertPollRequest`, `NewGetCertRequest` and
  `NewGetCRLRequest` build CertPoll, GetCert and GetCRL requests, and `ParsePKIMessage` parses
  them. `NewCSRRequest` builds UpdateReq messages as well.
- **`Pending`** answers PENDING and **`SuccessCRL`** answers a GetCRL.
- **`ParseOptions.Signers`** limits who may sign a message, so a CertRep that omits its signer
  certificate still verifies and a CertRep from any other key is refused.
- **`MatchesRequest`** checks that a CertRep answers a request: the same transaction ID and a
  recipientNonce that repeats the request senderNonce.
- **`EnvelopeRecipients`** lists the recipients of a request envelope, so a server with several
  keys can pick the one that decrypts it.
- **`CSRTransactionID`** derives the transaction ID from a CSR key, so a client can poll without
  storing the ID.
- **`SignedCertificates`** and **`ParseSignedCertificates`** build and verify the signed
  certificate list of a GetNextCACert answer.
- **Key identifiers** are derived for every key type crypto/x509 encodes, including Ed25519.

### Changed
- **The module path** is `github.com/misiektoja/go-scep`. Go 1.27.3 is the minimum. The CMS layer
  is `github.com/misiektoja/go-pkcs7`.
- **Option structs replace the functional options.** `ParsePKIMessage` takes `ParseOptions`,
  `NewCSRRequest` takes the message type, the CSR and `RequestOptions`, and `Success` and `Fail`
  take `ResponseOptions`.
- **Keys are `crypto.Signer` and `crypto.Decrypter`**, so they may live in an HSM.
  `DecryptPKIEnvelope` takes `pkcs7.DecryptOptions`.
- **Requests are signed with SHA-256 and encrypted with AES-128-CBC** by default. They used SHA-1
  and single DES.
- **Answers follow the request.** A CertRep uses the digest and the cipher of the request unless
  `ResponseOptions` sets them.
- **`Success` takes a certificate list**, such as the issued certificate and its chain, and no
  longer adds the issued certificate to the outer signed message.
- **The transaction ID** derived from a CSR key is the hex encoded key identifier. It was base64
  encoded.
- **CSR signatures are checked** when a request envelope is decrypted.
- **Single DES content and MD5 signatures are refused** unless the options allow them.
- **The `String` methods** of `MessageType`, `PKIStatus` and `FailInfo` describe unknown values.
  They panicked.

### Removed
- **`WithLogger`, `WithCACerts`, `WithCertsSelector`, `Option` and `Logger`.** The option structs
  replace them. `scepserver.Options.Logger` takes a `*slog.Logger`.

### Fixed
- **`Fail` reports the failInfo it sends.** The returned message reported badRequest whatever the
  argument was.
- **Each CertRep carries a fresh senderNonce.** `Success` and `Fail` reused the request
  senderNonce.

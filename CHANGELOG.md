# Changelog

Notable changes to go-scep, a continuation of [smallstep/scep](https://github.com/smallstep/scep).

## [0.1.0] - 2026-10-30

First release as `github.com/misiektoja/go-scep`. smallstep/scep has no tagged releases, so this
lists the changes since its commit 63893da. The module adds an HTTP server handler and an HTTP
client and covers every RFC 8894 message type. The defaults are SHA-256 and AES-128-CBC. Request
encryption needs RSA keys at both ends. Code written for smallstep/scep needs the changes under
Changed and Removed.

### Added
- **`scepserver`** serves SCEP over HTTP for a CA you implement: GetCACaps, GetCACert,
  GetCACertChain, GetNextCACert and PKIOperation over GET and POST. The CA can answer PENDING,
  finish on a later CertPoll or ask the client to retry with HTTP 503. Request bodies are limited
  to 64 KiB by default. Requests signed with a key other than RSA get badAlg.
- **`RefusalRecorder`** tells the CA about every request the handler refuses on its own.
- **`scepclient`** enrolls, renews, polls and queries a SCEP server. `EnrollAndWait` runs the whole
  PENDING loop. The client picks the digest, cipher and HTTP method from GetCACaps and retries
  HTTP 503. It reads a CertRep whatever the HTTP status of the answer.
- **`SortCACertificates`** splits a GetCACert answer into the CA, the RSA certificates to encrypt
  for and the certificates allowed to sign answers.
- **Every RFC 8894 message type**, including CertPoll, GetCert, GetCRL and UpdateReq. The
  **`Pending`** and **`SuccessCRL`** answers are new.
- **`ParseOptions.Signers`** verifies a CertRep that leaves out its signer certificate and refuses
  every other signer.
- **`MatchesRequest`** checks that a CertRep answers a given request.
- **`EnvelopeRecipients`**, **`CSRTransactionID`** and **`SignedCertificates`** help servers with
  several keys, clients that poll without storing state and GetNextCACert answers.

### Changed
- **Module path** `github.com/misiektoja/go-scep`. Go 1.27.3 or newer is required. The CMS layer is
  [go-pkcs7](https://github.com/misiektoja/go-pkcs7).
- **Option structs replace the functional options** in `ParsePKIMessage`, `NewCSRRequest`,
  `Success` and `Fail`.
- **Keys are `crypto.Signer` and `crypto.Decrypter`**, so they can live in an HSM.
- **Requests use SHA-256 and AES-128-CBC** by default. They used SHA-1 and DES-CBC. Answers use the
  digest and cipher of the request.
- **MD5 signatures and DES-CBC content are refused** unless the options allow them.
- **`Success` takes a certificate list**, such as the issued certificate and its chain. It no
  longer adds the issued certificate to the outer signed message.
- **Transaction IDs** derived from a CSR key are hex encoded. They were base64.
- **CSR signatures are checked** when a request is decrypted.

### Removed
- **`WithLogger`, `WithCACerts`, `WithCertsSelector`, `Option` and `Logger`.** Use the option
  structs. `scepserver.Options.Logger` takes a `*slog.Logger`.

### Fixed
- **`Fail` reports the failInfo it sends.** It always reported badRequest.
- **Each CertRep carries a fresh senderNonce.** It reused the one from the request.
- **`x509util.CreateCertificateRequest`** signs a request that has a challenge password with the
  requested algorithm, including SHA-1 and RSA-PSS.
- **`String` on `MessageType`, `PKIStatus` and `FailInfo`** no longer panics on unknown values.

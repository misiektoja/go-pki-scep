# Security model

This page states what the library checks, what it leaves to the code that embeds it and which
defaults protect both sides. Report vulnerabilities as the
[security policy](https://github.com/misiektoja/go-pki-scep/blob/main/SECURITY.md) describes.

## What a SCEP message protects

A pkiMessage is signed and its content is encrypted. Requests are encrypted for the CA or RA
certificate, so the CSR and the challenge password are readable only by the holder of that key.
Answers are encrypted for the certificate that signed the request. The signature covers the
encrypted content, so a changed envelope breaks the signature.

The HTTP transport adds nothing to this. Over plain HTTP the GetCACaps and GetCACert answers and
the fact that a device enrolls are visible and can be changed on the path. HTTPS hides them, but a
device still needs a trusted CA fingerprint for the GetCACert answer.

## What the handler checks

* The signature of each request, with the certificate the request carries. This proves that the
  requester holds the signer key. Any key can sign a request with a self-signed certificate.
* That the signing-time of a request, when present, falls within the validity of the signer
  certificate. The attribute is optional and the signer chooses its value, so it does not prove
  that the certificate is valid now.
* That the pkiEnvelope is addressed to an identity the CA returns from `Responder`.
* That the request signer key is RSA, so the answer can be encrypted for it.
* That the pkiEnvelope decrypts with an accepted cipher.
* For an enrollment, that the CSR signature is valid.
* The size of each PKIOperation message. A POST body is not read past `MaxMessageBytes`.

## What the CA decides

The handler does not authorize anyone. The CA decides:

* whether the challenge password of a PKCSReq is valid, compared in constant time
* whether the certificate that signs a RenewalReq was issued by the CA, is valid now and is not
  revoked, because the signing-time check of the handler does not settle that
* which subjects, names and key types a requester may get
* whether a CertPoll comes from the requester of the enrollment, because the answer is encrypted
  for the CertPoll signer
* who may fetch which certificate with GetCert and which CRL with GetCRL
* how often a device may poll, through `*scepserver.Busy`

Rate limits per client belong in HTTP middleware in front of the handler.

## What the client checks

* Nothing about the GetCACert answer. The caller checks the CA certificate against a fingerprint
  it trusts before it uses the answer.
* That each CertRep is signed by one of `CACertificates.Signers`. Certificates carried in the
  answer cannot replace them.
* That the transactionID and the recipientNonce of each CertRep match the request, so an answer to
  another request is refused.
* That GetNextCACert answers are signed by the current CA or RA.
* The size of each response body and the Retry-After delay a server can ask for.

## Algorithm defaults

| Area | Default | Opt-in for older peers |
| --- | --- | --- |
| Signature digest | SHA-256 | SHA-1 when a server lists SHA-1 but not SHA-256, SHA-512 or SCEPStandard. MD5 through `Digest` on the sending side and `AllowMD5` on the handler |
| Content cipher | AES-128-CBC. AES-CBC and DES-EDE3-CBC are accepted | Single DES through `Decrypt` on either side |
| Key transport | RSA PKCS #1 v1.5 | RSAES-OAEP for requests through `Encryption.KeyEncryption` |

PKCS #1 v1.5 key transport is what SCEP peers use. go-pkcs7 decrypts it with the countermeasure of
RFC 3218, so a failed decryption returns `pkcs7.ErrDecryptionFailed` whatever step failed. The
handler answers all of them with badMessageCheck, so a sender learns nothing about the padding.

## Information sent to clients

HTTP refusals carry a fixed reason. `Failure.Err` and internal errors are logged and never sent.
The client keeps at most 256 bytes of an error body in `HTTPError.Body` on one line. It drops a
body that is not text, so a hostile server cannot put control characters into a terminal or a log
through it.

## Logs

The handler logs transaction IDs, message types, statuses, failInfo values and the causes the CA
and the handler give. It never logs challenge passwords or CSRs. Keep secrets out of
`Failure.Err`, because it is logged.

## Not provided

* No storage. Pending requests, issued certificates and revocation state live in the CA.
* No TLS termination and no rate limiting.
* No password-based encryption of answers (PasswordRecipientInfo), so requesters need RSA keys to
  receive an answer.

# go-scep

[![GitHub Release](https://img.shields.io/github/v/release/misiektoja/go-scep?style=flat-square&color=blue)](https://github.com/misiektoja/go-scep/releases)
[![Go Reference](https://pkg.go.dev/badge/github.com/misiektoja/go-scep.svg)](https://pkg.go.dev/github.com/misiektoja/go-scep)
[![License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](LICENSE)
[![Tests](https://github.com/misiektoja/go-scep/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/misiektoja/go-scep/actions/workflows/test.yml)
[![Interop](https://github.com/misiektoja/go-scep/actions/workflows/interop.yml/badge.svg?branch=main)](https://github.com/misiektoja/go-scep/actions/workflows/interop.yml)
[![Supply chain](https://github.com/misiektoja/go-scep/actions/workflows/supply-chain.yml/badge.svg?branch=main)](https://github.com/misiektoja/go-scep/actions/workflows/supply-chain.yml)
[![OpenSSF Scorecard](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fapi.scorecard.dev%2Fprojects%2Fgithub.com%2Fmisiektoja%2Fgo-scep&query=%24.score&label=openssf%20scorecard&style=flat-square)](https://scorecard.dev/viewer/?uri=github.com/misiektoja/go-scep)

go-scep is a Go implementation of the Simple Certificate Enrollment Protocol (SCEP, RFC 8894), the
protocol routers, VPN gateways, mobile device managers and other network devices use to request
certificates from a CA. It has three packages:

* `scep` builds and parses the SCEP messages.
* `scepserver` is an HTTP handler that serves SCEP for a CA you implement.
* `scepclient` enrolls, renews, polls and queries a SCEP server.

The CMS layer comes from [go-pkcs7](https://github.com/misiektoja/go-pkcs7). Algorithm choices are
made per call through option structs. Nothing is configured through package variables.

## Contents

* [Install](#install)
* [Scope](#scope)
* [Getting started](#getting-started)
* [Security defaults](#security-defaults)
* [Compatibility](#compatibility)
* [Documentation](#documentation)
* [Limitations](#limitations)
* [Credits](#credits)
* [Support](#support)
* [License](#license)

## Install

```bash
go get github.com/misiektoja/go-scep
```

The module needs Go 1.27.3 or newer. Its only dependency is go-pkcs7. The API may still change
before v1.0.0, as [CHANGELOG.md](CHANGELOG.md) records.

## Scope

| Operation | Server handler | Client |
| --- | --- | --- |
| GetCACaps | Lists the capabilities, derived from the options or replaced by them | Fetched once and used to pick POST, the digest and the cipher |
| GetCACert | One DER certificate, or the CA and RA certificates in a certificate-only message | Sorts the answer into the CA, the encryption recipients and the allowed CertRep signers |
| GetNextCACert | The next CA certificates, signed by the current CA or RA, when the CA implements it | Verifies the signature against the current certificates |
| GetCACertChain | The CA certificate and its issuers up to the root in a certificate-only message, when the CA implements it | Returns the chain in server order |
| PKIOperation over GET and POST | Both, with a size limit | POST when the server lists POSTPKIOperation, GET otherwise |
| PKCSReq, RenewalReq and UpdateReq | Passed to the CA, which issues, keeps the request pending or refuses it | `Enroll` sends PKCSReq and RenewalReq |
| CertPoll | Passed to the CA | `Poll`, and `EnrollAndWait`, which polls while the answer is PENDING |
| GetCert and GetCRL | Passed to the CA when it implements them | `GetCert` and `GetCRL` |

The `scep` package handles every RFC 8894 message type in both directions: building and parsing
requests, decrypting their content and answering with SUCCESS, PENDING or FAILURE.

GetCACertChain is not part of RFC 8894. Some CAs still serve it for older clients. Its answer
carries no RA certificates, so clients enroll with the GetCACert answer.

## Getting started

A server implements `scepserver.CA` and mounts the handler. The CA decides who may enroll, for
example by checking the challenge password of a PKCSReq:

```go
handler, err := scepserver.NewHandler(myCA, scepserver.Options{Logger: slog.Default()})
if err != nil {
	return err
}
http.Handle("/scep", handler)
```

`Enroll` returns the issued certificate, `scepserver.ErrPending` to keep a request waiting for
approval, a `*scepserver.Failure` to refuse it or a `*scepserver.Busy` to ask the client to come
back later.

A client fetches the CA certificates, checks them against a fingerprint it trusts and enrolls:

```go
client, err := scepclient.New("https://ca.example.com/scep", scepclient.Options{})
if err != nil {
	return err
}
certs, err := client.GetCACert(ctx)
if err != nil {
	return err
}
// Compare certs.CA with a fingerprint obtained out of band before going further.
res, err := client.EnrollAndWait(ctx, certs, scepclient.EnrollRequest{
	CSR:               csr,
	SignerCertificate: selfSigned,
	SignerKey:         key,
}, 30*time.Second)
if err != nil {
	return err
}
if res.Status != scep.SUCCESS {
	return fmt.Errorf("enrollment refused: %s", res.FailInfo)
}
```

A PKCSReq is signed with a self-signed certificate for the CSR key. A RenewalReq is signed with the
certificate being renewed. `x509util.CreateCertificateRequest` adds the challenge password to a CSR.

## Security defaults

* **CertRep signers** are restricted. The client accepts a CertRep only when one of the CA or RA
  certificates from GetCACert signed it, even when the message carries its own certificate.
* **Answers are matched** to their requests by transaction ID and nonce.
* **Requester authorization** belongs to the CA. The handler verifies the signature and decrypts
  the request, then passes the challenge password and the signer certificate to the CA.
* **CSR signatures** are checked before the CA sees the request.
* **Ciphers** default to AES-128-CBC. The handler and the client accept AES-CBC and DES-EDE3-CBC.
  Single DES needs `Decrypt` in the options of either side.
* **Digests** default to SHA-256. MD5 signatures are refused unless `AllowMD5` is set.
* **Sizes are bounded**: messages on the server, response bodies on the client and the Retry-After
  delay a server can ask for.
* **Errors inside the CA** are answered with HTTP 500 and logged, so the client retries instead of
  treating the transaction as refused. Internal error text never reaches the client.

## Compatibility

The client copes with server behavior that RFC 8894 does not require:

* A CertRep without a senderNonce or without the signer certificate.
* A capability list that ends with a NUL byte.
* An empty 200 OK for an operation the server does not support.
* HTTP 503 without a Retry-After header, sent to throttle requests that arrive close together.
  The client retries after `BusyDelay`, five seconds by default.
* CertRep messages signed with SHA-1.
* Answers encrypted with single DES whatever the request used, when `Options.Decrypt` allows it.

The Interop workflow runs these peers on every change:

| Peer | Direction |
| --- | --- |
| sscep v0.10.0 | Against the handler: getcaps, getca, enroll with polling, getcert and getcrl |
| micromdm/scep v2.3.0 client | Against the handler: enrollment with a challenge password |
| micromdm/scep v2.3.0 server | The client enrolls, and a wrong challenge password is refused |

## Documentation

The package documentation on [pkg.go.dev](https://pkg.go.dev/github.com/misiektoja/go-scep)
describes every exported type and option. Repository files:

* [SUPPORT.md](SUPPORT.md) explains where to ask and what to include.
* [CONTRIBUTING.md](CONTRIBUTING.md) lists the development checks.
* [SECURITY.md](SECURITY.md) explains how to report a vulnerability.
* [DEPENDENCIES.md](DEPENDENCIES.md) lists the dependency and the copied code with their licenses.
* [CHANGELOG.md](CHANGELOG.md) records user-visible changes per release.

## Limitations

* **Requesters need RSA keys.** Answers are encrypted for the request signer certificate with RSA
  key transport, as RFC 8894 requires.
* **No storage.** The CA implementation keeps pending requests, issued certificates and CRLs.
* **No CA chain validation in the client.** The caller decides whether to trust the GetCACert
  answer, such as by a pinned fingerprint.
* **No automatic CA rollover.** `GetNextCACert` returns the next certificates and the caller
  switches to them.
* **No AES-GCM or AuthEnvelopedData.**
* **Retry-After** is read in seconds. HTTP dates are ignored.

## Credits

go-scep continues the work of these projects and their contributors:

* [micromdm/scep](https://github.com/micromdm/scep), the original implementation by Victor
  Vrantchan and the MicroMDM contributors.
* [smallstep/scep](https://github.com/smallstep/scep), the Smallstep fork of the message layer
  this repository started from.

Both are MIT licensed. [NOTICE](NOTICE) records the origins of the code, including the Go standard
library code in `x509util`.

## Support

[SUPPORT.md](SUPPORT.md) directs usage questions, bug reports, feature requests and security
reports.

## License

Licensed under the [MIT License](LICENSE). The Go code in `x509util` keeps the Go BSD-style license
in its file header, as [NOTICE](NOTICE) describes.

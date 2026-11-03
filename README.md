# go-pki-scep

[![GitHub Release](https://img.shields.io/github/v/release/misiektoja/go-pki-scep?style=flat-square&color=blue)](https://github.com/misiektoja/go-pki-scep/releases)
[![Go Reference](https://pkg.go.dev/badge/github.com/misiektoja/go-pki-scep.svg)](https://pkg.go.dev/github.com/misiektoja/go-pki-scep)
[![License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](LICENSE)
[![Tests](https://github.com/misiektoja/go-pki-scep/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/misiektoja/go-pki-scep/actions/workflows/test.yml)
[![Interop](https://github.com/misiektoja/go-pki-scep/actions/workflows/interop.yml/badge.svg?branch=main)](https://github.com/misiektoja/go-pki-scep/actions/workflows/interop.yml)
[![Supply chain](https://github.com/misiektoja/go-pki-scep/actions/workflows/supply-chain.yml/badge.svg?branch=main)](https://github.com/misiektoja/go-pki-scep/actions/workflows/supply-chain.yml)
[![OpenSSF Scorecard](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fapi.scorecard.dev%2Fprojects%2Fgithub.com%2Fmisiektoja%2Fgo-pki-scep&query=%24.score&label=openssf%20scorecard&style=flat-square)](https://scorecard.dev/viewer/?uri=github.com/misiektoja/go-pki-scep)

go-pki-scep is a Go implementation of the Simple Certificate Enrollment Protocol (SCEP,
RFC 8894). Routers, VPN gateways, mobile device managers and other network devices use SCEP to
request certificates from a CA. The module has three packages:

* `scep` builds and parses SCEP messages and answers requests without any transport.
* `scepserver` is an `http.Handler` that serves SCEP for a CA you implement.
* `scepclient` enrolls, renews, polls and queries a SCEP server over HTTP.

The library handles message signatures and encryption, nonces, transaction IDs and the HTTP
operations. Your code decides who may enroll, issues the certificates and keeps the state of the
CA. The CMS layer comes from [go-pkcs7](https://github.com/misiektoja/go-pkcs7).

## Contents

* [Install](#install)
* [Scope](#scope)
* [Getting started](#getting-started)
* [Documentation](#documentation)
* [Limitations](#limitations)
* [Credits](#credits)
* [Support](#support)
* [License](#license)

## Install

```bash
go get github.com/misiektoja/go-pki-scep
```

The module needs Go 1.27.3 or newer. Its only dependency is go-pkcs7.

## Scope

| Operation | Server handler | Client |
| --- | --- | --- |
| GetCACaps and GetCACert | Yes | Yes |
| PKCSReq and RenewalReq | Passed to the CA, which issues, keeps the request pending or refuses it | `Enroll` and `EnrollAndWait` |
| UpdateReq | Passed to the CA | Message layer only |
| CertPoll | Passed to the CA | `Poll` |
| GetCert and GetCRL | When the CA implements them | `GetCert` and `GetCRL` |
| GetNextCACert and GetCACertChain | When the CA implements them | `GetNextCACert` and `GetCACertChain` |

The `scep` package builds, parses and answers every RFC 8894 message type. sscep, the micromdm/scep
client and server and EJBCA run against the module in CI, see
[Tested implementations](https://misiektoja.github.io/go-pki-scep/interoperability/tested-implementations/).
The API may still change before v1.0.0 as described in the
[Compatibility policy](https://misiektoja.github.io/go-pki-scep/reference/compatibility/).

## Getting started

A server implements `scepserver.CA` and mounts the handler. The CA decides who may enroll, for
example by checking the challenge password of a PKCSReq:

```go
handler, err := scepserver.NewHandler(myCA, scepserver.Options{Logger: slog.Default()})
if err != nil {
	log.Fatal(err)
}
http.Handle("/scep", handler)
```

A device fetches the CA certificates with `GetCACert`, checks them against a fingerprint it trusts
and enrolls with `EnrollAndWait` from `scepclient`.

[Getting started](https://misiektoja.github.io/go-pki-scep/getting-started/) builds a local server
and client in one file, enrolls and renews a certificate and names what to replace before
production. That program is in [examples/quickstart](examples/quickstart/) and runs with
`go run ./examples/quickstart`. The package example in `example_test.go` shows the message layer
without HTTP.

## Documentation

Full documentation is at
[misiektoja.github.io/go-pki-scep](https://misiektoja.github.io/go-pki-scep/).

* [Getting started](https://misiektoja.github.io/go-pki-scep/getting-started/)
* [Support matrix](https://misiektoja.github.io/go-pki-scep/support-matrix/)
* [Architecture](https://misiektoja.github.io/go-pki-scep/architecture/)
* [Implementing a CA](https://misiektoja.github.io/go-pki-scep/server/implementing-a-ca/)
* [Pending requests and throttling](https://misiektoja.github.io/go-pki-scep/server/pending-requests/)
* [Optional operations](https://misiektoja.github.io/go-pki-scep/server/optional-operations/)
* [Refusals and logging](https://misiektoja.github.io/go-pki-scep/server/refusals-and-logging/)
* [CA certificates and trust](https://misiektoja.github.io/go-pki-scep/client/ca-certificates/)
* [Enrollment and renewal](https://misiektoja.github.io/go-pki-scep/client/enrollment/)
* [Capabilities, answers and retries](https://misiektoja.github.io/go-pki-scep/client/answers-and-retries/)
* [Message layer](https://misiektoja.github.io/go-pki-scep/message-layer/)
* [Server options](https://misiektoja.github.io/go-pki-scep/reference/server-options/) and [Client options](https://misiektoja.github.io/go-pki-scep/reference/client-options/)
* [Troubleshooting](https://misiektoja.github.io/go-pki-scep/operations/troubleshooting/)
* [Security model](https://misiektoja.github.io/go-pki-scep/security/security-model/)

The package documentation on [pkg.go.dev](https://pkg.go.dev/github.com/misiektoja/go-pki-scep)
describes every exported type and option. Repository files:

* [SUPPORT.md](SUPPORT.md) explains where to ask and what to include.
* [CONTRIBUTING.md](CONTRIBUTING.md) lists the development checks.
* [SECURITY.md](SECURITY.md) explains how to report a vulnerability.
* [DEPENDENCIES.md](DEPENDENCIES.md) lists the dependency and the copied code with their licenses.
* [CHANGELOG.md](CHANGELOG.md) records user-visible changes per release.

## Limitations

* Requests and answers use RSA key transport, so a requester signs with an RSA key and a CA
  without an RSA key needs an RSA RA certificate. A CSR may still carry an ECDSA key.
  Password-based encryption of answers (PasswordRecipientInfo) is not supported.
* No storage. The CA keeps pending requests, issued certificates and CRLs.
* The client makes no trust decision about the GetCACert answer. The caller checks it, for
  example against a pinned fingerprint.
* No automatic CA rollover, AES-GCM or AuthEnvelopedData.

[Known limitations](https://misiektoja.github.io/go-pki-scep/known-limitations/) explains each gap.

## Credits

go-pki-scep continues the work of these projects and their contributors:

* [micromdm/scep](https://github.com/micromdm/scep), the original implementation by Victor
  Vrantchan and the MicroMDM contributors.
* [smallstep/scep](https://github.com/smallstep/scep), the Smallstep fork of the message layer
  this repository started from.

Both are MIT licensed. [NOTICE](NOTICE) records the origins of the code, including the Go standard
library code in `x509util`.

## Support

[SUPPORT.md](SUPPORT.md) directs usage questions, bug reports, feature requests and security
reports. Check
[Troubleshooting](https://misiektoja.github.io/go-pki-scep/operations/troubleshooting/)
and gather the versions, the failInfo or HTTP status and the server log before posting.

## License

Licensed under the [MIT License](LICENSE). The Go code in `x509util` keeps the Go BSD-style license
in its file header, as [NOTICE](NOTICE) describes.

# go-pki-scep

go-pki-scep is a Go implementation of the Simple Certificate Enrollment Protocol (SCEP,
RFC 8894). Routers, VPN gateways, mobile device managers and other network devices use SCEP to
request certificates from a CA. The module has three packages:

* `scep` builds and parses SCEP messages and answers requests without any transport.
* `scepserver` is an `http.Handler` that serves SCEP for a CA you implement.
* `scepclient` enrolls, renews, polls and queries a SCEP server over HTTP.

The library handles the protocol: message signatures and encryption, nonces, transaction IDs,
the HTTP operations and the answers. Your code decides who may enroll, issues the certificates and
keeps whatever state the CA needs. The CMS layer comes from
[go-pkcs7](https://misiektoja.github.io/go-pkcs7/). Algorithm choices are made per call through
option structs. Nothing is configured through package variables.

```bash
go get github.com/misiektoja/go-pki-scep
```

The module needs Go 1.27.3 or newer. Its only dependency is go-pkcs7.

## Where to go next

| I want to | Page |
| --- | --- |
| Run a SCEP server and client on my machine | [Getting started](getting-started.md) |
| See which operations, message types and algorithms are supported | [Support matrix](support-matrix.md) |
| Understand how the packages and a request fit together | [Architecture](architecture.md) |
| Serve SCEP for my CA | [Implementing a CA](server/implementing-a-ca.md) |
| Approve requests later or throttle clients | [Pending requests and throttling](server/pending-requests.md) |
| Enroll or renew a device from a Go program | [Enrollment and renewal](client/enrollment.md) |
| Decide whether to trust a CA certificate | [CA certificates and trust](client/ca-certificates.md) |
| Build SCEP messages without HTTP | [Message layer](message-layer.md) |
| Look up an option or a default | [Server options](reference/server-options.md) and [Client options](reference/client-options.md) |
| Find out which SCEP implementations were tested | [Tested implementations](interoperability/tested-implementations.md) |
| Fix a refused request | [Troubleshooting](operations/troubleshooting.md) |
| Know what the library checks and what it leaves to me | [Security model](security/security-model.md) |
| Check what is not supported | [Known limitations](known-limitations.md) |
| Look up a type or function | [Package documentation](https://pkg.go.dev/github.com/misiektoja/go-pki-scep) |
| See what changed in a release | [Changelog](https://github.com/misiektoja/go-pki-scep/blob/main/CHANGELOG.md) |
| Ask for help or report a problem | [Support](https://github.com/misiektoja/go-pki-scep/blob/main/SUPPORT.md) |
| Report a vulnerability | [Security policy](https://github.com/misiektoja/go-pki-scep/blob/main/SECURITY.md) |
| Contribute | [Contributing](https://github.com/misiektoja/go-pki-scep/blob/main/CONTRIBUTING.md) |

## Credits

go-pki-scep continues the work of these projects and their contributors:

* [micromdm/scep](https://github.com/micromdm/scep), the original implementation by Victor
  Vrantchan and the MicroMDM contributors.
* [smallstep/scep](https://github.com/smallstep/scep), the Smallstep fork of the message layer
  this repository started from.

Both are MIT licensed. [NOTICE](https://github.com/misiektoja/go-pki-scep/blob/main/NOTICE) records
the origins of the code, including the Go standard library code in `x509util`.

## Related projects

Other PKI projects from the same maintainer:

* [certrally](https://misiektoja.github.io/certrally/): a command line client for certificate enrollment over CMP, EST and SCEP
* [cmp-issuer](https://misiektoja.github.io/cmp-issuer/): a cert-manager external issuer for CMP servers
* [go-acme-server](https://misiektoja.github.io/go-acme-server/): an embeddable ACME server library for Go (RFC 8555)
* [go-pki-cmp](https://misiektoja.github.io/go-pki-cmp/): a Go library for the Certificate Management Protocol (CMP) with a client and a server
* [go-pki-est](https://misiektoja.github.io/go-pki-est/): a Go library for Enrollment over Secure Transport (EST, RFC 7030) with a client and a server
* [go-pkcs7](https://misiektoja.github.io/go-pkcs7/): a Go library for PKCS #7 and CMS (RFC 5652) signed and enveloped data
* [go-composite-mldsa](https://misiektoja.github.io/go-composite-mldsa/): a Go library for post-quantum composite ML-DSA signatures
* [go-tls-srp](https://github.com/misiektoja/go-tls-srp): TLS 1.2 with SRP password authentication (RFC 5054) for Go

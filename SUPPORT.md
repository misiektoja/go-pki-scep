# Getting help

Start with the [README](README.md), which covers the supported operations, the security defaults
and the server behavior the client copes with. The package documentation on
[pkg.go.dev](https://pkg.go.dev/github.com/misiektoja/go-scep) describes every exported type.

## Check your setup first

Many problems come from limits the library applies on purpose. Before asking, confirm that:

* The requester key is RSA. Answers are encrypted for the request signer certificate.
* A device that encrypts with single DES talks to a handler whose `Options.Decrypt` lists
  `pkcs7.DESCBC`. A server that answers with single DES needs the same in the client options.
* A device that signs with MD5 talks to a handler with `Options.AllowMD5`.
* The CertRep is signed by a certificate in `CACertificates.Signers`. A client that pins its CA
  certificates builds that list with `scepclient.SortCACertificates`.
* A server that throttles with HTTP 503 gets enough retries through `BusyRetries` and
  `BusyDelay`.

## Where to ask

| You want to | Go to |
| --- | --- |
| Ask a usage question or discuss an idea | [Discussions](https://github.com/misiektoja/go-scep/discussions) |
| Report something broken | [Bug report](https://github.com/misiektoja/go-scep/issues/new?template=bug_report.yml) |
| Request a capability | [Feature request](https://github.com/misiektoja/go-scep/issues/new?template=feature_request.yml) |
| Report a vulnerability | [Private security advisory](https://github.com/misiektoja/go-scep/security/advisories/new), never a public issue |
| Contribute a change | [CONTRIBUTING.md](CONTRIBUTING.md) |

## Before you post

Include the go-scep version, the Go version, the device or server on the other side and its
version and the algorithms involved. Attach the error and, where you can, a request or answer
captured with a throwaway key.

Never post private keys, challenge passwords or messages captured from a production system. See
[SECURITY.md](SECURITY.md).

## What to expect

This project is maintained in spare time, so replies are best effort with no response time
attached. Only the latest release receives fixes, as [SECURITY.md](SECURITY.md) describes, so
reproduce the problem on the current version before reporting it.

# Tested implementations

The [Interop workflow](https://github.com/misiektoja/go-pki-scep/actions/workflows/interop.yml)
runs other SCEP implementations against the handler and the client on every push and pull request
to `dev` and `main` and once a week. The peers are built from pinned sources or run from images
pinned by digest. A peer that is missing fails the run instead of being skipped.

## Clients against the handler

The handler serves `internal/testca`, an in-memory RSA CA with a challenge password.

| Client | Version | What the run covers |
| --- | --- | --- |
| [sscep](https://github.com/certnanny/sscep) | v0.10.0, commit `b3f9798` | `getcaps`. `getca` returns the CA certificate. `enroll` with AES and SHA-256: the CA answers PENDING and issues on the first CertPoll. `getcert` fetches the issued certificate by serial number. `getcrl` fetches a CRL signed by the CA |
| [micromdm/scep](https://github.com/micromdm/scep) `scepclient` | v2.3.0 | Enrollment with a challenge password. The issued certificate has the requested subject and verifies against the CA |

The micromdm/scep v2.3.0 client encrypts with single DES, the default of the smallstep/pkcs7
v0.1.1 library it uses. The test therefore adds `pkcs7.DESCBC` to the handler `Options.Decrypt`.
It does not assert which cipher the client chose.

## The client against servers

| Server | Version | What the run covers |
| --- | --- | --- |
| [micromdm/scep](https://github.com/micromdm/scep) `scepserver` | v2.3.0 | GetCACaps and GetCACert. A PKCSReq with the challenge password gets SUCCESS and a certificate that verifies against the CA. A wrong challenge password gets FAILURE |
| EJBCA Community Edition | 9.6.3, image `keyfactor/ejbca-ce:9.6.3` | GetCACaps and GetCACert with a CA name. GetCACertChain returns the issuing CA and its root. A PKCSReq with the end entity password gets SUCCESS. A second request with the same password gets FAILURE. A wrong password gets HTTP 401 and a missing one HTTP 400, both without a CertRep |

The micromdm/scep v2.3.0 server encrypts its answers with the same single DES default. The test
therefore adds `pkcs7.DESCBC` to the client `Options.Decrypt` for that run. It does not assert
which cipher the server chose.

EJBCA runs with two RSA CAs, a root and an issuing CA. Its SCEP alias runs in CA mode, where the CSR
common name names the end entity and its password is the challenge password. The client sets
`Options.CAName` to the issuing CA.

## Running the tests locally

The interop tests have the `interop` build tag. `make interop` runs the sscep and micromdm/scep
tests and skips each one whose peer is missing:

```bash
make interop
```

Point `SSCEP` and `MICROMDM_SCEPCLIENT` at the client binaries when they are not on the `PATH`.
The tests against servers need a running server: set `SCEP_INTEROP_MICROMDM_URL` and
`SCEP_INTEROP_MICROMDM_CHALLENGE` for micromdm/scep. Set `SCEP_INTEROP_EJBCA_URL`,
`SCEP_INTEROP_EJBCA_CA` and `SCEP_INTEROP_EJBCA_CHALLENGE` for EJBCA and run
`make interop INTEROP_RUN=TestEJBCAServer`. The
[workflow file](https://github.com/misiektoja/go-pki-scep/blob/main/.github/workflows/interop.yml)
shows how CI starts each peer.

## Other servers

The client copes with server behavior that RFC 8894 does not require. Unit tests in `scepclient`
simulate each case. The CertRep without a senderNonce or certificates is tested in the `scep`
package, whose parser the client uses:

* A capability list that ends with a NUL byte.
* An empty 200 OK to GetCACert, GetCACertChain or GetNextCACert, returned as
  `scepclient.ErrEmptyResponse`.
* A CertRep without a senderNonce or without certificates.
* A CertRep signed with SHA-1.
* A PENDING CertRep with HTTP 202 and a FAILURE CertRep with HTTP 400.
* HTTP 503 with or without a Retry-After header.
* A GetCACert answer as a PEM certificate.
* An answer encrypted with single DES whatever the request used, when `Options.Decrypt` allows it.

[certrally](https://misiektoja.github.io/certrally/), a command line client built on this
library, records the behavior of further SCEP servers in its
[interoperability notes](https://misiektoja.github.io/certrally/interop/).

# Compatibility policy

The module uses semantic versioning. Its public API is every exported identifier of the `scep`,
`scepserver`, `scepclient`, `x509util` and `cryptoutil` packages. `internal/testca` and the
programs under `examples` are not part of it.

## Before v1.0.0

A minor release may change the public API.
[CHANGELOG.md](https://github.com/misiektoja/go-pki-scep/blob/main/CHANGELOG.md) describes every
change that affects callers, including any that needs a code change.

## Optional interfaces

The handler finds the optional CA interfaces, `CertificateGetter`, `CRLGetter`, `NextCAGetter`,
`ChainGetter` and `RefusalRecorder`, with type assertions at run time. A CA that lacks one still
compiles and the handler falls back as [Optional operations](../server/optional-operations.md)
describes. A method added to `scepserver.CA` itself is a compile error that names what to
implement.

## Upgrading

1. Read the CHANGELOG section of each version between yours and the new one.
2. Run `go get github.com/misiektoja/go-pki-scep@vX.Y.Z` and build.
3. Run your tests against the SCEP clients or servers you support.
   [Tested implementations](../interoperability/tested-implementations.md) names the versions the
   Interop workflow runs.

## Go version

The module declares the minimum Go version in `go.mod`, currently 1.27.3. CI builds and tests with
exactly that version.

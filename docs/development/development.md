# Development

How to build, check and change the library. Contribution rules are in
[CONTRIBUTING.md](https://github.com/misiektoja/go-pki-scep/blob/main/CONTRIBUTING.md).

## Prerequisites

* Go at the version `go.mod` declares.
* Python 3 with the MkDocs toolchain for the documentation site, installed by `make docs-deps`
  from packages pinned by hash.
* sscep and the micromdm/scep client for the interop tests, see [Testing](testing.md).

golangci-lint, actionlint, govulncheck, gitleaks and cyclonedx-gomod are downloaded into `bin/` at
pinned versions by the Make targets that need them.

## Repository layout

| Path | Content |
| --- | --- |
| root package `scep` | The pkiMessage layer: building, parsing, decrypting and answering |
| `scepserver/` | The HTTP handler and the `CA` interfaces |
| `scepclient/` | The HTTP client and the sorting of CA certificates |
| `x509util/` | CSRs with a challenge password, partly copied from the Go standard library |
| `cryptoutil/` | Key identifiers for transaction IDs |
| `internal/testca/` | The in-memory CA the tests run against |
| `examples/` | Runnable programs, built and tested with the root module |
| `testdata/` | Message fixtures with their test certificates and keys |
| `docs/` | This site |

## Common commands

```bash
make fmt-check    # fail when a tracked Go file is not gofmt formatted
make lint         # golangci-lint at the version CI uses
make test         # go vet and the tests under the race detector
make fuzz         # each fuzz target for FUZZTIME, 30s by default
make interop      # sscep and micromdm/scep against the module
make docs-build   # strict MkDocs build
make help         # every target
```

Run `make tidy-check` when `go.mod` changes, `make govulncheck` when a dependency changes and
`make actionlint` when a workflow changes. `make gitleaks` scans the working tree and the commit
history for credentials.

## Documentation

The site is built with MkDocs and the Material theme from `docs/` and `mkdocs.yml`. Set `PYTHON`
when the MkDocs toolchain lives in a virtual environment:

```bash
make docs-deps PYTHON=.venv/bin/python
make docs-serve PYTHON=.venv/bin/python
```

`make docs-build` runs with `--strict`, so a broken link, a missing anchor or a page absent from
the navigation fails the build. Pages include code from `examples/quickstart` and from `Example` in
`example_test.go` through snippet markers, so that code is compiled and run by `make test`. Keep
the `--8<--` marker lines when you edit those files. CI runs the same build on every change to the
documentation and publishes the site from `main`.

## Continuous integration

| Workflow | Runs |
| --- | --- |
| Tests | Tidy and format checks, the build, the tests and 30 seconds of each fuzz target on Linux, the tests on macOS and the build on Windows |
| Lint | golangci-lint, its configuration check and actionlint |
| Interop | sscep, micromdm/scep and EJBCA against the module, also weekly |
| Supply chain | govulncheck and gitleaks, also weekly |
| CodeQL and Scorecard | Static analysis and the OpenSSF Scorecard checks |
| Documentation | The strict site build and publishing from `main` |
| Release | The release artifacts for a version tag, see [Release process](release-process.md) |

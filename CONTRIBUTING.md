# Contributing

go-pki-scep is a Go implementation of SCEP, the certificate enrollment protocol of RFC 8894. Bug reports, interoperability results and code contributions are welcome. Usage questions belong in Discussions, as [SUPPORT.md](SUPPORT.md) describes.

## Before contributing

Contribute only code you have the right to license under the MIT License. Do not copy code from another SCEP implementation without checking its license and naming the source in the pull request. The project derives from [smallstep/scep](https://github.com/smallstep/scep) and [micromdm/scep](https://github.com/micromdm/scep), as [NOTICE](NOTICE) records.

Never commit private keys other than throwaway test keys, challenge passwords or messages captured from a production system. Keep scratch files and local test state out of commits.

Open pull requests against `dev`. Pull requests run the formatting, vet, lint, test, fuzz, interop and supply chain checks. `dev` and `main` accept a change only after the build, test, lint, vulnerability and credential scan checks pass.

## Development checks

Run these before submitting a change:

```bash
make fmt-check
make lint
make test
```

`make fmt-check` fails when a tracked Go file is not gofmt formatted. `make lint` runs golangci-lint at the version CI uses, installed under `bin/`. `make test` runs `go vet` and the tests under the race detector. `make fuzz` runs each fuzz target for 30 seconds, or for `FUZZTIME`. Run `make tidy-check` when `go.mod` changes, `make govulncheck` when a dependency changes and `make actionlint` when a workflow changes. `make gitleaks` scans the working tree and the commit history for credentials. `make help` lists every target.

`make interop` runs sscep and the micromdm/scep tools against the module. Each test skips when its tool is missing, and [the Interop workflow](.github/workflows/interop.yml) shows how CI builds them. Point `SSCEP` and `MICROMDM_SCEPCLIENT` at the binaries, or set `SCEP_INTEROP_MICROMDM_URL` and `SCEP_INTEROP_MICROMDM_CHALLENGE` for a running micromdm/scep server.

Protocol changes need negative tests and an RFC citation. A parser or handler change also needs a fuzz run, and a crash the fuzzer finds stays in `testdata/fuzz` as a regression input. Interoperability claims need evidence naming the peer and its version. User-facing behavior changes update the Go doc comments, the README and [CHANGELOG.md](CHANGELOG.md).

## Compatibility

The module uses semantic versioning. Versions before v1.0.0 may change the API in a minor release. [CHANGELOG.md](CHANGELOG.md) describes every change that affects callers, including any that needs a code change.

## Releases

[CHANGELOG.md](CHANGELOG.md) has one section per version, dated on the release day. Before tagging, run the release check on `main`. With `VERSION` set it also checks the changelog heading:

```bash
VERSION=v0.1.0 make release-check
```

It tests an export of `HEAD` and imports it from a separate module, so it catches files that are untracked or only present locally. A release starts when a version tag reachable from `main` is pushed:

```bash
git tag -s v0.1.0 -m 'v0.1.0'
git push origin main v0.1.0
```

The release workflow repeats the check on the tag, builds source archives, an SBOM and checksums, attests their provenance and creates a draft release with the changelog section as its description. Review the draft and publish it. Do not draft a release in the GitHub UI. That creates the tag and the workflow refuses to rebuild a published release.

## Code style

[.editorconfig](.editorconfig) records the whitespace rules: UTF-8, LF line endings, a final newline, no trailing whitespace, tabs for Go and Make recipes and two-space indentation for YAML and TOML. Markdown keeps meaningful trailing spaces. The license, the copied Go code's notice and the test fixtures remain verbatim. Most editors apply these settings automatically, while a few need a plugin.

# What this changes

<!-- What the change does and why. Link the issue it closes. -->

## Validation

<!-- Which of these you ran, and anything that failed. -->

- [ ] `make fmt-check`
- [ ] `make lint`
- [ ] `make test`
- [ ] `make fuzz`, for a parser or handler change
- [ ] `make interop`, for a protocol change
- [ ] `make gitleaks`
- [ ] `make govulncheck`, for a dependency change
- [ ] Checked against a real device, client or CA, for a protocol change

<!-- Name the peer and its version. -->

## Documentation and changelog

- [ ] User-facing behavior is documented in the Go doc comments and the README
- [ ] `CHANGELOG.md` carries an entry, or the change is not user facing
- [ ] A protocol change cites the RFC 8894 section and has a negative test

## Anything a reviewer should know

<!-- Trade-offs, follow-up work, or parts you are unsure about. -->

<!-- Never include private keys, challenge passwords or messages captured from a production
     system in a pull request. -->

# Testing

The library is tested at three levels. Each package has unit tests. Fuzz targets cover the parser
and the handler. The Interop workflow runs other SCEP implementations against the module.

## Unit tests

```bash
make test
```

Runs `go vet` and every test under the race detector.

* The `scep` tests build, parse, decrypt and answer every message type, check the algorithm
  choices of answers, the restriction to expected signers and the nonce and transaction ID checks,
  and parse captured messages from `testdata`.
* The `scepserver` tests drive the handler with `internal/testca`: every operation and method,
  the size limits, the refusals and their failInfo values, the CA outcomes, the refusal recorder
  and the log levels.
* The `scepclient` tests run the client against the handler and against test servers that
  reproduce server behavior outside RFC 8894, such as answers with a NUL byte, an empty body,
  HTTP 503, HTTP 202 and single DES.
* `Example` in `example_test.go` and the tests of `examples/quickstart` run the code the
  documentation shows.

## Fuzzing

```bash
make fuzz
make fuzz FUZZTIME=2m
```

Runs two fuzz targets for `FUZZTIME` each, 30 seconds by default:

| Target | Checks |
| --- | --- |
| `FuzzParsePKIMessage` | Parsing, decrypting and answering hostile messages returns errors instead of panicking |
| `FuzzPKIOperation` | The handler answers any POST body with a client error or a CertRep, never with a panic or HTTP 500 |

CI runs 30 seconds of each target on every push and pull request. Go writes a failing input under
the package's `testdata/fuzz` directory. Commit that input with the fix so it stays a regression
test.

## Interop tests

```bash
make interop
```

The interop tests have the `interop` build tag and run real SCEP peers against the module.
`make interop` runs the sscep and micromdm/scep tests and skips each one whose peer is missing.
`SCEP_INTEROP=required` turns a skip into a failure, as in CI. `INTEROP_RUN` selects the tests:

```bash
make interop INTEROP_RUN=TestSSCEP
```

| Test | Peer | Environment |
| --- | --- | --- |
| `TestSSCEP` | sscep against the handler | `SSCEP`, else `sscep` on the `PATH` |
| `TestMicroMDMClient` | The micromdm/scep client against the handler | `MICROMDM_SCEPCLIENT`, else `scepclient` on the `PATH` |
| `TestMicroMDMServer` | The client against a running micromdm/scep server | `SCEP_INTEROP_MICROMDM_URL`, `SCEP_INTEROP_MICROMDM_CHALLENGE` |
| `TestEJBCAServer` | The client against a running EJBCA | `SCEP_INTEROP_EJBCA_URL`, `SCEP_INTEROP_EJBCA_CA`, `SCEP_INTEROP_EJBCA_CHALLENGE` |

The [Interop workflow](https://github.com/misiektoja/go-pki-scep/blob/main/.github/workflows/interop.yml)
builds each peer, starts the servers and sets these variables.
[Tested implementations](../interoperability/tested-implementations.md) describes what each test
covers.

# Examples

Runnable programs that use go-pki-scep. They are part of the root module, so `go vet ./...` and
`go test ./...` build and test them with the library.

| Example | Shows | Run |
| --- | --- | --- |
| [quickstart](quickstart/) | A local SCEP server with a throwaway RSA CA that checks a challenge password. A client enrolls and renews against it | `go run ./examples/quickstart` |

[Getting started](https://misiektoja.github.io/go-pki-scep/getting-started/) walks through the
quickstart and enrolls against it with another SCEP client. The message layer example without HTTP
is `Example` in [example_test.go](../example_test.go), shown on
[pkg.go.dev](https://pkg.go.dev/github.com/misiektoja/go-pki-scep#example-package).

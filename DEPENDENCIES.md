# Dependencies

The module has one dependency outside the Go standard library. It derives from
[smallstep/scep](https://github.com/smallstep/scep) and carries one copy of Go code, as
[NOTICE](NOTICE) records.

| Dependency or copied code | Use | License |
| --- | --- | --- |
| [github.com/misiektoja/go-pkcs7](https://github.com/misiektoja/go-pkcs7) | The CMS SignedData and EnvelopedData messages that carry SCEP requests and answers | MIT |
| `x509util`, parts of Go `crypto/x509` | Building CSRs that carry the challenge password attribute | BSD-3-Clause |

go-pkcs7 has the same maintainer and no dependencies outside the standard library. The release
SBOM lists the module and its licenses.

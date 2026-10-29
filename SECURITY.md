# Security policy

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability.

Report it privately through [GitHub security advisories](https://github.com/misiektoja/go-scep/security/advisories/new), which keeps the report visible only to the maintainer until an advisory is published. If you cannot use that, email <misiektoja-github@rm-rf.ninja>.

Do not include private keys, passwords or messages captured from a production system in a report. Include the affected revision, the impact, the preconditions to reproduce it and a sanitized proof, such as a message made with a throwaway key, when you have one.

The maintainer will acknowledge the report and coordinate disclosure once a fix is available.

## Severity and fix targets

A report is rated by where the flaw is reachable and what it gives an attacker, not by its CVSS score alone. The tiers and targets are those of the products built on this library.

| Tier | Meaning | Before the fix | Fixed release |
| --- | --- | --- | --- |
| Emergency | Exploited in the wild. Also any flaw an unauthenticated sender can reach that forges a signature, recovers plaintext or key material, bypasses a trust check or gets a certificate the CA did not authorize | Same day: an advisory with a workaround where one exists | Within 3 days |
| Critical | The same impact behind a non-default option | Within 2 days | Within 7 days |
| High | Denial of service from a crafted message or request, such as a panic or unbounded memory or time | A documented workaround where one exists | Within 30 days |
| Moderate and low | Everything else | None | Next release |

The targets are what the maintainer works to, not a service commitment.

## Supported versions

Security fixes are made on the default branch and shipped in the next [GitHub release](https://github.com/misiektoja/go-scep/releases). Only the latest released version is supported. Earlier versions receive no backports.

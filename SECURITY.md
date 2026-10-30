# Security Policy

## Supported versions

Security fixes land on the latest released version of `immunogen`. Please
upgrade before reporting an issue against an older release.

| Version | Supported |
|---|---|
| latest `0.x` | ✅ |
| anything older | ❌ |

## Reporting a vulnerability

**Please do not open a public issue for a security problem in immunogen
itself.**

Report it privately through GitHub's private vulnerability reporting:
[**Report a vulnerability**](https://github.com/Mocinjay/immunogen/security/advisories/new).

Include as much of the following as you can:

- the immunogen version (`immunogen --version`) and Node.js version
- the command you ran and the input that triggers the problem (a minimal
  repo, ZIP, or URL — never include real secrets)
- what happened, and what you expected to happen

You should get an acknowledgement within a few days. Once a fix is ready it
is released and the advisory is published with credit to the reporter,
unless you ask to stay anonymous.

## Scope

In scope — problems in immunogen's own code, for example:

- immunogen executing, importing, or evaluating code from a scanned repo
- path traversal / Zip-Slip escapes during ingestion
- an SSRF-guard bypass in live-URL screening
- a full (unredacted) secret appearing in terminal, JSON, or SARIF output, or
  in a prompt sent to an LLM provider

Out of scope — findings immunogen reports *about the repo you scanned*.
Those are the tool working as intended; false positives and false negatives
are welcome as regular [bug reports](https://github.com/Mocinjay/immunogen/issues/new?template=bug_report.md).

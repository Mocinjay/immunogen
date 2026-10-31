# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.2.0] - 2026-10-31

### Security

- Live-URL screening pins every connection to the addresses that passed the
  SSRF check (the check runs inside the socket's own DNS lookup), closing
  the DNS-rebinding window between checking a host and connecting to it.

### Fixed

- SARIF fingerprints no longer include the line number, so GitHub
  code-scanning alerts keep their identity when unrelated edits move a
  finding. Existing alerts are re-keyed once on the first upload after
  upgrading.
- Scanning a mid-size repository no longer runs out of memory: files are
  parsed one at a time and their syntax trees freed, instead of every tree
  being held for the whole scan (10,000 files: crash at 2 GB heap before,
  ~400 MB now).
- TypeScript files with decorators (NestJS, Angular, TypeORM) or `<T>value`
  casts, and `.mts` / `.cts` files, are now parsed; they were silently
  skipped by every AST-based rule.
- Live-URL screening: the SSRF guard now resolves DNS, covers IPv6 / IPv4-
  mapped / CGNAT / reserved ranges, and re-checks every redirect hop
  (redirects are followed by hand, with a real hop limit). Exposed-file
  probes no longer follow redirects or read unbounded bodies, and an SPA
  catch-all page is no longer reported as an exposed `.env` / `.git` /
  `config.json`. Public Firebase / Maps keys in served bundles are no longer
  reported; Gemini keys are, as CRITICAL.
- LLM fix prompts: the Anthropic adapter used a retired model, so every
  call failed silently. It now defaults to `claude-haiku-5-5`; set
  `IMMUNOGEN_MODEL` to override (required for Ollama and other
  OpenAI-compatible servers). Calls run at most four at a time, and failures
  or misconfiguration are reported instead of swallowed.
- ZIP inputs are capped (100,000 entries, 1 GB uncompressed) before
  anything is written; files over the per-file size cap are no longer read
  into memory first; git clones never prompt for credentials and time out
  after five minutes.
- Terminal output strips control characters from file names, matched text
  and LLM output, so a crafted repository cannot inject terminal escape
  sequences. All formats end with a newline; an unknown `--format` is an
  error instead of a silent fallback.
- npm range specifiers are reduced to a concrete version before the OSV
  lookup; `npm:` aliases resolve to the real package; URL / GitHub / tag
  specifiers are skipped.
- One `DEP-OFFLINE` notice per scan instead of one per manifest; exact
  duplicate findings are dropped; output order no longer depends on the
  host locale.
- SARIF: correct project URL, `driver.version`, percent-encoded artifact
  URIs anchored to `%SRCROOT%`.
- The Docker image includes `git`, so it can scan repository URLs.

### Changed

- `ScanResult` gains `diagnostics`, rendered by every reporter (terminal
  warnings block, JSON field, SARIF tool-execution notifications).
- Secrets and client-exposure rules also scan `.vue`, `.svelte`, `.astro`,
  `.html`, and (secrets) more config and source formats.
- Test, fixture, mock, example and story code is recognized by one shared
  rule set across all detectors (`.spec.` files and `tests/` / `testdata/`
  directories were previously honored by only some of them).
- Library API (breaking): `ScanResult.diagnostics` is a new required field,
  and `ProviderAdapter.generate()` now rejects on failure instead of
  resolving to an empty string.
- `undici` is now a runtime dependency (used for the pinned live-URL
  connections).
- Code comments no longer reference internal planning documents.

## [0.1.0] - 2026-10-31

First public release.

### Added

- Static repo scan: 23 detectors across 12 categories for JavaScript /
  TypeScript, Python, and Go — secrets, client-bundle exposure, auth & RLS,
  abuse / rate limiting, payment safety, dependencies, injection / XSS /
  SSRF / open redirects, CORS & headers, storage, legal, config / debug, and
  the AI layer (prompt injection, exfiltration, MCP tool poisoning and least
  privilege).
- Dependency checks for every resolved package, direct and transitive, read
  from npm / pnpm / yarn / bun / Poetry / uv / Pipenv lockfiles or manifests,
  rated by each advisory's real severity, with a bundled offline fallback
  list and an `--offline` flag that never touches the network.
- Live-URL screening behind a required `--authorize` consent gate, with an
  SSRF guard (`--allow-private` escape hatch for local dev): security
  headers, CORS, exposed files, secrets in served bundles, cookie flags.
- Scanning a git repo URL (GitHub, GitLab, Bitbucket, Codeberg, any `.git`).
- 0–100 Ship Score with band, verdict, and an A–F health grade; any
  CRITICAL finding is an automatic `F`.
- Terminal, JSON, and SARIF reporters; exit code `1` on a blocked verdict,
  `2` when the scan cannot run.
- Suppressions via inline `immunogen-ignore` comments and
  `.immunogenignore`, with `--no-ignore` to audit repos you do not control.
- Optional LLM fix prompts (Anthropic or OpenAI-compatible), off by default,
  with redaction before anything is sent.
- Library API (`import { scan } from "immunogen"`, ESM and CJS), Docker
  image, and a Claude Code skill.
- `immunogen` with no path argument scans the current directory;
  `-v, --version` prints the installed version.

### Fixed

- The installed CLI (`npx immunogen`, global installs) ran through npm's bin
  symlink and silently exited 0 without scanning.
- The offline advisory list no longer flags patched backport releases on
  older lines (e.g. `semver@5.7.2`, `ws@7.5.10`, `minimist@0.2.4`).

[Unreleased]: https://github.com/Mocinjay/immunogen/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/Mocinjay/immunogen/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Mocinjay/immunogen/releases/tag/v0.1.0

# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-10-30

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

[Unreleased]: https://github.com/Mocinjay/immunogen/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Mocinjay/immunogen/releases/tag/v0.1.0

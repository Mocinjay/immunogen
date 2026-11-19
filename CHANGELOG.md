# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
follows [Semantic Versioning](https://semver.org/).

## [0.3.1] - 2026-11-19

Hardening release: zero known vulnerabilities in the dependency tree, zero
lint warnings, CodeQL code scanning on immunogen's own source, and npm as
the main way to install.

### Security

- File reads during a scan are race-free: each file is opened once
  (refusing a path that has become a symlink), checked and read through the
  same handle, and the read stops at the size cap even if the file grows.
  The `.git` pointer lookup is a single operation too. (CodeQL
  js/file-system-race.)
- Git browse-URL parsing and live-URL probe paths no longer use a regex that
  is quadratic on long runs of `/` (CodeQL js/polynomial-redos).
- A private npm registry is recognized by exact hostname, not by a substring
  of its URL (CodeQL js/incomplete-url-substring-sanitization).
- The GitHub Action passes step outputs through environment variables, never
  into a script (CodeQL actions/code-injection); every third-party action in
  the Action and the workflows is pinned to a commit SHA, and checkout no
  longer leaves the token in `.git/config`.
- `minimatch` (moderate advisory, via the TypeScript ESLint toolchain) pinned
  to 11.0.2: `pnpm audit` reports no known vulnerabilities.
- Test files no longer contain literal bidirectional-override characters
  (they are written as `\u202E` escapes), and lint is warning-free.
- Repository: Dependabot alerts and security updates, and CodeQL default
  setup, are enabled.

### Added

- Published to npm: `npx immunogen` or `npm install -g immunogen`. Releases
  publish through npm trusted publishing (OIDC, with provenance) — no npm
  token is stored anywhere.
- `immunogen --install-skill` links the Claude Code skill that now ships in
  the npm package into `~/.claude/skills/immunogen`, so `/immunogen` always
  runs the installed version. It never overwrites an existing folder.

## [0.3.0] - 2026-11-19

A second production audit (see `docs/AUDIT.md`), driven by scanning real
AI-built projects: on one of them the 0.2.0 report was 146 findings and
120 CRITICALs; on 0.3.0 it is 10 findings, none of them false alarms from
duplicate checkouts or bulk-protected tables.

### Security

- ZIP input is extracted by a new symlink-safe extractor (built on yauzl);
  `extract-zip` is gone. It allowed writes outside the extraction folder
  through symlink entries (GHSA-7pqw-9j4j-h8q3, no fixed release). Symlink and
  special entries are skipped and reported (`ZIP_ENTRIES_SKIPPED`).
- `simple-git` 3.36.0 → 4.0.2, past a CRITICAL unsafe-operation-guard bypass
  (GHSA-x6jw-m9v5-85vh). Patched dev-tool transitives are pinned with
  `pnpm.overrides`, and Dependabot now offers major updates for packages
  that handle untrusted input.
- Both were found by running immunogen on itself, which CI now does on
  every push.

### Added

- **Database connection strings** with a password (SEC-10): Postgres /
  Supabase / Neon, MySQL, MongoDB Atlas, Redis, AMQP, SQL Server. CRITICAL
  on managed cloud hosts; local and docker-compose hosts, template
  variables and default passwords are skipped; the password is always
  masked (and now also redacted before any LLM call).
- **Agent auto-run and permissions** (AILAYER-05 / AILAYER-06): Claude Code
  hooks, status-line and credential-helper commands, Cursor hooks, VS Code
  folder-open tasks and MCP launch commands that download-and-run code or
  send credentials out; `Bash(*)`, `bypassPermissions` and
  `enableAllProjectMcpServers` in committed agent settings.
- AI-layer coverage for `.vscode/mcp.json`, `.windsurfrules`, `GEMINI.md`,
  `.clinerules`, `.claude/agents` and `commands`, `.github/instructions` and
  `prompts`, `.kiro/steering`, Roo and Amazon Q configs.
- **Hallucinated dependencies** (DEP-02): direct dependencies that do not
  exist on the public npm registry or PyPI. Private registries configured in
  the repo, workspace packages and non-registry specifiers are skipped.
- **Backend data exposure** in live-URL mode (WEB-DATA-01/02/03): whether
  the Supabase tables, Firebase Realtime Database or Firestore collections a
  site's code uses can be read with the public key it ships — row counts and
  names only, read-only. `--no-data-probes` turns it off.
- `--format prompt`: a deterministic, numbered fix-it brief to paste into a
  coding agent.
- `--baseline <file>`: findings already in an earlier JSON report are not
  scored, so existing repos can gate CI on new findings only (SARIF
  `baselineState`).
- `--min-severity <level>`.
- A GitHub Action: `uses: Mocinjay/immunogen@v0.3.0`.
- Suppressed findings are reported instead of dropped: `ScanResult.suppressed`,
  a `FINDINGS_SUPPRESSED` diagnostic, and SARIF `suppressions` (shown as
  dismissed in code scanning). Files excluded by `.immunogenignore` are
  counted (`PATHS_IGNORED`).

### Fixed

- Agent worktrees (`.claude/worktrees/`, or any nested git worktree) are no
  longer scanned as part of the repo; they duplicated every finding.
  Python, deploy-tool and framework caches are excluded, and
  `.git/info/exclude` is honored.
- Documentation placeholders (`sk_live_YOUR_KEY_HERE`, AWS's
  `AKIAIOSFODNN7EXAMPLE`, Slack's `XXXX` webhook) are no longer reported as
  live keys.
- A committed `.env` file is CRITICAL only when it holds a secret value
  (variable names are listed, values never echoed); one with only public or
  default values is INFO, as Next.js and Vite document committing those.
- A gitignored `.env` inside a ZIP is now scanned — the archive shipped it.
- Supabase tables protected in bulk (a loop that enables RLS on every table,
  an RLS event trigger, or revoking every privilege from `anon`) are no
  longer reported one CRITICAL per table. Supabase projects are recognized
  from `supabase/functions/`, `supabase/migrations/` and Deno imports.
- Privacy / terms pages named the way Lovable and Bolt name them
  (`PrivacyPolicy.tsx`, `TermsOfService.tsx`) and router links to them count
  as present.
- GitHub / GitLab / Bitbucket `/tree/` and `/blob/` links are cloned (at that
  ref, scanning that folder) instead of being treated as live websites.
- Dependency checks retry OSV.dev on transient failures, give each advisory
  lookup its own timeout, say when OSV gave no severity, name the version to
  upgrade to, and rate dev-only packages (npm and pnpm lockfiles) one level
  lower.

### Changed

- LOW-confidence findings cost half their severity's points. Any CRITICAL is
  still an automatic F.
- The terminal report groups the same problem in several places into one
  entry with every location, and counts Medium / Low in the header.
- Library API: `ScanResult.sarif` (reserved, never used) is removed;
  `ScanResult` gains optional `suppressed` and `baselined`; `ScanOptions`
  gains `minSeverity`, `baseline` and `dataProbes`; `format` accepts
  `"prompt"`.
- Live-URL `scanIncomplete` follows warn-level diagnostics only.

### Earlier, unreleased

- README: the one-off `npx` and CI examples pin the release URL. npx caches
  whatever a URL first downloaded, so the unpinned `latest` URL kept
  serving the first version a user ran.

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

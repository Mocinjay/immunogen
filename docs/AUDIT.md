# immunogen — production-readiness audit (2026-10-31)

Scope: the whole repository at `6e5d5fc` — ingest (`src/core/ingest`), parsing
(`src/core/parse`), the detector registry and all 23 static detectors, scoring,
the LLM enrichment layer, the live-URL pipeline (`src/web`), the three
reporters, the CLI, the Claude Code skill, Docker, and CI/release workflows.

Baseline before any change: `typecheck`, `lint` (0 errors, 3 warnings) and
`test` (62 files / 928 tests) all green. Green tests did not mean a working
product — several of the findings below were reproduced empirically, not
inferred.

Severity scale: **Critical** = the product fails or is unsafe on ordinary
input; **High** = a core promise (coverage, safety, correctness) is broken for
a large class of users; **Medium** = wrong/fragile behavior with a narrower
blast radius or a maintainability hazard that is already causing drift;
**Low** = polish, hygiene, consistency.

---

## Critical

### C1. Any mid-size repo runs the scanner out of memory
- **What:** `buildAstCache` parses every JS/TS file up front and keeps every
  Babel AST alive in `ScanContext.astCache` for the whole scan.
- **Evidence:** a synthetic repo of 10,000 small `.ts` files (13.9 MB of
  source) produced **1.55 GB of AST heap** (~110× the source size); the full
  `scan()` crashed with `FATAL ERROR: JavaScript heap out of memory`. The
  walker's default total cap is 50 MB of source, i.e. ~5.5 GB of AST — the
  safety cap guarantees the crash instead of preventing it.
- **Root cause:** "parse once, share many" was implemented as "parse
  everything, hold everything". No detector needs another file's AST —
  cross-file detectors read `fileSet` text.
- **Fix:** parse lazily per file inside the registry, run every detector for
  that file, then drop the AST; process files with bounded concurrency.
  `astCache` is removed from `ScanContext`.
- **Blast radius:** ingest, registry, `ScanContext` type, ingest tests.

### C2. Live-URL screening's SSRF guard is bypassable three ways
- **What:** `resolveUrlTarget` only pattern-matches the *hostname string*.
  1. `fetch(..., { redirect: "follow" })` follows redirects to any host, so
     `https://attacker.example/` → `302 http://169.254.169.254/latest/meta-data/`
     is fetched (the textbook SSRF bypass). The exposed-file probes follow
     redirects too.
  2. No DNS check: any public name resolving to a private address
     (`127.0.0.1.nip.io`, an internal CNAME) passes.
  3. IPv6 coverage is `::1` only — IPv4-mapped (`[::ffff:7f00:1]`), ULA
     (`fd00::/8`, incl. AWS IMDS `fd00:ec2::254`), link-local `fe80::/10` and
     `::` pass; IPv4 misses `0.0.0.0/8`, CGNAT `100.64.0.0/10` (Alibaba
     metadata), `192.0.0.0/24`, `198.18.0.0/15`, multicast/reserved;
     `*.localhost`, `metadata.google.internal` pass.
- **Also:** `maxRedirects` is documented as a count but only toggles
  follow/manual.
- **Fix:** resolve every hop's host with `dns.lookup(all)` and check each
  address against a `net.BlockList` covering all special-purpose ranges
  (v4, v6, v4-mapped); follow redirects manually with per-hop validation and
  a real hop limit; probes never follow redirects.
- **Residual:** DNS-rebinding between check and connect is not closed
  (would need a pinned-IP dispatcher). Documented.

## High

### H1. Every decorator-using or `<T>x`-casting `.ts` file is invisible to AST detectors
- **Evidence:** `@Controller() class A {}` → `This experimental syntax requires
  enabling ... "decorators-legacy"`; `const a = <string>foo;` → `Unterminated
  JSX contents`. Both throw even with `errorRecovery`.
- **Impact:** NestJS, Angular, TypeORM, MikroORM, class-validator codebases —
  every route-auth, injection, XSS and server-route detector silently skips
  those files. `.mts`/`.cts` are never parsed at all.
- **Root cause:** one plugin set (`typescript` + `jsx`) for every extension.
- **Fix:** per-extension plugins: `.ts/.mts/.cts` → `typescript` +
  `decorators-legacy` (no JSX), `.tsx` → + `jsx`, JS → `jsx` +
  `decorators-legacy`; `allowReturnOutsideFunction` for CJS.

### H2. Diagnostics are collected and then thrown away
- **What:** `PARSE_WARN`, `SCAN_TRUNCATED` etc. land in `ctx.diagnostics`, but
  `ScanResult` has no diagnostics field. The terminal reporter does not show
  `scanIncomplete` either, so a truncated scan prints "No findings. Ready to
  ship" with no warning.
- **Root cause:** the module docs promise "a degraded scan is visible rather
  than silent", but the contract stops at `ScanContext`.
- **Fix:** `ScanResult.diagnostics`; terminal prints an incomplete-scan
  banner and a diagnostics summary; JSON carries them; SARIF emits
  `invocations[].toolExecutionNotifications`; the skill shows them.

### H3. LLM enrichment is dead on arrival
- **What:** `AnthropicAdapter` hard-codes `claude-3-5-haiku-latest`, a
  retired model; every call fails and is swallowed into `""`. The OpenAI
  adapter hard-codes `gpt-4o-mini`, so the advertised "works with Ollama /
  vLLM via `OPENAI_BASE_URL`" path 404s on every call. Misconfiguration
  (`IMMUNOGEN_PROVIDER` set, key missing) and total failure are both silent.
  Up to 20 calls fire at once — an easy 429 storm.
- **Fix:** current default model, `IMMUNOGEN_MODEL` override, bounded
  concurrency, adapters surface errors and the enricher turns them into
  diagnostics.

### H4. Ingest resource exhaustion on hostile input
- **ZIP bomb:** `extract-zip` runs with no entry-count or uncompressed-size
  cap; a small archive can fill the disk before the walker's caps ever run.
- **Oversized files are read whole before the size check** (`readFile` then
  `buffer.length > cap`) — a 4 GB file in a repo is loaded into memory to be
  discarded. Skipped files leave no trace.
- **Git clone:** no timeout and no `GIT_TERMINAL_PROMPT=0`, so a private or
  mistyped HTTPS URL hangs forever on a credential prompt (fatal in CI); an
  input that begins with `-` and ends in `.git` is passed to `git clone` as
  an option.
- **Fix:** entry/byte caps enforced in `onEntry`; stat before read plus a
  `FILES_SKIPPED` diagnostic; clone with prompt disabled, a block timeout,
  and option-shaped inputs rejected.

### H5. URL mode reports high-severity false positives on ordinary sites
- **Redirect FP:** `/.env` → `302 /` → `200 index.html` is reported as "A .env
  file is publicly served" (HIGH). Same for `/config.json`, `/.git/*`.
- **SPA catch-all FP:** any SPA that serves `index.html` for every path gets
  HIGH `/.env`, `/.git/HEAD`, `/config.json` findings.
- **Unbounded probe reads:** probes use `response.text()` with no byte cap.
- **Google key FP:** `bundle-secrets` reuses every provider pattern including
  `AIza…`, so every Firebase / Maps site gets a HIGH "live-looking provider
  key" for a key that is public by design. Messages say "(SEC-09 shape)"
  instead of naming the provider.
- **Fix:** probes do not follow redirects and read bounded bodies; an HTML
  body (or one identical to the main document) on a non-HTML path is not an
  exposure; Google keys are reported only with Gemini/GenAI context, matching
  the static detector.

## Medium

### M1. Registry does avoidable O(detectors × files × globs) work
`matchesGlob` compiles a fresh `RegExp` for every (detector, file, glob)
triple — hundreds of thousands of compilations on a large repo. `isSuppressed`
re-splits the whole file for every finding. **Fix:** compile once per
detector; cache split lines per file.

### M2. `requiresStack` is dead, and wrong where it exists
Declared on 8 detectors, enforced nowhere ("closed by 05-08" never happened).
The Stripe detector declares `["stripe"]`, which is not even a value
`frameworks` can hold — enforcing the metadata as written would have silently
disabled Stripe checks. **Fix:** enforce it in the registry, add `stripe` to
`frameworks`, drop it from the Firebase rules detector (whose real gate is
deliberately broader).

### M3. No finding dedupe; DEP-OFFLINE repeated per manifest; locale-dependent sort
Identical (rule, file, line, message) findings each cost score points. Offline
mode emits one `DEP-OFFLINE` per manifest (10 in a 10-package monorepo). The
final sort uses `localeCompare`, so SARIF/JSON ordering depends on the
machine's ICU locale. **Fix:** dedupe, collapse the sentinel, ordinal compare.

### M4. Test/fixture allowlist copy-pasted 20 times — and already drifted
`FP_ALLOWLIST_SEGMENTS` + `isAllowlistedPath` are duplicated in 20 detector
files. Three variants exist: most skip `.test.`/`.stories.` only, one adds
`.spec.`, three add `tests`/`testdata`. `foo.spec.ts` is suppressed by one
detector and scanned by 19. **Fix:** one shared `isTestOrFixturePath`.

### M5. Coverage gaps for the stacks the tool targets
The secrets and client-exposure detectors never look at `.vue`, `.svelte`,
`.astro` or `.html` — where Vue/Svelte/Astro apps reference
`import.meta.env.VITE_*` and inline keys. **Fix:** extend both globs (both
detectors are text-based, so no parser needed).

### M6. Terminal escape injection from scanned content
File names, matched snippets and LLM output are printed raw. A crafted
filename or a hostile model response can emit ANSI/OSC sequences (clear
screen, rewrite earlier lines, OSC-8 links) into the user's terminal — the
one thing a scanner of untrusted repos must not do. **Fix:** strip C0/C1
control characters in the terminal reporter.

### M7. npm range specifiers are sent to OSV verbatim-ish
Without a lockfile, `cleanVersionSpecifier` only strips one leading operator:
`">=1.0.0 <2.0.0"` → `"1.0.0 <2.0.0"`, `"1.x || 2.x"`, `npm:alias@1.2.3`,
URLs and GitHub shorthands are all sent as versions. **Fix:** extract the
first concrete semver, resolve `npm:` aliases, skip anything else.

### M8. SARIF identity and validity
`informationUri` points at a non-existent `immunogen-dev/immunogen` repo; no
`driver.version`; `artifactLocation.uri` is not URI-encoded (spaces, `#`, `%`
in paths produce invalid URIs). **Fix:** correct URI, version, encoding.

### M9. Docker image cannot scan git URLs
The Alpine runtime image has no `git`, so `docker run immunogen
https://github.com/...` fails. **Fix:** install git in the runtime stage.

## Low

- **L1.** CLI output has no trailing newline (the shell prompt glues onto the
  last line); `--format jsn` silently falls back to terminal output instead of
  erroring.
- **L2.** Version string duplicated in two hard-coded User-Agents
  (`immunogen/0.1`) that will drift from `package.json`.
- **L3.** `isSuppressed` with a `line` of 0 would read the *last* line via
  `Array.at(-1)`.
- **L4.** Module-level OSV caches grow without bound in a long-lived host
  process (library/MCP use). Acceptable for the CLI; noted.
- **L5.** Documentation comments are heavily process-oriented ("Plan 05-08",
  "Pass 2", threat IDs) and in places now false (e.g. "requiresStack ...
  closed by 05-08"). Fixed where touched; a wider pass is recommended.

---

## Execution plan (order = dependency order)

1. **C1 + H1** — lazy per-file parsing with per-extension plugins (foundation
   for everything AST-based; removes the OOM).
2. **H2** — diagnostics in `ScanResult` and every reporter (the channel every
   later fix reports through).
3. **H4** — ingest hardening (ZIP caps, stat-before-read, git clone).
4. **C2 + H5** — SSRF guard rewrite, manual redirects, probe correctness,
   bundle-secrets Google gating.
5. **H3** — LLM layer.
6. **M1–M3** — registry rework.
7. **M4–M5** — shared allowlist, glob coverage.
8. **M6–M9, L1–L3** — reporter/CLI/SARIF/Docker/OSV polish.
9. Full verification: typecheck, lint, unit + golden suites, build, dist
   smoke tests, and the 10k-file benchmark re-run.

The results of each step are recorded in the "Outcome" section below.

---

## Outcome

Every item above was fixed in this pass. Verification after the changes:
`typecheck` clean, `lint` 0 errors (the same 3 pre-existing warnings, all in
test fixtures / the skill script), `test` **64 files / 1040 tests** (was 62 /
928; the golden snapshot suite is unchanged), `build` and the dist smoke
tests (`test:dist`: ESM + CJS import, skill parity, symlinked CLI) pass.

| # | Result | Where |
|---|---|---|
| C1 | 10k-file repo: OOM crash at 2 GB → completes in ~15 s at ~400 MB RSS | `src/detectors/registry.ts`, `src/core/parse/ast-cache.ts`, `src/core/ingest/index.ts` |
| C2 | DNS-resolved `BlockList` guard on every request and redirect hop; manual redirects with a real hop limit | `src/web/host-guard.ts`, `src/web/dns-resolve.ts`, `src/web/fetch-target.ts`, `src/web/url-resolver.ts` |
| H1 | Per-extension parser plugins (`decorators-legacy`, no JSX in `.ts`, `.mts`/`.cts`) | `src/core/parse/ast-cache.ts` |
| H2 | `ScanResult.diagnostics`; terminal banner + warnings block, JSON field, SARIF notifications, skill output | `src/core/types.ts`, `src/index.ts`, `src/reporters/*`, `.claude/skills/immunogen/scan.mjs` |
| H3 | `claude-haiku-5-5` default, `IMMUNOGEN_MODEL`, 4-way concurrency, `LLM_CONFIG` / `LLM_FAILED` diagnostics | `src/llm/*` |
| H4 | ZIP entry/byte caps, stat-before-read + `FILES_SKIPPED`, prompt-free time-limited clone, option-shaped input refused | `src/core/ingest/input-resolver.ts`, `src/core/ingest/file-walker.ts` |
| H5 | Non-redirecting byte-capped probes, HTML catch-all detection, JSON check, Google-key gating | `src/web/scan-url.ts`, `src/web/detectors/exposed-files.ts`, `src/web/detectors/bundle-secrets.ts` |
| M1–M3 | Compiled-glob cache, enforced `requiresStack` (+`stripe` framework hint), `usesAst`, dedupe, single DEP-OFFLINE, ordinal sort, line-split cache | `src/detectors/registry.ts`, `src/core/ingest/stack-detector.ts` |
| M4 | One shared allowlist replaces 20 copies | `src/detectors/shared/test-paths.ts` |
| M5 | `.vue` / `.svelte` / `.astro` / `.html` and more config formats scanned | secrets + client-exposure detector globs |
| M6 | Control-character stripping for all untrusted terminal text | `src/reporters/terminal.ts` |
| M7 | Lower-bound version extraction, `npm:` aliases, non-registry specifiers skipped (linear parsing, no backtracking regex) | `src/detectors/deps/osv-detector.ts` |
| M8 | Correct `informationUri`, `driver.version`, encoded `%SRCROOT%` URIs | `src/reporters/sarif.ts` |
| M9 | `git` in the runtime image | `Dockerfile` |
| L1–L3 | Trailing newline in every format; `--format` validated; single version source (`src/version.ts`, injected by tsup/vitest); `line < 1` guarded | `bin/immunogen.ts`, `src/version.ts`, build configs |

### Behavior changes worth knowing

- `ScanResult` has a new required `diagnostics` field. `ScanContext.astCache`
  is gone (internal type).
- `ProviderAdapter.generate()` now rejects on failure (the enricher reports
  it) and adapters expose `model`.
- `.spec.` files and `tests/` / `testdata/` directories are now treated as
  test code by every detector.
- SARIF `partialFingerprints.primaryLocationLineHash` is still derived from
  rule + file + line. It churns when lines shift; moving it to a
  content-stable fingerprint is the main remaining SARIF improvement.

### Not done (recommended next)

- Pin URL-mode connections to the checked IP (custom undici dispatcher) to
  close the DNS-rebinding window documented in `host-guard.ts`.
- Content-stable SARIF fingerprints (see above).
- Trim the process-history comments (plan IDs, "Pass 2", threat IDs) across
  the codebase; several still describe superseded designs.

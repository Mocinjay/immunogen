<div align="center">

<img src="https://raw.githubusercontent.com/Mocinjay/immunogen/main/assets/logo.svg" alt="immunogen" width="460" />

**Your AI agent shipped the code. immunogen makes sure it didn't ship an infection.**

[![npm version](https://img.shields.io/npm/v/immunogen.svg)](https://www.npmjs.com/package/immunogen)
[![CI](https://github.com/Mocinjay/immunogen/actions/workflows/ci.yml/badge.svg)](https://github.com/Mocinjay/immunogen/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![Node >=22](https://img.shields.io/badge/node-%3E%3D22-brightgreen.svg)](https://nodejs.org)

<img src="https://raw.githubusercontent.com/Mocinjay/immunogen/main/assets/hero.jpg" alt="immunogen — a clean bill of health for AI-built apps" width="100%" />

<samp>A · Immune&nbsp;&nbsp;·&nbsp;&nbsp;B · Healthy&nbsp;&nbsp;·&nbsp;&nbsp;C · Symptomatic&nbsp;&nbsp;·&nbsp;&nbsp;D · Infected&nbsp;&nbsp;·&nbsp;&nbsp;F · Critical</samp>

</div>

A clean bill of health for AI-built apps, before you ship. immunogen is a static, offline-first screen for repos built with Cursor, Claude Code, Lovable, Bolt, v0, or Replit — it never executes your code, reads it once, and returns a 0–100 **Ship Score** across 11 categories, including the AI layer itself (skills, MCP servers, agent/system prompts) — a surface most scanners skip entirely.

## Quickstart

```sh
npx immunogen
```

Run it in your project directory — it scans the current folder, no API key required, and prints a terminal report with a Ship Score. Point it elsewhere with `npx immunogen ./path/to/app`. The only network call it ever makes is a dependency-vulnerability lookup against OSV.dev (package names + versions only); add `--offline` to skip that too.

## Sample output

Run against a deliberately contaminated fixture app:

```
GRADE: F — Critical
Ship Score: 0/100 — High risk
Verdict: blocked
Critical: 17  High: 34

  CRITICAL SEC-05 .env:1
    Committed environment file (.env) found in the scanned tree. [confidence: HIGH]

  CRITICAL SEC-01 .env:2
    Hardcoded Stripe live secret key (sk_live_) found in source. [confidence: HIGH]
    matched: sk_l****

  CRITICAL SEC-04 .env:3
    SUPABASE_SERVICE_ROLE_KEY is assigned a hardcoded value in source. [confidence: HIGH]
    matched: SUPA****

  CRITICAL PAY-01 app/api/stripe/webhook/route.ts:3
    Stripe webhook handler does not verify the signature (missing constructEvent). [confidence: HIGH]

  CRITICAL AUTH-01 app/api/stripe/webhook/route.ts:8
    Exported Next.js route handler POST has no authentication or authorization check. [confidence: MEDIUM]
    matched: POST

  CRITICAL AUTH-01 app/api/users/route.ts:5
    Exported Next.js route handler GET has no authentication or authorization check. [confidence: MEDIUM]
    matched: GET

  CRITICAL AUTH-01 app/debug/route.ts:5
    Exported Next.js route handler GET has no authentication or authorization check. [confidence: MEDIUM]
    matched: GET
```

🔴 **Contaminated — quarantine before shipping.** Every hit above is a detected contaminant with a `ruleId` and exact `file:line` — secrets are redacted, never printed in full.

## Health grade legend

The `GRADE:` line is a headline A–F rating layered on top of the 0–100 Ship
Score — the score, band, and verdict are still reported in full underneath
it, unchanged.

| Grade | Status | Meaning |
|---|---|---|
| **A** | Immune | Score 90–100 — clean bill of health, ready to ship |
| **B** | Healthy | Score 75–89 — minor issues, low risk |
| **C** | Symptomatic | Score 55–74 — moderate risk, worth fixing before launch |
| **D** | Infected | Score 35–54 — high risk, address before shipping |
| **F** | Critical | Score 0–34, **or any single CRITICAL finding** — automatic fail regardless of the numeric score |

Any CRITICAL finding is an automatic `F` — a single leaked production secret
or unauthenticated payment route floors the grade even if every other
category is spotless, mirroring the same CRITICAL hard cap already applied
to the numeric Ship Score.

## Why immunogen

immunogen isn't the only scanner for AI-built apps — but it's the only one that's **deterministic, free, and offline, covers a repo *and* a live URL *and* the AI layer**, and emits SARIF for a CI gate. The checklist-style tools lean on your AI assistant to do the inspecting (so results aren't reproducible), and the hosted scanner is a paid service that only probes a deployed URL.

| | **immunogen** | [vibe-check.cloud][vc] | [benavlabs/vibe-check][bv] | [Vibe App Scanner][vas] |
|---|:---:|:---:|:---:|:---:|
| Free / open source | ✅ MIT | ✅ | ✅ MIT | ❌ paid |
| Deterministic engine — no LLM, reproducible | ✅ | ❌ AI-driven | ❌ AI-driven | ~ hosted |
| Static repo scan (never executes your code) | ✅ | ✅ | ✅ | ❌ dynamic |
| Live URL / deployed-app scan | ✅ | ❌ | ❌ | ✅ |
| Scans the **AI layer** (skills / MCP / agent prompts) | ✅ deep | ~ partial | ❌ | ❌ |
| SARIF output for a CI gate | ✅ | ❌ | ❌ | ❌ |

<sub>✅ yes · ~ partial · ❌ no / not documented. Compared against each tool's public docs & README as of July 2026 — something wrong? Open a PR.</sub>

[vc]: https://vibe-check.cloud/
[bv]: https://github.com/benavlabs/vibe-check
[vas]: https://vibeappscanner.com/

## What it screens for

11 categories and 17 detectors on a repo scan — plus a 12th category of 5 web-probe detectors when you screen a live URL — the launch-blocking problems coding agents quietly ship.

| Category | What it catches |
|---|---|
| Secrets | Hardcoded provider keys (Stripe, AWS, OpenAI incl. `sk-proj-`, Anthropic, Supabase `service_role`/`sb_secret_`), committed `.env` files, high-entropy tokens (prose, URLs, hashes, and lockfiles are ignored) |
| Client-bundle exposure | Secret-named env vars leaking into the browser via `NEXT_PUBLIC_`/`VITE_` prefixes |
| Auth & RLS | Unauthenticated route handlers, open Firebase rules, missing Supabase row-level security |
| Payment safety | Stripe webhook handlers that skip signature verification |
| Dependencies (OSV) | Known CVEs in the direct dependencies of every `package.json` (root and nested apps like `app/` or `apps/web/`) via the OSV.dev batch API, with offline fallback |
| Injection / XSS | Unsanitized `dangerouslySetInnerHTML` |
| CORS & headers | Wildcard CORS with credentials, missing Content-Security-Policy |
| Storage | Public Firebase/Firestore/Storage rules, unpoliced Supabase buckets |
| Legal | Missing privacy-policy / terms surface when the app collects user data |
| Config / debug | Full `process.env` dumps to logs or debug endpoints |
| ⭐ AI layer | Prompt-injection strings, data-exfiltration patterns, and MCP tool-poisoning/least-privilege gaps in skills, rules, and agent prompts — a layer most scanners skip |

## Architecture

```
repo → ingest (walk + AST cache) → detectors (17, 11 categories) → Ship Score → reporters (terminal · json · sarif)
```

## CLI usage

```sh
immunogen [path] [--format terminal|json|sarif] [--offline] [--no-llm] [--authorize] [--allow-private]
```

- `[path]` — path to the repository to scan (default: the current directory), or a live `https://`/`http://` URL to screen.
- `--format terminal|json|sarif` — output format (default `terminal`). `json` is a stable machine-readable `ScanResult`; `sarif` is for GitHub code scanning / other SARIF-aware tooling.
- `--offline` — never touch the network: skip the OSV.dev lookup and check dependencies against the bundled offline advisory list only (the report notes the dependency check is incomplete).
- `--no-llm` — disable LLM fix-prompt enrichment. This is already the default; the flag exists for explicitness in scripts/CI.
- `--authorize` — required consent gate to screen a live URL target (see [Screen a live URL](#screen-a-live-url)). Has no effect when `<path>` is a local repo.
- `--allow-private` — escape hatch letting live-URL screening target a loopback/private/link-local host (local dev/test only).
- **Exit code:** `1` when the verdict is `blocked` (contaminated), `0` when `pass` (cleared), `2` when the scan could not run at all (bad path, missing `--authorize`, refused private host, ...) — drop it straight into a CI gate.

### Library usage

```js
import { scan } from "immunogen";

const result = await scan("./my-app");
console.log(result.score, result.findings);
```

`scan(path, options?)` returns a `ScanResult`: `{ target, scannedAt, stackHints, findings, score, llmEnriched, scanIncomplete }`. `score` is a `ShipScore` (`{ score, grade, gradeLabel, band, verdict, criticalCount, highCount }`); `findings` is a severity-sorted `Finding[]` with `file`/`line`/`ruleId`/`category`/`confidence`.

### Optional LLM fix prompts

By default, immunogen never calls an LLM. To enable Claude- or OpenAI-generated copy-paste fix prompts for HIGH/CRITICAL findings, set:

| Env var | Purpose |
|---|---|
| `IMMUNOGEN_PROVIDER` | `anthropic` or `openai` — selects the adapter |
| `ANTHROPIC_API_KEY` | Required when `IMMUNOGEN_PROVIDER=anthropic` |
| `OPENAI_API_KEY` | Required when `IMMUNOGEN_PROVIDER=openai` |
| `OPENAI_BASE_URL` | Optional override for OpenAI-compatible endpoints (e.g. a local Ollama server) |

If neither an env-configured provider nor the matching key is present, immunogen silently stays offline (no network call, no error). Every finding snippet is redacted before it is sent to any provider — no full source, no matched secret text ever leaves your machine unredacted.

## Screen a live URL

```sh
immunogen https://myapp.com --authorize
```

immunogen can also screen a deployed website directly, not just a local repo. This is a real, bounded probe against the target's own infrastructure — so `--authorize` is a required consent gate, not a cosmetic flag: **only screen sites you own or are explicitly authorized to test.**

What it checks on the live target:

- **Security headers** — missing/weak `Content-Security-Policy`, HSTS, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy` (`WEB-HDR`).
- **CORS misconfiguration** — `Access-Control-Allow-Origin: *` combined with `Access-Control-Allow-Credentials: true`, and reflected-origin variants (`WEB-CORS`).
- **Exposed files** — a publicly served `.env`, `.git/config`/`.git/HEAD`, `config.json`, or a leaked `.js.map` source map (`WEB-EXPOSED`).
- **Secrets in served bundles** — live-looking Stripe/AWS/OpenAI keys found in same-origin script bundles or inline `<script>` blocks, redacted before they ever appear in output (`WEB-SEC`).
- **Cookie flags** — session-shaped cookies missing `Secure`, `HttpOnly`, or a strong `SameSite` (`WEB-COOKIE`).

`--allow-private` is a separate escape hatch for the SSRF guard, only needed to point live-URL screening at a loopback/private/link-local host (e.g. `localhost`) during local dev/test — it is refused by default. Live-URL screening is fully deterministic and never invokes an LLM, regardless of your provider env vars.

## Use as a Claude Code skill

immunogen ships a first-class **Claude Code skill** in this repo at
[`.claude/skills/immunogen/`](./.claude/skills/immunogen). Once installed, ask
Claude Code to run it — or invoke it directly — and it screens a repo **or a
live URL** and hands back the graded report verbatim:

```
/immunogen ./my-app
/immunogen https://myapp.com --authorize
```

It's the exact same deterministic `scan()` the CLI uses (byte-for-byte parity
is enforced by a test), so the grade, Ship Score, and findings match the CLI.

**Install it:**

```sh
# 1. get immunogen and build it (until it's on npm)
git clone https://github.com/Mocinjay/immunogen.git
cd immunogen && pnpm install && pnpm build

# 2. make the skill visible to Claude Code everywhere — symlink (stays in
#    sync when you rebuild) or copy the skill folder into ~/.claude/skills/
ln -s "$PWD/.claude/skills/immunogen" ~/.claude/skills/immunogen
```

The wrapper resolves the built library automatically — from the repo when the
skill lives inside it (a symlink follows the real path), or from an installed
`immunogen` package once you `npm i immunogen`. Live-URL screening stays
consent-gated: a URL without `--authorize` is refused before any request is
made.

## CI gate example

Screen every push and upload results as a GitHub code-scanning alert:

```yaml
- name: Screen with immunogen
  run: npx immunogen . --format sarif > results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

A `blocked` verdict fails the step; a `pass` verdict clears it — the repo's exit code is the gate.

## Roadmap

Planned for v2: Python/Go detector coverage, and deeper detectors (transitive lockfile traversal, slopsquatting/hallucinated-package detection, JWT storage checks, SQL injection detection). Live-URL screening shipped in v2 (see [Screen a live URL](#screen-a-live-url)).

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for dev setup, how to add a detector, and commit conventions.

## Install name

`immunogen` may already be taken on npm — if so, this package publishes under `@<scope>/immunogen` instead, with an identical CLI and library API.

## License

This project is licensed under the [MIT License](./LICENSE). Some third-party code adapted into this project (notably from NVIDIA SkillSpector, Apache-2.0) retains its original license and attribution — see [NOTICE](./NOTICE) and [THIRD_PARTY_NOTICES.md](./THIRD_PARTY_NOTICES.md) for details.

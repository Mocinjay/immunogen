# immunogen

[![npm version](https://img.shields.io/npm/v/immunogen.svg)](https://www.npmjs.com/package/immunogen)
[![CI](https://github.com/Mocinjay/immunogen/actions/workflows/ci.yml/badge.svg)](https://github.com/Mocinjay/immunogen/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![Node >=22](https://img.shields.io/badge/node-%3E%3D22-brightgreen.svg)](https://nodejs.org)

**Your AI agent shipped the code. immunogen makes sure it didn't ship an infection.**

A clean bill of health for AI-built apps, before you ship. immunogen is a static, offline-first screen for repos built with Cursor, Claude Code, Lovable, Bolt, v0, or Replit — it never executes your code, reads it once, and returns a 0–100 **Ship Score** across 11 categories, including the AI layer itself (skills, MCP servers, agent/system prompts) — the exposure surface nothing else screens for.

## Quickstart

```sh
npx immunogen ./my-app
```

Runs fully offline, no API key required, and prints a terminal report with a Ship Score.

## Sample output

Run against a deliberately contaminated fixture app:

```
Ship Score: 0/100 — High risk
Verdict: blocked
Critical: 17  High: 34

  CRITICAL SEC-05 .env:1
    Committed environment file (.env) found in the scanned tree. [confidence: HIGH]

  CRITICAL SEC-01 .env:2
    Hardcoded Stripe live secret key (sk_live_) found in source. [confidence: HIGH]
    matched: sk_l****

  CRITICAL SEC-04 .env:3
    Reference to SUPABASE_SERVICE_ROLE_KEY found in source. [confidence: HIGH]
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

## Why immunogen

| | immunogen | vibe-check.cloud | benavlabs | vibeappscanner |
|---|---|---|---|---|
| Offline / zero API key | Yes | — | — | — |
| **Scans the AI layer (skills/MCP/prompts) — unique** | **Yes** | — | — | — |
| **SARIF output for CI gate** | **Yes** | — | — | — |
| Open source (MIT) | Yes | — | — | — |
| Static-only, never executes code | Yes | — | — | — |

## What it screens for

11 categories, 17 detectors — the launch-blocking problems coding agents quietly ship.

| Category | What it catches |
|---|---|
| Secrets | Hardcoded provider keys (Stripe, AWS, OpenAI), committed `.env` files, high-entropy tokens |
| Client-bundle exposure | Secret-named env vars leaking into the browser via `NEXT_PUBLIC_`/`VITE_` prefixes |
| Auth & RLS | Unauthenticated route handlers, open Firebase rules, missing Supabase row-level security |
| Payment safety | Stripe webhook handlers that skip signature verification |
| Dependencies (OSV) | Known CVEs in direct dependencies via the OSV.dev batch API, with offline fallback |
| Injection / XSS | Unsanitized `dangerouslySetInnerHTML` |
| CORS & headers | Wildcard CORS with credentials, missing Content-Security-Policy |
| Storage | Public Firebase/Firestore/Storage rules, unpoliced Supabase buckets |
| Legal | Missing privacy-policy / terms surface when the app collects user data |
| Config / debug | Full `process.env` dumps to logs or debug endpoints |
| ⭐ AI layer | Prompt-injection strings, data-exfiltration patterns, and MCP tool-poisoning/least-privilege gaps in skills, rules, and agent prompts — screening no other scanner performs |

## Architecture

```
repo → ingest (walk + AST cache) → detectors (17, 11 categories) → Ship Score → reporters (terminal · json · sarif)
```

## CLI usage

```sh
immunogen <path> [--format terminal|json|sarif] [--no-llm]
```

- `<path>` — path to the repository to scan.
- `--format terminal|json|sarif` — output format (default `terminal`). `json` is a stable machine-readable `ScanResult`; `sarif` is for GitHub code scanning / other SARIF-aware tooling.
- `--no-llm` — disable LLM fix-prompt enrichment. This is already the default; the flag exists for explicitness in scripts/CI.
- **Exit code:** `1` when the verdict is `blocked` (contaminated), `0` when `pass` (cleared) — drop it straight into a CI gate.

### Library usage

```js
import { scan } from "immunogen";

const result = await scan("./my-app");
console.log(result.score, result.findings);
```

`scan(path, options?)` returns a `ScanResult`: `{ target, scannedAt, stackHints, findings, score, llmEnriched, scanIncomplete }`. `score` is a `ShipScore` (`{ score, band, verdict, criticalCount, highCount }`); `findings` is a severity-sorted `Finding[]` with `file`/`line`/`ruleId`/`category`/`confidence`.

### Optional LLM fix prompts

By default, immunogen never calls an LLM. To enable Claude- or OpenAI-generated copy-paste fix prompts for HIGH/CRITICAL findings, set:

| Env var | Purpose |
|---|---|
| `IMMUNOGEN_PROVIDER` | `anthropic` or `openai` — selects the adapter |
| `ANTHROPIC_API_KEY` | Required when `IMMUNOGEN_PROVIDER=anthropic` |
| `OPENAI_API_KEY` | Required when `IMMUNOGEN_PROVIDER=openai` |
| `OPENAI_BASE_URL` | Optional override for OpenAI-compatible endpoints (e.g. a local Ollama server) |

If neither an env-configured provider nor the matching key is present, immunogen silently stays offline (no network call, no error). Every finding snippet is redacted before it is sent to any provider — no full source, no matched secret text ever leaves your machine unredacted.

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

Planned for v2: live-URL screening, Python/Go detector coverage, and deeper detectors (transitive lockfile traversal, slopsquatting/hallucinated-package detection, JWT storage checks, SQL injection detection). See [`.planning/REQUIREMENTS.md`](./.planning/REQUIREMENTS.md) for the full list.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for dev setup, how to add a detector, and commit conventions.

## Install name

`immunogen` may already be taken on npm — if so, this package publishes under `@<scope>/immunogen` instead, with an identical CLI and library API.

## License

This project is licensed under the [MIT License](./LICENSE). Some third-party code adapted into this project (notably from NVIDIA SkillSpector, Apache-2.0) retains its original license and attribution — see [NOTICE](./NOTICE) and [THIRD_PARTY_NOTICES.md](./THIRD_PARTY_NOTICES.md) for details.

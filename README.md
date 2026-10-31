<div align="center">

<img src="https://raw.githubusercontent.com/Mocinjay/immunogen/main/assets/logo.svg" alt="immunogen" width="460" />

**Your AI agent shipped the code. immunogen makes sure it didn't ship an infection.**

[![Latest release](https://img.shields.io/github/v/release/Mocinjay/immunogen)](https://github.com/Mocinjay/immunogen/releases/latest)
[![CI](https://github.com/Mocinjay/immunogen/actions/workflows/ci.yml/badge.svg)](https://github.com/Mocinjay/immunogen/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![Node >=22](https://img.shields.io/badge/node-%3E%3D22-brightgreen.svg)](https://nodejs.org)

<img src="https://raw.githubusercontent.com/Mocinjay/immunogen/main/assets/hero.jpg" alt="immunogen — a clean bill of health for AI-built apps" width="100%" />

<samp>A · Immune&nbsp;&nbsp;·&nbsp;&nbsp;B · Healthy&nbsp;&nbsp;·&nbsp;&nbsp;C · Symptomatic&nbsp;&nbsp;·&nbsp;&nbsp;D · Infected&nbsp;&nbsp;·&nbsp;&nbsp;F · Critical</samp>

</div>

A clean bill of health for AI-built apps, before you ship. immunogen is a static, offline-first screen for repos built with Cursor, Claude Code, Lovable, Bolt, v0, or Replit — JavaScript/TypeScript, Python, and Go — it never executes your code, reads it once, and returns a 0–100 **Ship Score** across 12 categories, including the AI layer itself (skills, MCP servers, agent/system prompts) — a surface most scanners skip entirely.

## Quickstart

Requires Node.js 22 or newer. Install the latest release from GitHub:

```sh
npm install -g https://github.com/Mocinjay/immunogen/releases/latest/download/immunogen.tgz
```

Then run it in your project directory:

```sh
immunogen
```

It scans the current folder, no API key required, and prints a terminal report with a Ship Score. Point it elsewhere with `immunogen ./path/to/app`. The only network call it ever makes is a dependency-vulnerability lookup against OSV.dev (package names + versions only); add `--offline` to skip that too.

One-off run without a global install:

```sh
npx --yes --package=https://github.com/Mocinjay/immunogen/releases/latest/download/immunogen.tgz immunogen
```

Per-project (CI gate / library use):

```sh
npm install --save-dev https://github.com/Mocinjay/immunogen/releases/latest/download/immunogen.tgz
```

Or run it in Docker with no Node toolchain at all:

```sh
docker build -t immunogen https://github.com/Mocinjay/immunogen.git
docker run --rm -v "$PWD:/app" immunogen /app
```

## Sample output

Run against a deliberately contaminated fixture app:

```
GRADE: F — Critical
Ship Score: 0/100 — High risk
Verdict: blocked
Critical: 13  High: 6

  CRITICAL SEC-05 .env:1
    Committed environment file (.env) found in the scanned tree. [confidence: HIGH]

  CRITICAL SEC-01 .env:2
    Hardcoded Stripe live secret key (sk_live_/rk_live_) found in source. [confidence: HIGH]
    matched: sk_l****

  CRITICAL SEC-04 .env:3
    SUPABASE_SERVICE_ROLE_KEY is assigned a hardcoded value in source. [confidence: HIGH]
    matched: SUPA****

  CRITICAL PAY-01 app/api/stripe/webhook/route.ts:3
    Stripe webhook handler does not verify the signature (missing constructEvent). [confidence: HIGH]

  CRITICAL AUTH-01 app/api/stripe/webhook/route.ts:8
    Exported Next.js route handler POST has no authentication or authorization check. [confidence: MEDIUM]
    matched: POST

  CRITICAL AUTH-02 firestore.rules:5
    Firebase rule grants public read/write access (allow ...: if true). [confidence: HIGH]
    matched: allow read, write: if true;
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

12 categories and 23 detectors on a repo scan (JavaScript/TypeScript, Python, Go) — plus 5 web-probe detectors when you screen a live URL — the launch-blocking problems coding agents quietly ship.

| Category | What it catches |
|---|---|
| Secrets | Hardcoded provider keys (Stripe, AWS, OpenAI incl. `sk-proj-`, Anthropic, Gemini / Google `AIza` keys outside Firebase/Maps client config, Supabase `service_role`/`sb_secret_`, GitHub, Slack, SendGrid, Resend, Groq, xAI, Hugging Face, Replicate, npm), committed private keys / service-account JSON, committed `.env` files (git-tracked, or not covered by any `.gitignore`), high-entropy tokens (prose, URLs, hashes, and lockfiles are ignored) |
| Client-bundle exposure | Secret-named env vars inlined into the client via `NEXT_PUBLIC_`/`VITE_`/`EXPO_PUBLIC_`/`REACT_APP_`/`NUXT_PUBLIC_`/`GATSBY_` (public-by-design keys like the Supabase anon key are not flagged), LLM SDKs run in the browser with `dangerouslyAllowBrowser` |
| Auth & RLS | Unauthenticated routes — Next.js App Router handlers, Pages Router API routes, Server Actions, Express/Fastify/Hono/Koa, FastAPI/Flask, Go (Gin/Echo/Chi/Fiber/net/http); Supabase tables created without RLS and `using (true)` write policies (read from your migrations); open Firebase rules incl. test-mode and signed-in-only wildcards; JWTs decoded without verification; auth tokens stored in `localStorage` |
| Abuse / rate limiting | AI endpoints that call a paid LLM API and login/sign-up/password-reset endpoints with no rate limiting |
| Payment safety | Stripe webhook handlers that skip signature verification, charge amounts taken from the request (JS, Python, Go) |
| Dependencies (OSV) | Known vulnerabilities in every resolved package — direct and transitive, read from `package-lock.json` / `pnpm-lock.yaml` / `yarn.lock` / `bun.lock` / `poetry.lock` / `uv.lock` / `Pipfile.lock`, or from `package.json` / `requirements.txt` / `pyproject.toml` / `go.mod` when there is no lockfile — rated by each advisory's real severity (GitHub rating or CVSS v3 score), with an offline fallback |
| Injection / XSS | Unsanitized `dangerouslySetInnerHTML`; SQL built by interpolation (`$queryRawUnsafe`, `` .query(`... ${x}`) ``, Python f-string `execute`, Go `Sprintf` queries); `eval` / `exec` / shell commands / unsafe YAML or pickle on dynamic input; server-side request forgery (fetching a URL taken from the request); open redirects |
| CORS & headers | Wildcard CORS with credentials, any-origin-with-credentials setups (`cors({ origin: true, credentials: true })`, FastAPI/flask-cors, Go cors packages, reflected origins), missing Content-Security-Policy |
| Storage | Public Firebase/Firestore/Storage rules, unpoliced Supabase buckets |
| Legal | Missing privacy-policy / terms surface when the app collects user data |
| Config / debug | Full environment dumps (`process.env`, `os.environ`, `os.Environ()`) to logs or HTTP responses |
| ⭐ AI layer | Prompt-injection strings, data-exfiltration patterns, and MCP tool-poisoning/least-privilege gaps in skills, rules, and agent prompts — a layer most scanners skip |

## Architecture

```
repo → ingest (walk + AST cache) → detectors (23, 12 categories) → Ship Score → reporters (terminal · json · sarif)
```

## CLI usage

```sh
immunogen [path] [--format terminal|json|sarif] [--offline] [--no-ignore] [--no-llm] [--authorize] [--allow-private]
```

- `[path]` — path to the repository to scan (default: the current directory), a git repo URL to clone and scan (`https://github.com/owner/repo`, GitLab, Bitbucket, Codeberg, or any `.git` URL), or a live `https://`/`http://` URL to screen.
- `--format terminal|json|sarif` — output format (default `terminal`). `json` is a stable machine-readable `ScanResult`; `sarif` is for GitHub code scanning / other SARIF-aware tooling.
- `--offline` — never touch the network: skip the OSV.dev lookup and check dependencies against the bundled offline advisory list only (the report notes the dependency check is incomplete).
- `--no-ignore` — disregard `.immunogenignore` and inline `immunogen-ignore` comments (see [Suppressing findings](#suppressing-findings)) — use it when auditing a repo you do not control.
- `--no-llm` — disable LLM fix-prompt enrichment. This is already the default; the flag exists for explicitness in scripts/CI.
- `--authorize` — required consent gate to screen a live URL target (see [Screen a live URL](#screen-a-live-url)). Has no effect when `<path>` is a local repo.
- `--allow-private` — escape hatch letting live-URL screening target a loopback/private/link-local host (local dev/test only).
- `-v, --version` — print the installed version.
- **Exit code:** `1` when the verdict is `blocked` (contaminated), `0` when `pass` (cleared), `2` when the scan could not run at all (bad path, missing `--authorize`, refused private host, ...) — drop it straight into a CI gate.

### Suppressing findings

Accept a reviewed finding with a comment on its line or the line above it — bare to cover every rule there, or with the rule ids to cover just those:

```ts
// immunogen-ignore AUTH-01 — public newsletter signup, rate-limited upstream
export async function POST(req: Request) { /* ... */ }
```

Exclude whole paths (vendored code, seed data) with a `.immunogenignore` file at the scan root, in `.gitignore` syntax. Route handlers can also be marked with a `// public` comment.

### Library usage

```js
import { scan } from "immunogen";

const result = await scan("./my-app");
console.log(result.score, result.findings);
```

`scan(path, options?)` returns a `ScanResult`: `{ target, scannedAt, stackHints, findings, score, llmEnriched, scanIncomplete, diagnostics }`. `diagnostics` lists every non-fatal warning (unparseable files, files over the size cap, a truncated walk, LLM misconfiguration or failures, failed URL probes); every output format shows them, and `scanIncomplete` is `true` whenever coverage was reduced. `score` is a `ShipScore` (`{ score, grade, gradeLabel, band, verdict, criticalCount, highCount }`); `findings` is a severity-sorted `Finding[]` with `file`/`line`/`ruleId`/`category`/`confidence`.

### Optional LLM fix prompts

By default, immunogen never calls an LLM. To enable Claude- or OpenAI-generated copy-paste fix prompts for HIGH/CRITICAL findings, set:

| Env var | Purpose |
|---|---|
| `IMMUNOGEN_PROVIDER` | `anthropic` or `openai` — selects the adapter |
| `ANTHROPIC_API_KEY` | Required when `IMMUNOGEN_PROVIDER=anthropic` |
| `OPENAI_API_KEY` | Required when `IMMUNOGEN_PROVIDER=openai` |
| `OPENAI_BASE_URL` | Optional override for OpenAI-compatible endpoints (e.g. a local Ollama server) |
| `IMMUNOGEN_MODEL` | Optional model override. Defaults: `claude-haiku-5-5` (Anthropic), `gpt-4o-mini` (OpenAI). Required for OpenAI-compatible servers, which serve their own model names (e.g. `llama3.1`) |

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

`--allow-private` is a separate escape hatch for the SSRF guard, only needed to point live-URL screening at a loopback/private/link-local host (e.g. `localhost`) during local dev/test — it is refused by default. The guard resolves the host's DNS and re-checks before every request, including each redirect hop, so neither a public name that resolves to an internal address nor a redirect into your network is followed. Exposed-file probes never follow redirects, and an HTML app shell served for `/.env` (an SPA catch-all) is not reported as a leak. Live-URL screening is fully deterministic and never invokes an LLM, regardless of your provider env vars.

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
# 1. get immunogen and build it
git clone https://github.com/Mocinjay/immunogen.git
cd immunogen && pnpm install && pnpm build

# 2. make the skill visible to Claude Code everywhere — symlink (stays in
#    sync when you rebuild) or copy the skill folder into ~/.claude/skills/
ln -s "$PWD/.claude/skills/immunogen" ~/.claude/skills/immunogen
```

The wrapper resolves the built library automatically — from the repo when the
skill lives inside it (a symlink follows the real path), or from an installed
`immunogen` package (see [Quickstart](#quickstart)). Live-URL screening stays
consent-gated: a URL without `--authorize` is refused before any request is
made.

## CI gate example

Screen every push and upload results as GitHub code-scanning alerts:

```yaml
name: immunogen

on: [push, pull_request]

permissions:
  contents: read
  security-events: write

jobs:
  screen:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7

      - uses: actions/setup-node@v7
        with:
          node-version: "22"

      - name: Screen with immunogen
        run: npx --yes --package=https://github.com/Mocinjay/immunogen/releases/latest/download/immunogen.tgz immunogen . --format sarif > results.sarif

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: results.sarif
```

A `blocked` verdict fails the step; a `pass` verdict clears it — the exit code is the gate. `if: always()` makes sure the findings still reach the Security tab when the gate fails.

## Roadmap

Planned: Django and Rails route coverage, slopsquatting / hallucinated-package detection, and cross-file data-flow for injection rules. Shipped since v1: live-URL screening (see [Screen a live URL](#screen-a-live-url)), Python and Go support, lockfile (transitive) dependency checks with real advisory severity, SSRF / open-redirect / rate-limit / token-storage rules.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for dev setup, how to add a detector, and commit conventions. Release notes live in [CHANGELOG.md](./CHANGELOG.md).

## Security

Found a vulnerability in immunogen itself (not in a repo you scanned)? Please report it privately — see [SECURITY.md](./SECURITY.md).

## License

This project is licensed under the [MIT License](./LICENSE). Some third-party code adapted into this project (notably from NVIDIA SkillSpector, Apache-2.0) retains its original license and attribution — see [NOTICE](./NOTICE) and [THIRD_PARTY_NOTICES.md](./THIRD_PARTY_NOTICES.md) for details.

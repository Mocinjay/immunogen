<div align="center">

<img src="https://raw.githubusercontent.com/Mocinjay/immunogen/main/assets/logo.svg" alt="immunogen" width="460" />

### Your AI agent shipped the code. immunogen makes sure it didn't ship an infection.

[![Latest release](https://img.shields.io/github/v/release/Mocinjay/immunogen?style=flat-square&color=2ea043&label=release)](https://github.com/Mocinjay/immunogen/releases/latest)
[![CI](https://img.shields.io/github/actions/workflow/status/Mocinjay/immunogen/ci.yml?branch=main&style=flat-square&label=CI)](https://github.com/Mocinjay/immunogen/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](./LICENSE)
[![Node ≥ 22](https://img.shields.io/badge/node-%E2%89%A5%2022-339933?style=flat-square&logo=nodedotjs&logoColor=white)](https://nodejs.org)
[![SARIF](https://img.shields.io/badge/output-SARIF%202.1.0-6e7681?style=flat-square)](#ci-integration)

[Quickstart](#quickstart) · [What it catches](#what-it-catches) · [CI integration](#ci-integration) · [Live URL screening](#screen-a-live-url) · [Changelog](./CHANGELOG.md)

<br />

<img src="https://raw.githubusercontent.com/Mocinjay/immunogen/main/assets/demo.svg" alt="immunogen scanning a sample app: grade F, Ship Score 0/100, verdict blocked, with findings for a committed .env file, a hardcoded Stripe live key, a hardcoded Supabase service-role key, an unverified Stripe webhook and an unauthenticated route" width="100%" />

</div>

<br />

**immunogen** is a static security scanner for apps built with AI coding agents — Cursor, Claude Code, Lovable, Bolt, v0, Replit. Point it at a project and it returns a **0–100 Ship Score**, an **A–F grade**, and every launch-blocking problem with its exact `file:line`: leaked keys, unauthenticated routes, missing row-level security, unverified payment webhooks, vulnerable dependencies — and the AI layer itself (agent rules, skills, MCP servers), which most scanners never look at.

- **Deterministic** — the same code always produces the same report. No LLM decides what counts as a finding.
- **Never runs your code** — static analysis only, and secrets are redacted in every output format.
- **Offline-first** — a local scan's only network calls are an OSV.dev lookup and a registry existence check of package names (and versions for OSV); `--offline` removes both.
- **Covers the AI layer** — prompt injection, data exfiltration, MCP tool poisoning, auto-running agent hooks and over-broad agent permissions in skills, rules, settings and MCP configs.
- **Repo, git URL or live site** — scan a folder, a ZIP, a GitHub/GitLab/Bitbucket URL, or (with consent) a deployed website.
- **CI-native** — a GitHub Action, exit codes that gate the build, SARIF for code scanning, and a baseline mode so existing repos fail only on new findings.

Works on JavaScript / TypeScript, Python and Go.

## Quickstart

Requires **Node.js 22+**. Install the latest release:

```sh
npm install -g https://github.com/Mocinjay/immunogen/releases/latest/download/immunogen.tgz
```

Run it in your project folder:

```sh
immunogen
```

That's it — no account, no API key. Scan another folder with `immunogen ./path/to/app`, or a remote repo with `immunogen https://github.com/owner/repo`.

Fixing with an AI coding agent? `immunogen --format prompt` prints a numbered, ready-to-paste brief — every problem with its `file:line` and fix.

<details>
<summary><b>Other ways to run it</b> — npx, per-project, Docker</summary>

<br />

One-off run without installing (pinned to a release, because npx caches whatever a URL first downloaded):

```sh
npx --yes --package=https://github.com/Mocinjay/immunogen/releases/download/v0.3.0/immunogen-0.3.0.tgz immunogen
```

As a project dev dependency (CI gate or library use):

```sh
npm install --save-dev https://github.com/Mocinjay/immunogen/releases/latest/download/immunogen.tgz
```

In Docker, with no Node toolchain at all:

```sh
docker build -t immunogen https://github.com/Mocinjay/immunogen.git
docker run --rm -v "$PWD:/app" immunogen /app
```

</details>

## How grading works

<img src="https://raw.githubusercontent.com/Mocinjay/immunogen/main/assets/grades.svg" alt="Grade scale on the 0–100 Ship Score: F Critical 0–34, D Infected 35–54, C Symptomatic 55–74, B Healthy 75–89, A Immune 90–100. Any CRITICAL finding is an automatic F." width="100%" />

Every finding costs points by severity (CRITICAL 50, HIGH 25, MEDIUM 10, LOW 5) — half that for a LOW-confidence heuristic — and the remaining score maps to a grade. **A single CRITICAL finding** — one leaked production key, one unauthenticated payment route — **is an automatic F** and blocks the verdict, however clean the rest of the project is. The verdict is `blocked` on any CRITICAL finding or a score below 40, and `pass` otherwise.

## What it catches

25 detectors across 12 categories on a repo scan, plus 5 web probes and a backend data-exposure check when you screen a live URL.

| Category | What it catches |
|---|---|
| **Secrets** | Hardcoded provider keys (Stripe, AWS, OpenAI incl. `sk-proj-`, Anthropic, Gemini / Google `AIza` keys outside Firebase/Maps client config, Supabase `service_role` / `sb_secret_`, GitHub, Slack, SendGrid, Resend, Groq, xAI, Hugging Face, Replicate, npm), database connection strings with a password (Postgres / Supabase / Neon, MySQL, MongoDB Atlas, Redis), committed private keys and service-account JSON, committed `.env` files that hold secrets, high-entropy tokens (prose, URLs, hashes, lockfiles and documentation placeholders such as `sk_live_YOUR_KEY` are ignored) |
| **Client-bundle exposure** | Secret-named env vars inlined into the client via `NEXT_PUBLIC_` / `VITE_` / `EXPO_PUBLIC_` / `REACT_APP_` / `NUXT_PUBLIC_` / `GATSBY_` (public-by-design keys such as the Supabase anon key are not flagged); LLM SDKs running in the browser with `dangerouslyAllowBrowser` |
| **Auth & RLS** | Unauthenticated routes — Next.js App Router handlers, Pages Router API routes, Server Actions, Express / Fastify / Hono / Koa, FastAPI / Flask, Go (Gin / Echo / Chi / Fiber / net/http); Supabase tables without RLS and `using (true)` write policies; open Firebase rules; JWTs decoded without verification; auth tokens in `localStorage` |
| **Abuse / rate limiting** | Paid-LLM endpoints and login / sign-up / password-reset endpoints with no rate limiting |
| **Payment safety** | Stripe webhooks that skip signature verification; charge amounts taken from the request |
| **Dependencies** | Known vulnerabilities in every resolved package, direct and transitive, from npm / pnpm / yarn / bun / Poetry / uv / Pipenv lockfiles or manifests — rated by each advisory's real severity (one level lower for dev-only packages), with the version to upgrade to and an offline fallback; dependencies that don't exist on the public npm / PyPI registry (hallucinated names an attacker could register) |
| **Injection / XSS** | Unsanitized `dangerouslySetInnerHTML`; SQL built by string interpolation; `eval` / `exec` / shell / unsafe YAML or pickle on dynamic input; server-side request forgery; open redirects |
| **CORS & headers** | Wildcard or reflected origins combined with credentials; missing Content-Security-Policy |
| **Storage** | Public Firebase / Firestore / Storage rules; Supabase buckets with no access policy |
| **Legal** | No privacy policy or terms when the app collects user data |
| **Config / debug** | Whole-environment dumps (`process.env`, `os.environ`, `os.Environ()`) to logs or HTTP responses |
| **AI layer** | Prompt-injection strings, data-exfiltration directives, MCP tool poisoning and least-privilege gaps in skills, rules and agent prompts (Claude, Cursor, Copilot, Windsurf, Gemini, Cline, Kiro, ...); agent hooks, VS Code folder-open tasks and MCP launch commands that download-and-run code or send credentials out; `Bash(*)`, `bypassPermissions` and auto-approved MCP servers in committed agent settings |

## How it compares

| | **immunogen** | [vibe-check.cloud][vc] | [benavlabs/vibe-check][bv] | [Vibe App Scanner][vas] |
|---|:---:|:---:|:---:|:---:|
| Free / open source | ✅ MIT | ✅ | ✅ MIT | ❌ paid |
| Deterministic engine — no LLM, reproducible | ✅ | ❌ AI-driven | ❌ AI-driven | ~ hosted |
| Static repo scan (never executes your code) | ✅ | ✅ | ✅ | ❌ dynamic |
| Live URL / deployed-app scan | ✅ | ❌ | ❌ | ✅ |
| Scans the **AI layer** (skills / MCP / agent prompts) | ✅ deep | ~ partial | ❌ | ❌ |
| SARIF output for a CI gate | ✅ | ❌ | ❌ | ❌ |

<sub>✅ yes · ~ partial · ❌ no / not documented. Compared against each tool's public docs and README as of July 2026 — something wrong? Open a PR.</sub>

[vc]: https://vibe-check.cloud/
[bv]: https://github.com/benavlabs/vibe-check
[vas]: https://vibeappscanner.com/

## Usage

```sh
immunogen [path] [options]
```

`path` is a local folder (default: the current directory), a ZIP file, a git repository URL (GitHub, GitLab, Bitbucket, Codeberg or any `.git` URL), or a live `https://` URL to screen.

| Option | Description |
|---|---|
| `--format <format>` | `terminal` (default), `json` (a stable `ScanResult`), `sarif` (GitHub code scanning and other SARIF tools), or `prompt` (a numbered fix-it brief to paste into Claude Code / Cursor / Copilot). |
| `--min-severity <level>` | Leave out — and don't score — findings below `info` / `low` / `medium` / `high` / `critical`. |
| `--baseline <file>` | An earlier `--format json` report: findings already in it are not scored, so only new ones can fail the build. |
| `--offline` | No dependency lookups: check against the bundled advisory list instead of OSV.dev, and skip the registry existence check. (Cloning a git URL still needs the network.) |
| `--no-ignore` | Disregard `.immunogenignore` and inline `immunogen-ignore` comments — for auditing a repo you don't control. |
| `--no-llm` | Disable LLM fix prompts (already the default; explicit for scripts). |
| `--authorize` | Required consent to screen a live URL. Only screen sites you own or are authorized to test. |
| `--allow-private` | Let live-URL screening reach loopback / private hosts (local dev only). |
| `--no-data-probes` | Live-URL screening: skip the Supabase / Firebase data-exposure check. |
| `-v, --version` | Print the installed version. |

| Exit code | Meaning |
|:---:|---|
| `0` | Verdict `pass` |
| `1` | Verdict `blocked` — fail the build |
| `2` | The scan could not run (bad path, missing `--authorize`, refused host, …) |

### Suppressing findings

Accept a reviewed finding with a comment on its line or the line above — bare to cover every rule there, or with rule IDs to cover just those:

```ts
// immunogen-ignore AUTH-01 — public newsletter signup, rate-limited upstream
export async function POST(req: Request) { /* ... */ }
```

Exclude whole paths (vendored code, seed data) with a `.immunogenignore` file at the scan root, in `.gitignore` syntax. Route handlers can also be marked with a `// public` comment.

Suppressions never disappear silently: every report counts them, JSON lists them under `suppressed` with their comment, and SARIF marks them as suppressed in source — so an accepted risk stays visible, including one a coding agent accepted for you. Pass `--no-ignore` to score them anyway.

The scan follows `.gitignore` and `.git/info/exclude`, and skips agent worktrees (`.claude/worktrees/`, or any nested git worktree) so a second checkout of the same repo is never counted twice.

<details>
<summary><b>Library API</b></summary>

<br />

```js
import { scan } from "immunogen";

const result = await scan("./my-app");
console.log(result.score.grade, result.score.score, result.findings.length);
```

`scan(path, options?)` returns a `ScanResult`: `{ target, scannedAt, stackHints, findings, score, llmEnriched, scanIncomplete, diagnostics, suppressed?, baselined? }`.

- `score` — `{ score, grade, gradeLabel, band, verdict, criticalCount, highCount }`
- `findings` — severity-sorted, each with `ruleId`, `category`, `severity`, `confidence`, `file`, `line`, `message`, `remediation`
- `diagnostics` — every non-fatal note (unparseable files, files over the size cap, a truncated walk, suppressed or baselined findings, LLM or URL-probe failures); `scanIncomplete` is `true` when the dependency check fell back to the offline list, the walk hit a repo-size cap, or a live-URL check could not complete
- `suppressed` — findings silenced by `immunogen-ignore` comments (not scored); `baselined` — findings that matched `options.baseline` (not scored)

Ships as ESM and CommonJS with TypeScript types.

</details>

<details>
<summary><b>Optional LLM fix prompts</b></summary>

<br />

immunogen never calls an LLM unless you configure one. To add copy-paste fix prompts to HIGH and CRITICAL findings:

| Env var | Purpose |
|---|---|
| `IMMUNOGEN_PROVIDER` | `anthropic` or `openai` |
| `ANTHROPIC_API_KEY` | Required when the provider is `anthropic` |
| `OPENAI_API_KEY` | Required when the provider is `openai` |
| `OPENAI_BASE_URL` | Optional OpenAI-compatible endpoint (e.g. a local Ollama server) |
| `IMMUNOGEN_MODEL` | Optional model override. Defaults: `claude-haiku-5-5` (Anthropic), `gpt-4o-mini` (OpenAI). Required for OpenAI-compatible servers, which serve their own model names |

Every snippet is redacted before it is sent — no source file and no matched secret ever leaves your machine. Scoring never depends on the LLM.

</details>

## CI integration

Gate every push and pull request with the GitHub Action, and send findings to the repository's **Security → Code scanning** tab:

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
      - uses: Mocinjay/immunogen@v0.3.0
```

A `blocked` verdict fails the job, and the SARIF report is uploaded either way. Alert fingerprints don't depend on line numbers, so alerts keep their identity when unrelated edits move code around.

| Input | Default | |
|---|---|---|
| `path` | `.` | Folder to scan |
| `format` | `sarif` | `sarif`, `json`, `terminal` or `prompt` |
| `output` | `immunogen.sarif` | Where the report is written |
| `args` | | Extra flags, e.g. `--min-severity high` or `--baseline immunogen-baseline.json` |
| `upload-sarif` | `true` | Upload to code scanning (needs `security-events: write`) |
| `fail-on-blocked` | `true` | Fail the step on a `blocked` verdict |

Outputs: `score`, `grade`, `verdict`.

**Adopting it on an existing repo?** Commit a baseline once — `immunogen --format json > immunogen-baseline.json` — and pass `args: --baseline immunogen-baseline.json`. Existing findings stop counting; any new one still fails the build.

<details>
<summary>Without the action (any CI)</summary>

<br />

```sh
npx --yes --package=https://github.com/Mocinjay/immunogen/releases/download/v0.3.0/immunogen-0.3.0.tgz immunogen . --format sarif > results.sarif
```

Exit code `1` means blocked.

</details>

## Screen a live URL

```sh
immunogen https://myapp.com --authorize
```

A bounded, read-only probe of a deployed site. `--authorize` is a required consent gate — **only screen sites you own or are explicitly authorized to test.**

| Check | What it looks for |
|---|---|
| Security headers (`WEB-HDR`) | Missing or weak CSP, HSTS, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy` |
| CORS (`WEB-CORS`) | Any-origin or reflected-origin access combined with credentials |
| Exposed files (`WEB-EXPOSED`) | A publicly served `.env`, `.git/config`, `.git/HEAD`, `config.json` or source map |
| Secrets in bundles (`WEB-SEC`) | Live-looking provider keys in same-origin scripts, redacted in output |
| Cookies (`WEB-COOKIE`) | Session cookies missing `Secure`, `HttpOnly` or a strong `SameSite` |
| Backend data exposure (`WEB-DATA`) | Whether the Supabase tables, Firebase Realtime Database or Firestore collections the site's code uses can be read with the public key it ships |

The data-exposure check is read-only: it asks Supabase for a row **count** (`HEAD` with `Prefer: count=exact`, no row data), asks Firebase for top-level key names or document names only, writes nothing, and only contacts the Supabase / Firebase hosts named in the site's own bundle. `--no-data-probes` turns it off.

<details>
<summary><b>SSRF protection</b></summary>

<br />

Every request — the page, each redirect hop, each script, each probe — is checked against the addresses its host resolves to. Loopback, private, link-local (including cloud metadata such as `169.254.169.254`), CGNAT, reserved and IPv6 equivalents are refused, and each connection is pinned to the addresses that passed the check, so a DNS-rebinding server can't swap in an internal address afterwards. Redirects are followed by hand with a hop limit; probes never follow redirects; an SPA's catch-all page served for `/.env` isn't reported as a leak. `--allow-private` lifts the guard for local development. URL mode never calls an LLM.

</details>

## Use as a Claude Code skill

immunogen ships a [Claude Code skill](./.claude/skills/immunogen) that runs the same deterministic scan and returns the graded report — a test checks that the skill and the library report the same Ship Score and findings count.

```
/immunogen ./my-app
/immunogen https://myapp.com --authorize
```

<details>
<summary><b>Install the skill</b></summary>

<br />

```sh
git clone https://github.com/Mocinjay/immunogen.git
cd immunogen && pnpm install && pnpm build
ln -s "$PWD/.claude/skills/immunogen" ~/.claude/skills/immunogen
```

The symlink keeps the skill in sync when you rebuild; copying the folder also works if immunogen is installed as a package (see [Quickstart](#quickstart)).

</details>

## Architecture

```mermaid
flowchart LR
    R["Folder · ZIP · git URL"] --> I["Ingest<br/>walk + parse"]
    I --> D["25 detectors<br/>12 categories"]
    U["Live URL<br/>--authorize"] --> F["Bounded fetch<br/>SSRF-guarded"]
    F --> W["5 web probes<br/>+ data exposure"]
    D --> S["Ship Score<br/>grade · verdict"]
    W --> S
    S --> O["terminal · JSON · SARIF · prompt"]
```

Scanned code is only ever read, never imported or executed; each file is parsed at most once and released before the next.

## Roadmap

Planned: Django and Rails route coverage, and cross-file data flow for injection rules. See the [changelog](./CHANGELOG.md) for what has shipped.

## Contributing

Contributions that add detection coverage, cut false positives or improve reporters are welcome — see [CONTRIBUTING.md](./CONTRIBUTING.md) for setup, how to add a detector, and conventions.

**Security issues in immunogen itself** (not in a repo you scanned) should be reported privately — see [SECURITY.md](./SECURITY.md).

## License

[MIT](./LICENSE). Code adapted from NVIDIA SkillSpector (Apache-2.0) keeps its original license and attribution — see [NOTICE](./NOTICE) and [THIRD_PARTY_NOTICES.md](./THIRD_PARTY_NOTICES.md).

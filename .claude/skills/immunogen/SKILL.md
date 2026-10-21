---
name: immunogen
description: Scan an AI-built ("vibe-coded") repo for launch-blocking issues — leaked secrets, exposed API keys, broken auth, missing row-level security, unsafe payment wiring, vulnerable dependencies, and risky AI-layer surface (skills/MCP servers/agent prompts). Returns a 0-100 Ship Score with a banded verdict and ranked findings. Trigger this skill when the user asks to "scan this repo for security issues before shipping", "check if this app is safe to launch", "audit this AI-generated codebase", or similar pre-launch security review requests.
---

# immunogen

immunogen is a static-analysis scanner purpose-built for repos built (or partly
built) by coding agents — Cursor, Claude Code, Lovable, Bolt, v0, Replit, and
similar tools quietly ship the same handful of launch-blocking mistakes, and
immunogen finds them before a user finds them in production.

## What this skill does

Running the wrapper script performs one deterministic scan of a target
directory and returns:

- A headline **A-F health grade** (`Grade: F — Critical`, etc. — see the
  grade legend in the immunogen repo's README) layered on top of the
  numeric score below it.
- A **Ship Score** (0-100) with a band (`Ready to ship` / `Low risk` /
  `Moderate risk` / `High risk`) and a `pass`/`blocked` verdict.
- **Ranked findings** — each with severity, a stable rule id, the exact
  `file:line` location, a one-line message, and a confidence tag.

The scan is **static only** — it reads and parses source files, it never
executes, imports, or evals anything from the scanned repo (this is a hard
correctness/safety guarantee of the underlying library, not just this skill).

## How to invoke it

Run the wrapper script against the path the user wants scanned (defaults to
the current directory if no path is given), or against a live `http(s)://`
URL to screen a deployed site (see "Live URL support" below):

```bash
node .claude/skills/immunogen/scan.mjs <path-to-repo>
node .claude/skills/immunogen/scan.mjs https://myapp.com --authorize
```

The first non-flag argument is the target (a local path or an `http(s)://`
URL). `--authorize`, `--allow-private`, and `--offline` (skip the OSV.dev
dependency lookup — no network at all) are forwarded to the scan when
present.

### Live URL support

This wrapper **now forwards** a live-URL target and the `--authorize` /
`--allow-private` flags, so it can screen a deployed website directly:

```bash
node .claude/skills/immunogen/scan.mjs https://myapp.com --authorize
```

See the immunogen repo's README "Screen a live URL" section for what it
checks (security headers, CORS misconfig, exposed `.env`/`.git`, secrets in
served bundles, cookie flags). This makes REAL bounded network requests
against the target host, so it requires the caller's explicit authorization
(`--authorize`) — **only screen sites the user owns or is explicitly
authorized to test.** A URL passed without `--authorize` is refused by the
consent gate before any request is made (clean error, exit code 2); do not
work around that — surface the message and confirm the user is authorized.
`--allow-private` additionally permits a loopback/private host (local
dev/test only). Live-URL screening is deterministic and never invokes an LLM.

The wrapper resolves the immunogen library automatically — from the built
repo (`pnpm build`) when it lives inside it, or from an installed `immunogen`
package. If it can find neither it prints one clear error asking you to build
the repo or install the package; if you see that, do that first — do not
reimplement the scan logic yourself.

The script prints markdown to stdout. **Present that markdown to the user
verbatim** — do not summarize, truncate, or rephrase the headline grade line,
the Ship Score header, or the findings list; the exact grade, score, band,
verdict, and ranked findings are the product, and altering them would
misrepresent the scan result.

## Determinism and offline behavior

This scan is **deterministic and needs no API key** — none is read or
forwarded by this wrapper. Its only network call is the OSV.dev dependency
lookup (package names + versions only); add `--offline` to skip it and use
the bundled advisory list instead. The same directory
always produces the same Ship Score and finding count (parity with the
`immunogen` CLI and the `scan()` library function is proven by an automated
test — `tests/dist/skill-parity.test.mjs` in the immunogen repo). Do not pass
any LLM/provider flags or environment variables when invoking this skill; the
zero-setup, offline path is the one this skill is wired to.

## What NOT to do

- Do not read the scanned repo's files yourself and hand-write findings —
  always run the wrapper and use its output.
- Do not execute, `require()`, or `eval` any file from the scanned repo for
  any reason, even to "double check" a finding.
- Do not invent or adjust the Ship Score or the A-F grade — report exactly
  what the wrapper returned.

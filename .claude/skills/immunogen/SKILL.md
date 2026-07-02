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

- A **Ship Score** (0-100) with a band (`Ready to ship` / `Low risk` /
  `Moderate risk` / `High risk`) and a `pass`/`blocked` verdict.
- **Ranked findings** — each with severity, a stable rule id, the exact
  `file:line` location, a one-line message, and a confidence tag.

The scan is **static only** — it reads and parses source files, it never
executes, imports, or evals anything from the scanned repo (this is a hard
correctness/safety guarantee of the underlying library, not just this skill).

## How to invoke it

Run the wrapper script against the path the user wants scanned (defaults to
the current directory if no path is given):

```bash
node .claude/skills/immunogen/scan.mjs <path-to-repo>
```

This requires the immunogen package to be built or installed so that
`dist/index.js` exists (`pnpm run build` in the immunogen repo, or
`npm install immunogen` as a dependency). If the command fails because
`dist/index.js` is missing, tell the user to build/install immunogen first —
do not attempt to reimplement the scan logic yourself.

The script prints markdown to stdout. **Present that markdown to the user
verbatim** — do not summarize, truncate, or rephrase the Ship Score header or
the findings list; the exact score, band, verdict, and ranked findings are the
product, and altering them would misrepresent the scan result.

## Determinism and offline behavior

This scan is **deterministic and fully offline by default** — no API key is
required, and none is read or forwarded by this wrapper. The same directory
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
- Do not invent or adjust the Ship Score — report exactly what the wrapper
  returned.

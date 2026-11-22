/**
 * immunogen Claude Code skill wrapper.
 *
 * Thin caller only — no detection/scoring logic lives here. This module
 * resolves the single `scan()` export from the BUILT immunogen package (see
 * `loadScan()` below) and does exactly one thing beyond that: it formats the
 * returned `ScanResult` into markdown for a Claude Code conversation to
 * present verbatim (the skill and the CLI are siblings, both thin callers of
 * the same `scan()`). The markdown leads with the
 * headline A-F health grade (`score.grade`/`score.gradeLabel`) before the
 * existing Ship Score/band/verdict/counts lines — an additive headline, not
 * a replacement for the numeric score already presented below it.
 *
 * Portability: this skill folder is meant to be copied or symlinked into
 * `~/.claude/skills/` independent of where the immunogen repo lives, so it
 * cannot rely on a fixed repo-relative path to `dist/index.js` — see
 * `loadScan()`.
 *
 * Determinism / offline-by-default: `runScanSkill` always passes
 * `noLlm: true`, so the skill never sends findings to an LLM provider —
 * not even when a provider + key happen to be configured in the ambient
 * environment (SKILL.md promises a deterministic, LLM-free scan). It never
 * reads or forwards any provider/LLM environment variable itself.
 * This keeps every distribution path (CLI, skill, Docker) on the same
 * deterministic scan by construction, which is what the skill-parity test
 * (tests/dist/skill-parity.test.mjs) proves. Callers may still opt in to
 * `{ authorize, allowPrivate }` explicitly (Task 2, live-URL screening) —
 * that is a caller-forwarded flag, not something this wrapper infers or
 * defaults on its own.
 *
 * ENG-05 (never execute scanned content): this file only calls `scan()`
 * (which itself never requires/imports/evals scanned repo content — see
 * src/index.ts's own doc comment) and then does plain string formatting of
 * the returned data. There is no `eval`, no `child_process`, and no
 * `require()` of anything derived from the scanned target anywhere in this
 * file.
 */

import { realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";

/**
 * Resolves the `scan()` function from, in order:
 *
 * 1. `../../../dist/index.js` relative to this file's own URL — the case
 *    where this skill folder still lives inside the built immunogen repo
 *    (a fresh `git clone` + `pnpm build`, or a realpath symlink of the repo's
 *    `.claude/skills/immunogen` folder into `~/.claude/skills/immunogen`;
 *    `import.meta.url`-relative resolution follows symlinks to the real
 *    on-disk path, so this covers both).
 * 2. the bare specifier `immunogen` — the case where this skill folder was
 *    copied standalone and immunogen is installed as an ordinary package
 *    (`npm install -g immunogen`), resolved via Node's normal
 *    module resolution from this file's location.
 *
 * If neither resolves, throws ONE clear, actionable error rather than
 * letting either import's own (confusing, path-specific) error propagate.
 */
async function loadScan() {
  try {
    const builtDist = new URL("../../../dist/index.js", import.meta.url);
    return (await import(builtDist.href)).scan;
  } catch {
    // Fall through to the installed-package resolution below.
  }

  try {
    return (await import("immunogen")).scan;
  } catch {
    throw new Error(
      "immunogen: could not find a built or installed immunogen. " +
        "Run this skill from inside the immunogen repo after `pnpm build`, " +
        "or install it with `npm install -g immunogen` and run `immunogen --install-skill`.",
    );
  }
}

/**
 * Renders one `Finding` as a single ranked markdown list item:
 * `- **[SEVERITY] ruleId** file:line — message (confidence: X)`. Mirrors
 * the information terminal.ts's `renderFinding` shows (severity, ruleId,
 * file:line, message, confidence) but as a markdown bullet instead of an
 * ANSI-colored block, since Claude Code renders markdown, not terminal
 * escape codes.
 */
function renderFindingLine(finding) {
  return `- **[${finding.severity}] ${finding.ruleId}** ${finding.file}:${finding.line} — ${finding.message} (confidence: ${finding.confidence})`;
}

/** Diagnostics listed in the markdown report before the rest are summarized as a count. */
const MAX_LISTED_DIAGNOSTICS = 10;

/**
 * Formats a `ScanResult` into a markdown report: a headline line leading
 * with the A-F health grade + status word (e.g. `**Grade: F — Critical**
 * (Ship Score 18/100 — blocked)`), followed by the existing band/verdict/
 * critical/high-count lines unchanged; a ranked findings list (findings
 * arrive pre-sorted by severity from `runDetectors()` — see src/index.ts,
 * this function does not re-sort); a note when `scanIncomplete` is true; and
 * the pipeline warnings (`result.diagnostics`).
 */
function formatMarkdown(result) {
  const { score } = result;
  const lines = [
    `**Grade: ${score.grade} — ${score.gradeLabel}** (Ship Score ${score.score}/100 — ${score.verdict})`,
    "",
    `## Ship Score: ${score.score}/100 — ${score.band}`,
    "",
    `**Verdict:** ${score.verdict}`,
    `**Critical:** ${score.criticalCount}  **High:** ${score.highCount}`,
    "",
  ];

  if (result.findings.length === 0) {
    lines.push("No findings.");
  } else {
    lines.push("### Findings (ranked by severity)", "");
    for (const finding of result.findings) {
      lines.push(renderFindingLine(finding));
    }
  }

  if (result.scanIncomplete) {
    lines.push(
      "",
      "> **Note:** this scan is incomplete — coverage was reduced (see warnings below), so the score may be optimistic.",
    );
  }

  const diagnostics = result.diagnostics ?? [];
  if (diagnostics.length > 0) {
    lines.push("", `### Warnings (${diagnostics.length})`, "");
    for (const diagnostic of diagnostics.slice(0, MAX_LISTED_DIAGNOSTICS)) {
      lines.push(`- \`${diagnostic.code}\` ${diagnostic.message}`);
    }
    if (diagnostics.length > MAX_LISTED_DIAGNOSTICS) {
      lines.push(`- ... and ${diagnostics.length - MAX_LISTED_DIAGNOSTICS} more`);
    }
  }

  return lines.join("\n");
}

/**
 * Runs one skill scan action: lazily resolves `scan()` via `loadScan()`,
 * calls it exactly once as `scan(target, { ...options, noLlm: true })`, and
 * formats the result. `options` is OPTIONAL and defaults to `{}`. Caller
 * flags (`authorize` / `allowPrivate` for live-URL screening, ...) are
 * forwarded unmodified; the only thing this wrapper adds is `noLlm: true`
 * (see module doc comment on determinism).
 *
 * Returns `{ markdown, score, count }` as a plain object — NOT a stdout
 * string — so the parity test (tests/dist/skill-parity.test.mjs) can assert
 * on the exact `score`/`count` numbers directly instead of parsing rendered
 * text. `score` is `result.score.score` (the 0-100 Ship Score); `count` is
 * `result.findings.length` (total finding count) — the two numbers parity
 * is defined over.
 */
export async function runScanSkill(target, options = {}) {
  const scan = await loadScan();
  const result = await scan(target, { ...options, noLlm: true });
  return {
    markdown: formatMarkdown(result),
    score: result.score.score,
    count: result.findings.length,
  };
}

/**
 * Parses `process.argv.slice(2)` for the CLI entry guard below: the first
 * non-flag argument is the scan target (a local path OR an `http(s)://`
 * URL), defaulting to `.` when omitted. `--authorize`, `--allow-private`,
 * `--offline`, `--no-ignore`, `--no-data-probes` and `--min-severity <level>`
 * (or `--min-severity=<level>`) map to the matching scan options (only set
 * when present,
 * mirroring bin/immunogen.ts's own conditional-inclusion pattern). Any other
 * flag-shaped argument (starting with `-`) is ignored rather than
 * mis-parsed as the target.
 */
const MIN_SEVERITIES = new Set(["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]);

function parseArgs(argv) {
  let target;
  const options = {};

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv.at(index) ?? "";
    if (arg === "--authorize") {
      options.authorize = true;
    } else if (arg === "--allow-private") {
      options.allowPrivate = true;
    } else if (arg === "--offline") {
      options.offline = true;
    } else if (arg === "--no-ignore") {
      options.noIgnore = true;
    } else if (arg === "--no-data-probes") {
      options.dataProbes = false;
    } else if (arg === "--min-severity" || arg.startsWith("--min-severity=")) {
      const value = (arg.includes("=") ? arg.slice(arg.indexOf("=") + 1) : argv.at((index += 1)) ?? "").toUpperCase();
      if (MIN_SEVERITIES.has(value)) {
        options.minSeverity = value;
      }
    } else if (!arg.startsWith("-") && target === undefined) {
      target = arg;
    }
  }

  return { target: target ?? ".", options };
}

// CLI entry guard — only runs when this file is executed directly (as
// `node .claude/skills/immunogen/scan.mjs <path-or-url> [--authorize]
// [--allow-private]`), not when imported as a module (e.g. by the
// skill-parity test, which imports only `runScanSkill` and must not trigger
// a second stdout-printing scan). Compared via realpath so a SYMLINKED
// install (`~/.claude/skills/immunogen` → the repo) still triggers: Node
// sets `import.meta.url` to this file's realpath, while `process.argv[1]` is
// the (possibly symlinked) invocation path, so the two only match after
// resolving argv[1]'s real path.
const invokedDirectly =
  process.argv[1] !== undefined &&
  // eslint-disable-next-line security/detect-non-literal-fs-filename -- resolves this script's own invocation path from argv, never scanned content
  fileURLToPath(import.meta.url) === realpathSync(process.argv[1]);
if (invokedDirectly) {
  const { target, options } = parseArgs(process.argv.slice(2));

  try {
    const { markdown } = await runScanSkill(target, options);
    process.stdout.write(`${markdown}\n`);
  } catch (err) {
    // Surface the consent gate (and any other scan()-thrown error, e.g. a
    // bad path) as a single clean stderr line, never a raw stack trace —
    // mirrors bin/immunogen.ts's own try/catch around scan().
    const message = err instanceof Error ? err.message : String(err);
    process.stderr.write(`immunogen: ${message}\n`);
    process.exitCode = 2;
  }
}

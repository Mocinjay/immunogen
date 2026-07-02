/**
 * immunogen Claude Code skill wrapper.
 *
 * Thin caller only — no detection/scoring logic lives here. This module
 * imports the single `scan()` export from the BUILT dist
 * (`../../../dist/index.js`, the ESM entry produced by `pnpm run build`)
 * and does exactly one thing beyond that: it formats the returned
 * `ScanResult` into markdown for a Claude Code conversation to present
 * verbatim (.planning/research/ARCHITECTURE.md "Pattern 3: Library-First,
 * CLI-as-Thin-Wrapper" — the skill and the CLI are siblings, both thin
 * callers of the same `scan()`).
 *
 * Determinism / offline-by-default (T-08-12, T-08-13): `runScanSkill` calls
 * `scan(target)` with NO options object at all — it never reads or forwards
 * any provider/LLM environment variable, and never passes `noLlm` either
 * way. `scan()`'s own default (src/index.ts) is to use `selectAdapter(env)`,
 * which resolves to the offline `NoopAdapter` unless a provider + key are
 * BOTH already configured in the ambient environment — this wrapper does
 * not change that default in either direction, it just doesn't touch it.
 * This keeps every distribution path (CLI, skill, Docker) on the same
 * deterministic scan by construction, which is what the skill-parity test
 * (tests/dist/skill-parity.test.mjs) proves.
 *
 * ENG-05 (never execute scanned content): this file only calls `scan()`
 * (which itself never requires/imports/evals scanned repo content — see
 * src/index.ts's own doc comment) and then does plain string formatting of
 * the returned data. There is no `eval`, no `child_process`, and no
 * `require()` of anything derived from the scanned target anywhere in this
 * file.
 */
import { scan } from "../../../dist/index.js";

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

/**
 * Formats a `ScanResult` into a markdown report: a header line with the
 * Ship Score (`score.score`/100), band, verdict, and critical/high counts;
 * a ranked findings list (findings arrive pre-sorted by severity from
 * `runDetectors()` — see src/index.ts, this function does not re-sort);
 * and a trailing note when `scanIncomplete` is true (the OSV-offline
 * fallback fired, per src/index.ts's DEP-OFFLINE sentinel).
 */
function formatMarkdown(result) {
  const { score } = result;
  const lines = [
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
      "> **Note:** this scan is incomplete — the offline dependency-vulnerability list was used because OSV.dev was unreachable. Re-run with network access for a complete dependency check.",
    );
  }

  return lines.join("\n");
}

/**
 * Runs one skill scan action: calls `scan(target)` exactly once (no
 * options — see module doc comment for why) and formats the result. Returns
 * `{ markdown, score, count }` as a plain object — NOT a stdout string —
 * so the parity test (tests/dist/skill-parity.test.mjs) can assert on the
 * exact `score`/`count` numbers directly instead of parsing rendered text.
 * `score` is `result.score.score` (the 0-100 Ship Score); `count` is
 * `result.findings.length` (total finding count) — the two numbers parity
 * is defined over (see PLAN.md critical_facts #3).
 */
export async function runScanSkill(target) {
  const result = await scan(target);
  return {
    markdown: formatMarkdown(result),
    score: result.score.score,
    count: result.findings.length,
  };
}

// CLI entry guard — only runs when this file is executed directly (as
// `node .claude/skills/immunogen/scan.mjs <path>`), not when imported as a
// module (e.g. by the skill-parity test, which imports only
// `runScanSkill` and must not trigger a second stdout-printing scan).
if (import.meta.url === `file://${process.argv[1]}`) {
  const target = process.argv[2] ?? ".";
  const { markdown } = await runScanSkill(target);
  process.stdout.write(`${markdown}\n`);
}

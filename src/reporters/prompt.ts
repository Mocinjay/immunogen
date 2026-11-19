/**
 * Prompt reporter (`--format prompt`) — a deterministic, copy-paste fix-it
 * brief for the coding agent that wrote the code (Claude Code, Cursor,
 * Copilot, ...). No LLM is involved: it is the scan result, reordered into
 * numbered tasks with file:line locations and the remediation for each.
 *
 * Untrusted text discipline: the brief is meant to be pasted into an agent,
 * so scanned-repo text is kept out of it as far as possible. File paths are
 * stripped of control characters and backticks and shown as code; matched
 * snippets are included only where they are short, already-masked values
 * (secrets, table names), never AI-layer text — that text may itself be a
 * prompt injection.
 */
import { groupFindings, messageTemplate, remediationTemplate } from "./group.js";
import { sanitize } from "./terminal.js";

import type { Reporter } from "./interface.js";

import type { Category, Finding, ScanResult } from "../core/types.js";

/** Most problem groups written into one brief (the rest are counted). */
const MAX_GROUPS = 40;

/** Locations listed per group. */
const MAX_LOCATIONS = 15;

/** Categories whose (masked, short) matched text helps the agent find the spot. */
const SNIPPET_CATEGORIES: ReadonlySet<Category> = new Set(["secrets", "auth", "storage", "client-exposure"]);

/** Longest matched snippet echoed. */
const MAX_SNIPPET_CHARS = 60;

/** Inline-code text: control characters and backticks removed. */
function code(text: string): string {
  return `\`${sanitize(text).replaceAll("`", "'")}\``;
}

/** One location bullet. */
function location(finding: Finding): string {
  const snippet =
    finding.matchedText !== undefined && SNIPPET_CATEGORIES.has(finding.category) && finding.matchedText.length <= MAX_SNIPPET_CHARS
      ? ` (${code(finding.matchedText)})`
      : "";
  return `- ${code(`${finding.file}:${String(finding.line)}`)}${snippet}`;
}

/** One numbered task for a group of identical problems. */
function task(group: readonly Finding[], index: number): string {
  const [first] = group;
  if (first === undefined) {
    return "";
  }
  const message = group.length > 1 ? messageTemplate(first) : first.message;
  const lines = [
    `### ${String(index + 1)}. ${first.severity} — ${sanitize(first.ruleId)}: ${sanitize(message)}`,
    "",
    group.length > 1 ? `Where (${String(group.length)} places):` : "Where:",
    ...group.slice(0, MAX_LOCATIONS).map(location),
  ];
  if (group.length > MAX_LOCATIONS) {
    lines.push(`- ...and ${String(group.length - MAX_LOCATIONS)} more — run \`immunogen --format json\` for the full list`);
  }
  lines.push("", `Fix: ${sanitize(group.length > 1 ? remediationTemplate(first) : first.remediation)}`);
  return lines.join("\n");
}

export const promptReporter: Reporter = {
  render(result: ScanResult): string {
    const actionable = result.findings.filter((finding) => finding.severity !== "INFO");
    const { score } = result;
    if (actionable.length === 0) {
      return `immunogen found nothing to fix (Ship Score ${String(score.score)}/100, grade ${score.grade}).\n`;
    }
    const groups = groupFindings(actionable);
    const leakedSecrets = actionable.some((finding) => finding.category === "secrets" || finding.category === "client-exposure");
    const sections = [
      `The immunogen security scanner found ${String(actionable.length)} problem(s) in this project (Ship Score ${String(score.score)}/100, grade ${score.grade}, verdict ${score.verdict}). Please fix them, most severe first.`,
      [
        "Rules for this work:",
        "- Make the smallest change that fixes each problem, and keep the app working; run the tests after each fix.",
        "- Do not silence a finding with an `immunogen-ignore` comment unless the code is genuinely safe — if so, say why in that comment.",
        "- Never print, paste or commit secret values; read them from environment variables instead.",
        ...(leakedSecrets
          ? ["- Removing a leaked key from the code does not revoke it: list every exposed credential at the end so I can rotate it."]
          : []),
      ].join("\n"),
      ...groups.slice(0, MAX_GROUPS).map(task),
    ];
    if (groups.length > MAX_GROUPS) {
      sections.push(`(${String(groups.length - MAX_GROUPS)} more problem group(s) not shown — fix these first, then re-run the scan.)`);
    }
    if (result.scanIncomplete) {
      sections.push("Note: this scan was incomplete (see the scanner's warnings), so other problems may remain.");
    }
    sections.push("When you are done, re-run `immunogen` and confirm these findings are gone.");
    return `${sections.join("\n\n")}\n`;
  },
};

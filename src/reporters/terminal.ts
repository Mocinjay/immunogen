/**
 * Human-readable reporter (OUT-01) — renders a `ScanResult` as a colored
 * terminal report: a header (Ship Score, band, verdict, critical/high
 * counts) followed by one block per finding (severity, ruleId, `file:line`,
 * message, inline confidence tag, the already-masked `matchedText` when
 * present, and — only if present — the LLM-generated `fixPrompt`).
 *
 * Secret safety (threat T-04-02, T-07-10): `matchedText` arrives already
 * masked from the detector layer (Plan 01), and `fixPrompt` — when present —
 * arrives already redacted from the enricher (Phase 7, SAFE-01 gate). This
 * module echoes both verbatim and NEVER transforms, expands, or un-masks
 * either — there is no un-masking/un-redaction logic anywhere in this file.
 *
 * Uses picocolors (CLAUDE.md stack decision) — not the larger alternative
 * color library this project's STACK.md explicitly rejected. `render` is
 * pure: it writes nothing to the terminal directly and never terminates
 * the host process; the CLI layer owns writing the returned string to
 * stdout.
 *
 * Pass 2 addition: the header now leads with a target line reading
 * "Screened <url>" for a live-URL scan (`result.target` is an http(s)://
 * URL, per `isUrl` from `src/web/url-resolver.ts`) or "Scanned <path>" for
 * the static file/dir/git/zip path — a small, non-structural touch so a
 * URL screen's terminal output doesn't read like a directory scan.
 */
import pc from "picocolors";

import type { Reporter } from "./interface.js";

import { isUrl } from "../web/url-resolver.js";

import type { Confidence, Finding, ScanResult, Severity, Verdict } from "../core/types.js";

/** Bands/verdicts that read as "safe" — rendered green. */
const SAFE_BANDS = new Set(["Ready to ship", "Low risk"]);

/** Colors the band label green when safe, red when in/near the blocked range. */
function colorBand(band: string): string {
  return SAFE_BANDS.has(band) ? pc.green(band) : pc.red(band);
}

/** Colors the verdict green for "pass", red for "blocked". */
function colorVerdict(verdict: Verdict): string {
  return verdict === "pass" ? pc.green(verdict) : pc.red(verdict);
}

/** Per-severity color function, used to highlight each finding's severity label. */
const SEVERITY_COLOR: Record<Severity, (text: string) => string> = {
  CRITICAL: pc.red,
  HIGH: pc.red,
  MEDIUM: pc.yellow,
  LOW: pc.gray,
  INFO: pc.gray,
};

/** Colors `severity` using its dedicated formatter from `SEVERITY_COLOR`. */
function colorSeverity(severity: Severity): string {
  // eslint-disable-next-line security/detect-object-injection -- `severity` is typed as the closed `Severity` string-literal union from core/types.ts, never arbitrary scanned-repo content
  return SEVERITY_COLOR[severity](severity);
}

/** Renders the `[confidence: HIGH|MEDIUM|LOW]` inline tag for a finding. */
function confidenceTag(confidence: Confidence): string {
  return pc.dim(`[confidence: ${confidence}]`);
}

/**
 * Renders one finding as a multi-line block: severity + ruleId, the
 * `file:line` location, the message, the inline confidence tag, and — only
 * when present — a line echoing `finding.matchedText` and/or a dimmed
 * `fix prompt:` block echoing `finding.fixPrompt`, both exactly as received.
 */
function renderFinding(finding: Finding): string {
  const lines = [
    `  ${colorSeverity(finding.severity)} ${pc.bold(finding.ruleId)} ${pc.cyan(`${finding.file}:${finding.line}`)}`,
    `    ${finding.message} ${confidenceTag(finding.confidence)}`,
  ];
  if (finding.matchedText !== undefined) {
    // Echoed verbatim — already masked upstream; never un-masked or transformed here.
    lines.push(`    matched: ${finding.matchedText}`);
  }
  if (finding.fixPrompt !== undefined) {
    // Echoed verbatim — already redacted upstream by the enricher (SAFE-01);
    // never un-redacted or transformed here.
    lines.push(`    ${pc.dim("fix prompt:")} ${finding.fixPrompt}`);
  }
  return lines.join("\n");
}

/** Renders the target line: "Screened <url>" for a live-URL scan, "Scanned <path>" otherwise. */
function renderTargetLine(target: string): string {
  const verb = isUrl(target) ? "Screened" : "Scanned";
  return `${pc.bold(verb)}: ${target}`;
}

/** Renders the header block: target line, Ship Score, band, verdict, critical/high counts. */
function renderHeader(result: ScanResult): string {
  const { score } = result;
  return [
    renderTargetLine(result.target),
    `${pc.bold("Ship Score:")} ${pc.bold(String(score.score))}/100 — ${colorBand(score.band)}`,
    `${pc.bold("Verdict:")} ${colorVerdict(score.verdict)}`,
    `${pc.bold("Critical:")} ${score.criticalCount}  ${pc.bold("High:")} ${score.highCount}`,
  ].join("\n");
}

export const terminalReporter: Reporter = {
  render(result: ScanResult): string {
    const header = renderHeader(result);

    if (result.findings.length === 0) {
      return [header, "", pc.green("No findings.")].join("\n");
    }

    const findingBlocks = result.findings.map(renderFinding).join("\n\n");
    return [header, "", findingBlocks].join("\n");
  },
};

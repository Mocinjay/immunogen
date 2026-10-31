/**
 * Human-readable reporter (OUT-01) — renders a `ScanResult` as a colored
 * terminal report: a header (headline A-F grade banner, Ship Score, band,
 * verdict, critical/high counts) followed by one block per finding
 * (severity, ruleId, `file:line`, message, inline confidence tag, the
 * already-masked `matchedText` when present, and — only if present — the
 * LLM-generated `fixPrompt`). The grade banner is an additive headline
 * rating layered above the existing Ship Score line — the score line, band,
 * and verdict are unchanged.
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
 * The header leads with "Screened <url>" for a live-URL scan or "Scanned
 * <path>" otherwise. A reduced-coverage scan (`scanIncomplete`) gets a
 * banner directly under the verdict, and every pipeline diagnostic is
 * summarized in a closing "Warnings" block, so a partial scan never reads
 * as a clean one.
 *
 * Terminal safety: file names, matched snippets, messages built from
 * scanned content, and LLM output are all attacker-influenced. Every such
 * string goes through `sanitize()`, which strips C0/C1 control characters
 * (ESC, CSI, OSC, BEL, ...) so a crafted filename or model response cannot
 * clear the screen, rewrite earlier lines, or plant terminal hyperlinks.
 */
import pc from "picocolors";

import type { Reporter } from "./interface.js";

import { isUrl } from "../web/url-resolver.js";

import type { Confidence, Diagnostic, Finding, Grade, ScanResult, Severity, Verdict } from "../core/types.js";

/** C0 controls except TAB/LF, DEL, and C1 controls — everything a terminal interprets as a command. */
const CONTROL_CHARS_RE = /[\u0000-\u0008\u000B-\u001F\u007F-\u009F]/g;

/** Strips control characters from multi-line untrusted text (LLM output), keeping line breaks. */
export function sanitizeMultiline(text: string): string {
  return text.replace(CONTROL_CHARS_RE, "");
}

/** Strips control characters from a single-line field and folds newlines, so a crafted name cannot forge report lines. */
export function sanitize(text: string): string {
  return sanitizeMultiline(text).replace(/[\n\t]+/g, " ");
}

/** Diagnostics listed per code before the rest are summarized as a count. */
const MAX_DIAGNOSTICS_PER_CODE = 3;

/** Bands/verdicts that read as "safe" — rendered green. */
const SAFE_BANDS = new Set(["Ready to ship", "Low risk"]);

/** Colors the band label green when safe, red when in/near the blocked range. */
function colorBand(band: string): string {
  return SAFE_BANDS.has(band) ? pc.green(band) : pc.red(band);
}

/**
 * Per-grade color function for the headline A-F banner — A/B green
 * ("healthy"), C amber/yellow ("symptomatic"), D a warmer red-orange
 * ("infected"), F plain red ("critical"). Reuses picocolors exclusively
 * (no new dependency); `pc.redBright` stands in for an "orange-ish" tone
 * since picocolors has no dedicated orange.
 */
const GRADE_COLOR: Record<Grade, (text: string) => string> = {
  A: pc.green,
  B: pc.green,
  C: pc.yellow,
  D: pc.redBright,
  F: pc.red,
};

/** Colors `grade` using its dedicated formatter from `GRADE_COLOR`. */
function colorGrade(grade: Grade): string {
  // eslint-disable-next-line security/detect-object-injection -- `grade` is typed as the closed `Grade` string-literal union from core/types.ts, never arbitrary scanned-repo content
  return GRADE_COLOR[grade](grade);
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
    `  ${colorSeverity(finding.severity)} ${pc.bold(sanitize(finding.ruleId))} ${pc.cyan(sanitize(`${finding.file}:${String(finding.line)}`))}`,
    `    ${sanitize(finding.message)} ${confidenceTag(finding.confidence)}`,
  ];
  if (finding.matchedText !== undefined) {
    // Already masked upstream; only control characters are stripped here.
    lines.push(`    matched: ${sanitize(finding.matchedText)}`);
  }
  if (finding.fixPrompt !== undefined) {
    // Already redacted upstream by the enricher; only control characters are stripped here.
    lines.push(`    ${pc.dim("fix prompt:")} ${sanitizeMultiline(finding.fixPrompt)}`);
  }
  return lines.join("\n");
}

/** Renders the closing warnings block: each diagnostic code with its count and a few examples. */
function renderDiagnostics(diagnostics: readonly Diagnostic[]): string {
  const byCode = new Map<string, Diagnostic[]>();
  for (const diagnostic of diagnostics) {
    const group = byCode.get(diagnostic.code) ?? [];
    group.push(diagnostic);
    byCode.set(diagnostic.code, group);
  }
  const lines = [pc.yellow(pc.bold(`Warnings (${String(diagnostics.length)}):`))];
  for (const [code, group] of byCode) {
    lines.push(`  ${pc.yellow(sanitize(code))}${group.length > 1 ? pc.dim(` x${String(group.length)}`) : ""}`);
    for (const diagnostic of group.slice(0, MAX_DIAGNOSTICS_PER_CODE)) {
      lines.push(`    ${sanitize(diagnostic.message)}`);
    }
    if (group.length > MAX_DIAGNOSTICS_PER_CODE) {
      lines.push(pc.dim(`    ... and ${String(group.length - MAX_DIAGNOSTICS_PER_CODE)} more (use --format json for the full list)`));
    }
  }
  return lines.join("\n");
}

/** Renders the target line: "Screened <url>" for a live-URL scan, "Scanned <path>" otherwise. */
function renderTargetLine(target: string): string {
  const verb = isUrl(target) ? "Screened" : "Scanned";
  return `${pc.bold(verb)}: ${sanitize(target)}`;
}

/**
 * Renders the headline A-F grade banner — `GRADE: F — Critical` — as the
 * lead line of the report, ABOVE the existing Ship Score line. This is an
 * additive headline rating on top of the numeric score; it does not
 * replace or reorder anything else already in the header.
 */
function renderGradeBanner(score: ScanResult["score"]): string {
  return `${pc.bold("GRADE:")} ${pc.bold(colorGrade(score.grade))} — ${score.gradeLabel}`;
}

/** Renders the header block: target line, grade banner, Ship Score, band, verdict, critical/high counts. */
function renderHeader(result: ScanResult): string {
  const { score } = result;
  const lines = [
    renderTargetLine(result.target),
    renderGradeBanner(score),
    `${pc.bold("Ship Score:")} ${pc.bold(String(score.score))}/100 — ${colorBand(score.band)}`,
    `${pc.bold("Verdict:")} ${colorVerdict(score.verdict)}`,
    `${pc.bold("Critical:")} ${String(score.criticalCount)}  ${pc.bold("High:")} ${String(score.highCount)}`,
  ];
  if (result.scanIncomplete) {
    lines.push(pc.yellow(pc.bold("Scan incomplete: coverage was reduced, so this score may be optimistic (see warnings).")));
  }
  return lines.join("\n");
}

export const terminalReporter: Reporter = {
  render(result: ScanResult): string {
    const sections = [renderHeader(result)];
    sections.push(
      result.findings.length === 0 ? pc.green("No findings.") : result.findings.map(renderFinding).join("\n\n"),
    );
    if (result.diagnostics.length > 0) {
      sections.push(renderDiagnostics(result.diagnostics));
    }
    return `${sections.join("\n\n")}\n`;
  },
};

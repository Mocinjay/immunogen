/**
 * Finding grouping shared by the human-facing reporters (terminal, prompt):
 * findings with the same severity, rule, confidence and message — ignoring
 * the per-item name the message embeds, such as a table or variable — are
 * one problem in several places, and read better as one entry.
 */
import type { Finding } from "../core/types.js";

/** True when `char` is part of an identifier (so a token next to it is not a whole token). */
function isWordChar(char: string): boolean {
  return /[A-Za-z0-9_]/.test(char);
}

/**
 * The message with the first whole-token occurrence of the finding's own
 * matched name (a table, a variable) replaced by `…`, so per-item variants
 * of one message group together. Unchanged when there is no such token.
 */
export function messageTemplate(finding: Finding): string {
  return blankFirstToken(finding.message, finding.matchedText);
}

/** `messageTemplate` for the remediation text, used when a group shows one fix for several places. */
export function remediationTemplate(finding: Finding): string {
  return blankFirstToken(finding.remediation, finding.matchedText);
}

/** `text` with the first whole-token occurrence of `token` replaced by `…`. */
function blankFirstToken(text: string, token: string | undefined): string {
  if (token === undefined || token.length === 0) {
    return text;
  }
  for (let index = text.indexOf(token); index !== -1; index = text.indexOf(token, index + 1)) {
    const end = index + token.length;
    if (!isWordChar(text.charAt(index - 1)) && !isWordChar(text.charAt(end))) {
      return `${text.slice(0, index)}…${text.slice(end)}`;
    }
  }
  return text;
}

/** Findings sharing severity, rule, confidence and message template, in first-seen (already sorted) order. */
export function groupFindings(findings: readonly Finding[]): Finding[][] {
  const groups = new Map<string, Finding[]>();
  for (const finding of findings) {
    const key = [finding.severity, finding.ruleId, finding.confidence, messageTemplate(finding)].join("\u0000");
    const group = groups.get(key);
    if (group === undefined) {
      groups.set(key, [finding]);
    } else {
      group.push(finding);
    }
  }
  return [...groups.values()];
}

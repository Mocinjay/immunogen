/**
 * Line-independent finding fingerprints, shared by the SARIF reporter
 * (`partialFingerprints.primaryLocationLineHash`) and baseline matching
 * (`ScanOptions.baseline`), so "the same finding" means the same thing in
 * both places.
 */
import { createHash } from "node:crypto";

import type { Finding } from "./types.js";

/** The finding fields that identify "the same problem" independent of where in the file it sits. */
function fingerprintKey(finding: Finding): string {
  return JSON.stringify([finding.ruleId, finding.file, finding.message, finding.matchedText ?? ""]);
}

/**
 * `partialFingerprints.primaryLocationLineHash` for every finding, in
 * `findings` order. The hash covers rule, file, message and the (masked)
 * matched snippet — never the line number — so an alert keeps its identity
 * when unrelated edits shift it up or down the file. Findings that share all
 * of those get an occurrence index (counted in line order) mixed in, so they
 * stay distinct. Only the scanner's own finding metadata is hashed.
 */
export function computeFingerprints(findings: readonly Finding[]): string[] {
  const indicesByKey = new Map<string, number[]>();
  for (const [index, finding] of findings.entries()) {
    const key = fingerprintKey(finding);
    const indices = indicesByKey.get(key);
    if (indices === undefined) {
      indicesByKey.set(key, [index]);
    } else {
      indices.push(index);
    }
  }

  const fingerprints = new Map<number, string>();
  for (const [key, indices] of indicesByKey) {
    const byLine = indices
      .map((index) => ({ index, line: findings.at(index)?.line ?? 0 }))
      .sort((a, b) => a.line - b.line || a.index - b.index);
    for (const [occurrence, { index }] of byLine.entries()) {
      fingerprints.set(index, createHash("sha256").update(`${key}\n${String(occurrence)}`).digest("hex"));
    }
  }
  return findings.map((_, index) => fingerprints.get(index) ?? "");
}


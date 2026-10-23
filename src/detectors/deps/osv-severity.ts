/**
 * osv-severity — maps a full OSV.dev vulnerability record to a Severity.
 *
 * OSV's batch endpoint (osv-client.ts `queryOsvBatch`) returns advisory ids
 * only, so DEP-01 used to rate every hit HIGH. The full record
 * (`GET /v1/vulns/{id}`) carries the real rating in one of two places:
 *
 *   1. `database_specific.severity` — GitHub's own rating on GHSA records
 *      (CRITICAL / HIGH / MODERATE / LOW); preferred when present.
 *   2. `severity[]` entries of type `CVSS_V3` holding a CVSS 3.x vector,
 *      scored here with the CVSS v3.1 base-score formula and banded by the
 *      standard qualitative ranges (9.0+ CRITICAL, 7.0+ HIGH, 4.0+ MEDIUM,
 *      0.1+ LOW).
 *
 * Anything else (no rating, a CVSS v2/v4-only record, malformed input)
 * yields `undefined`; the caller keeps its conservative HIGH default.
 *
 * Pure and dependency-free; never throws.
 */
import type { Severity } from "../../core/types.js";

/** CVSS v3 metric weights (FIRST CVSS v3.1 specification, section 7.4). */
const ATTACK_VECTOR: Record<string, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
const ATTACK_COMPLEXITY: Record<string, number> = { L: 0.77, H: 0.44 };
const PRIVILEGES_UNCHANGED: Record<string, number> = { N: 0.85, L: 0.62, H: 0.27 };
const PRIVILEGES_CHANGED: Record<string, number> = { N: 0.85, L: 0.68, H: 0.5 };
const USER_INTERACTION: Record<string, number> = { N: 0.85, R: 0.62 };
const IMPACT: Record<string, number> = { H: 0.56, L: 0.22, N: 0 };

/** CVSS v3.1 "Roundup": the smallest number with one decimal place that is >= the input (spec Appendix A). */
function roundUp(value: number): number {
  const scaled = Math.round(value * 100_000);
  return scaled % 10_000 === 0 ? scaled / 100_000 : (Math.floor(scaled / 10_000) + 1) / 10;
}

/** Reads one weight from a metric table, or undefined for a missing/unknown value. */
function weight(table: Record<string, number>, value: string | undefined): number | undefined {
  return value === undefined ? undefined : new Map(Object.entries(table)).get(value);
}

/** CVSS 3.0/3.1 base score for a vector like `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`, or undefined if malformed. */
export function cvss3BaseScore(vector: string): number | undefined {
  if (!/^CVSS:3\.[01]\//.test(vector)) {
    return undefined;
  }
  const metrics = new Map(
    vector
      .split("/")
      .slice(1)
      .map((part) => part.split(":") as [string, string]),
  );
  const scopeChanged = metrics.get("S") === "C";
  const av = weight(ATTACK_VECTOR, metrics.get("AV"));
  const ac = weight(ATTACK_COMPLEXITY, metrics.get("AC"));
  const pr = weight(scopeChanged ? PRIVILEGES_CHANGED : PRIVILEGES_UNCHANGED, metrics.get("PR"));
  const ui = weight(USER_INTERACTION, metrics.get("UI"));
  const c = weight(IMPACT, metrics.get("C"));
  const i = weight(IMPACT, metrics.get("I"));
  const a = weight(IMPACT, metrics.get("A"));
  if (av === undefined || ac === undefined || pr === undefined || ui === undefined || c === undefined || i === undefined || a === undefined) {
    return undefined;
  }

  const iss = 1 - (1 - c) * (1 - i) * (1 - a);
  const impact = scopeChanged ? 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 : 6.42 * iss;
  if (impact <= 0) {
    return 0;
  }
  const exploitability = 8.22 * av * ac * pr * ui;
  return scopeChanged ? roundUp(Math.min(1.08 * (impact + exploitability), 10)) : roundUp(Math.min(impact + exploitability, 10));
}

/** Qualitative severity band for a CVSS base score. */
export function severityForScore(score: number): Severity | undefined {
  if (score >= 9) {
    return "CRITICAL";
  }
  if (score >= 7) {
    return "HIGH";
  }
  if (score >= 4) {
    return "MEDIUM";
  }
  return score > 0 ? "LOW" : undefined;
}

/** GitHub advisory severity labels. */
const DATABASE_SEVERITY: Record<string, Severity> = {
  CRITICAL: "CRITICAL",
  HIGH: "HIGH",
  MODERATE: "MEDIUM",
  MEDIUM: "MEDIUM",
  LOW: "LOW",
};

/** Severity of an OSV vulnerability record (shape untrusted — see module doc), or undefined when it carries none. */
export function severityFromOsvRecord(record: unknown): Severity | undefined {
  if (typeof record !== "object" || record === null) {
    return undefined;
  }
  const candidate = record as { database_specific?: { severity?: unknown }; severity?: unknown };
  const label = candidate.database_specific?.severity;
  if (typeof label === "string") {
    const mapped = new Map(Object.entries(DATABASE_SEVERITY)).get(label.toUpperCase());
    if (mapped !== undefined) {
      return mapped;
    }
  }
  if (Array.isArray(candidate.severity)) {
    for (const entry of candidate.severity as unknown[]) {
      const rating = entry as { type?: unknown; score?: unknown };
      if (rating.type === "CVSS_V3" && typeof rating.score === "string") {
        const score = cvss3BaseScore(rating.score);
        if (score !== undefined) {
          return severityForScore(score);
        }
      }
    }
  }
  return undefined;
}

/** Rank used to pick the worst severity of a package's advisories. */
const SEVERITY_RANK: Record<Severity, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };

/** The most severe of `severities`, or undefined for an empty list. */
export function worstSeverity(severities: Severity[]): Severity | undefined {
  let worst: Severity | undefined;
  for (const severity of severities) {
    // eslint-disable-next-line security/detect-object-injection -- `severity` is the closed Severity union
    if (worst === undefined || SEVERITY_RANK[severity] > SEVERITY_RANK[worst]) {
      worst = severity;
    }
  }
  return worst;
}

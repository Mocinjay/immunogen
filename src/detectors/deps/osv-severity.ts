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

/** Fixed versions an OSV record lists for one affected package. */
export interface AffectedFix {
  ecosystem: string;
  name: string;
  fixed: string[];
}

/**
 * Every `affected[].ranges[].events[].fixed` version in an OSV record,
 * grouped by package. Malformed shapes contribute nothing (never throws).
 */
export function fixesFromOsvRecord(record: unknown): AffectedFix[] {
  if (typeof record !== "object" || record === null) {
    return [];
  }
  const affected = (record as { affected?: unknown }).affected;
  if (!Array.isArray(affected)) {
    return [];
  }
  const fixes: AffectedFix[] = [];
  for (const entry of affected as unknown[]) {
    const item = entry as { package?: { ecosystem?: unknown; name?: unknown }; ranges?: unknown };
    const ecosystem = item.package?.ecosystem;
    const name = item.package?.name;
    if (typeof ecosystem !== "string" || typeof name !== "string" || !Array.isArray(item.ranges)) {
      continue;
    }
    const fixed: string[] = [];
    for (const range of item.ranges as unknown[]) {
      const events = (range as { events?: unknown }).events;
      if (!Array.isArray(events)) {
        continue;
      }
      for (const event of events as unknown[]) {
        const value = (event as { fixed?: unknown }).fixed;
        if (typeof value === "string" && value.length > 0 && value.length < 64) {
          fixed.push(value);
        }
      }
    }
    if (fixed.length > 0) {
      fixes.push({ ecosystem, name, fixed });
    }
  }
  return fixes;
}

/**
 * Compares dotted numeric versions (`1.2.10` > `1.2.9`; a leading `v` is
 * ignored; a pre-release sorts before its release). Good enough to pick an
 * upgrade target across npm, PyPI and Go version strings.
 */
export function compareVersions(left: string, right: string): number {
  const split = (version: string): { parts: number[]; pre: boolean } => {
    const trimmed = version.trim().replace(/^v/i, "");
    const core = trimmed.split(/[-+]/, 1)[0] ?? "";
    return {
      parts: core.split(".").map((part) => Number.parseInt(part, 10) || 0),
      pre: /^[\d.]+-/.test(trimmed) || /[a-z]/i.test(core),
    };
  };
  const a = split(left);
  const b = split(right);
  for (let index = 0; index < Math.max(a.parts.length, b.parts.length); index += 1) {
    const delta = (a.parts.at(index) ?? 0) - (b.parts.at(index) ?? 0);
    if (delta !== 0) {
      return delta;
    }
  }
  return a.pre === b.pre ? 0 : a.pre ? -1 : 1;
}

/**
 * The version to upgrade `name@current` to so that every listed advisory is
 * fixed: for each advisory, the lowest fixed version above `current`; then
 * the highest of those. `undefined` when an advisory lists no applicable fix.
 */
export function upgradeTarget(
  name: string,
  ecosystem: string,
  current: string,
  fixesPerAdvisory: readonly (readonly AffectedFix[])[],
): string | undefined {
  let target: string | undefined;
  for (const fixes of fixesPerAdvisory) {
    const candidates = fixes
      .filter((fix) => fix.name === name && fix.ecosystem.toLowerCase() === ecosystem.toLowerCase())
      .flatMap((fix) => fix.fixed)
      .filter((version) => compareVersions(version, current) > 0)
      .sort(compareVersions);
    const lowest = candidates.at(0);
    if (lowest === undefined) {
      return undefined;
    }
    if (target === undefined || compareVersions(lowest, target) > 0) {
      target = lowest;
    }
  }
  return target;
}

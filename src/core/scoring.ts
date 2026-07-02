/**
 * Deterministic ScoringEngine — computes the 0–100 Ship Score from a scan's
 * `Finding[]`. SCORE-01 deliverable.
 *
 * Inverts SkillSpector's scoring direction: SkillSpector scores _risk_
 * (higher = worse); immunogen scores _ship-readiness_ (higher = safer). See
 * .planning/research/ARCHITECTURE.md ("Scoring Engine" section) for the
 * weight/cap formula this implements. That document's earlier draft used a
 * different, school-grade-style set of band names; src/core/types.ts since
 * LOCKED a separate, action-oriented set of labels (STATE.md Phase 02-01
 * decision) — this module classifies into those locked labels exclusively.
 *
 * `computeScore` is a pure function: no I/O, no timing or randomness calls,
 * no reliance on input order. The CRITICAL hard cap (threat T-04-06) and
 * overall determinism (threat T-04-05) are both enforced here and proven by
 * scoring.test.ts.
 */
import type { Band, Finding, Severity, ShipScore, Verdict } from "./types.js";

/** Per-severity point weight contributing to `rawPoints`. INFO contributes nothing. */
const SEVERITY_WEIGHTS: Record<Severity, number> = {
  CRITICAL: 50,
  HIGH: 25,
  MEDIUM: 10,
  LOW: 5,
  INFO: 0,
};

/** Risk floor applied when at least one CRITICAL finding is present — the critical hard cap (T-04-06). */
const CRITICAL_RISK_FLOOR = 80;

/** Maximum representable risk before inversion; also the score/risk clamp ceiling. */
const MAX_RISK = 100;

/** Inclusive lower score bound for the "Ready to ship" band. */
const BAND_READY_TO_SHIP_MIN = 90;

/** Inclusive lower score bound for the "Low risk" band. */
const BAND_LOW_RISK_MIN = 70;

/** Inclusive lower score bound for the "Moderate risk" band; also the verdict pass/blocked floor. */
const BAND_MODERATE_RISK_MIN = 40;

/**
 * Classifies a 0–100 score into one of the four LOCKED action-oriented
 * `Band` labels from types.ts. Thresholds mirror ARCHITECTURE.md's numeric
 * ranges (90/70/40) but map onto the action-oriented labels, never the
 * grade-style ones that document proposed.
 */
function bandFor(score: number): Band {
  if (score >= BAND_READY_TO_SHIP_MIN) {
    return "Ready to ship";
  }
  if (score >= BAND_LOW_RISK_MIN) {
    return "Low risk";
  }
  if (score >= BAND_MODERATE_RISK_MIN) {
    return "Moderate risk";
  }
  return "High risk";
}

/**
 * Computes the deterministic Ship Score for a scan's findings.
 *
 * Formula (ARCHITECTURE.md "Scoring Engine"):
 *   rawPoints  = sum of SEVERITY_WEIGHTS[finding.severity] across all findings
 *   hasCritical = at least one finding has severity "CRITICAL"
 *   cappedRisk = hasCritical ? max(rawPoints, 80) : min(rawPoints, 100)
 *   score      = 100 - cappedRisk   (inverted: 0 risk -> 100 Ship Score)
 *
 * The CRITICAL hard cap (criterion 3 / threat T-04-06) means cappedRisk is
 * floored at 80 whenever any CRITICAL finding exists, which floors `score`
 * at <= 20 regardless of how few other findings are present — well inside
 * the <= 25 acceptance bound. Verdict is "blocked" whenever a CRITICAL is
 * present OR the score falls into the "High risk" band (score < 40);
 * "pass" otherwise.
 *
 * Pure and order-independent: reduces and counts iterate `findings` without
 * depending on array order, and the function performs no I/O, timing, or
 * randomness (threat T-04-05) — calling this twice with the same findings,
 * in any order, returns a deep-equal `ShipScore`.
 */
export function computeScore(findings: Finding[]): ShipScore {
  let rawPoints = 0;
  let criticalCount = 0;
  let highCount = 0;

  for (const finding of findings) {
    rawPoints += SEVERITY_WEIGHTS[finding.severity];
    if (finding.severity === "CRITICAL") {
      criticalCount += 1;
    } else if (finding.severity === "HIGH") {
      highCount += 1;
    }
  }

  const hasCritical = criticalCount > 0;
  const cappedRisk = hasCritical
    ? Math.max(rawPoints, CRITICAL_RISK_FLOOR)
    : Math.min(rawPoints, MAX_RISK);

  const score = Math.round(Math.min(MAX_RISK, Math.max(0, MAX_RISK - cappedRisk)));
  const band = bandFor(score);
  const verdict: Verdict = hasCritical || score < BAND_MODERATE_RISK_MIN ? "blocked" : "pass";

  return { score, band, verdict, criticalCount, highCount };
}

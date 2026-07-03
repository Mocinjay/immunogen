/**
 * Compile-time-only assertions for the data contracts in `./types.ts`.
 *
 * This file contains NO runtime test cases. It is validated by
 * `pnpm typecheck` (`tsc --noEmit`) — not by vitest. There are no
 * `describe`/`it` blocks and no vitest import: the assertions ARE the test,
 * expressed entirely as constructs that must (or must not) type-check.
 *
 * Two halves:
 *   1. POSITIVE — one fully-valid value per contract, typed with `satisfies`
 *      so a future field rename to Finding/Detector/ScanResult/ShipScore
 *      breaks this file at compile time.
 *   2. NEGATIVE — each preceded by `// @ts-expect-error`, proving the
 *      construct on the next line is a genuine type error. If the construct
 *      ever stops being an error (e.g. a union is accidentally widened),
 *      `@ts-expect-error` itself becomes an unused-directive error and
 *      `pnpm typecheck` fails — that is what makes every negative assertion
 *      load-bearing rather than decorative.
 */

import type {
  Band,
  Confidence,
  Detector,
  Finding,
  ScanResult,
  ShipScore,
  Verdict,
} from "./types.js";

// ---------------------------------------------------------------------------
// POSITIVE assertions — valid shapes are accepted.
// ---------------------------------------------------------------------------

const validFinding = {
  ruleId: "SEC-01",
  category: "secrets",
  detectorName: "secrets-regex",
  file: "src/app.ts",
  line: 12,
  severity: "CRITICAL",
  confidence: "HIGH",
  message: "Hardcoded API key detected.",
  remediation: "Move the key to an environment variable.",
} satisfies Finding;
void validFinding;

const validDetector = {
  config: {
    name: "secrets-regex",
    category: "secrets",
    globs: ["**/*.ts"],
  },
  detect: async () => [],
} satisfies Detector;
void validDetector;

const validShipScore = {
  score: 92,
  band: "Ready to ship",
  verdict: "pass",
  criticalCount: 0,
  highCount: 0,
  grade: "A",
  gradeLabel: "Immune",
} satisfies ShipScore;
void validShipScore;

const validScanResult = {
  target: "/repo",
  scannedAt: "2026-06-20T00:00:00.000Z",
  stackHints: {
    frameworks: new Set<string>(),
    hasSupabase: false,
    hasFirebase: false,
    hasStripe: false,
    hasEnvFiles: false,
    hasMcpJson: false,
    hasClaudeSkills: false,
    hasCursorRules: false,
  },
  findings: [],
  score: validShipScore,
  llmEnriched: false,
  scanIncomplete: false,
} satisfies ScanResult;
void validScanResult;

// ---------------------------------------------------------------------------
// NEGATIVE assertions — invalid shapes MUST fail to compile.
// ---------------------------------------------------------------------------

// (a) Finding literal omitting the required `ruleId` field.
// @ts-expect-error -- Finding requires `ruleId`; omitting it must fail.
const findingMissingRuleId: Finding = {
  category: "secrets",
  detectorName: "secrets-regex",
  file: "src/app.ts",
  line: 12,
  severity: "CRITICAL",
  confidence: "HIGH",
  message: "Hardcoded API key detected.",
  remediation: "Move the key to an environment variable.",
};
void findingMissingRuleId;

// (b) Finding literal with a `severity` value outside the five-member Severity union.
const findingBadSeverity: Finding = {
  ruleId: "SEC-01",
  category: "secrets",
  detectorName: "secrets-regex",
  file: "src/app.ts",
  line: 12,
  // @ts-expect-error -- 'FATAL' is not a member of the closed Severity union.
  severity: "FATAL",
  confidence: "HIGH",
  message: "Hardcoded API key detected.",
  remediation: "Move the key to an environment variable.",
};
void findingBadSeverity;

// (c) 'VERY_HIGH' is not a member of the closed Confidence union (HIGH|MEDIUM|LOW).
// @ts-expect-error -- 'VERY_HIGH' is not a member of the closed Confidence union.
const badConfidence: Confidence = "VERY_HIGH";
void badConfidence;

// (d) 'Production' is the old grade-style label; the closed Band union is the
// action-oriented variant ('Ready to ship'|'Low risk'|'Moderate risk'|'High risk').
// @ts-expect-error -- 'Production' is the rejected grade-style label, not a Band member.
const badBand: Band = "Production";
void badBand;

// (e) 'failed' is not a member of the closed Verdict union ('pass'|'blocked').
// @ts-expect-error -- 'failed' is not a member of the closed Verdict union.
const badVerdict: Verdict = "failed";
void badVerdict;

// (f) Detector.detect must be ALWAYS async — a synchronous, non-Promise return
// must be rejected.
const syncDetector: Detector = {
  config: {
    name: "sync-detector",
    category: "secrets",
    globs: ["**/*.ts"],
  },
  // @ts-expect-error -- detect() must return Promise<Finding[]>, not a sync Finding[].
  detect: () => [],
};
void syncDetector;

// (g) Detector.detect must resolve to Finding[], not an unrelated element type.
const wrongReturnDetector: Detector = {
  config: {
    name: "wrong-return-detector",
    category: "secrets",
    globs: ["**/*.ts"],
  },
  // @ts-expect-error -- detect() must resolve to Promise<Finding[]>, not Promise<string[]>.
  detect: async () => ["not-a-finding"],
};
void wrongReturnDetector;

// (h) ScanResult literal missing the required `score` field.
// @ts-expect-error -- ScanResult requires `score`; omitting it must fail.
const scanResultMissingScore: ScanResult = {
  target: "/repo",
  scannedAt: "2026-06-20T00:00:00.000Z",
  stackHints: {
    frameworks: new Set<string>(),
    hasSupabase: false,
    hasFirebase: false,
    hasStripe: false,
    hasEnvFiles: false,
    hasMcpJson: false,
    hasClaudeSkills: false,
    hasCursorRules: false,
  },
  findings: [],
  llmEnriched: false,
  scanIncomplete: false,
};
void scanResultMissingScore;

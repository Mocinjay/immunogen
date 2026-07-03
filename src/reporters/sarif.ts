/**
 * SARIF 2.1.0 reporter (OUT-03) — serializes a `ScanResult` into a
 * GitHub-Code-Scanning-valid + VS-Code-valid SARIF 2.1.0 document, built
 * directly from `ScanResult.findings`.
 *
 * Mirrors `json.ts`'s reporter shape exactly: a pure `render(result): string`
 * that builds a plain serializable view (here, a `SarifLog`) then
 * `JSON.stringify`s it. Unlike `json.ts`, this reporter reshapes the data
 * into the SARIF object model rather than passing it through — but the
 * contract (pure, no I/O, `Reporter`-typed) is identical.
 *
 * `tool.driver.rules[]` is populated with exactly one entry per DISTINCT
 * `ruleId` present in `result.findings` (first-seen order preserved) so
 * GitHub Code Scanning's alert pages show rule NAMES, not bare IDs.
 * `partialFingerprints.primaryLocationLineHash` is set on EVERY result (a
 * sha256 of `ruleId + file + line`, computed via the `node:crypto` builtin)
 * so GitHub can dedupe the same finding across repeated scans.
 *
 * Findings arrive ALREADY masked and ALREADY sorted from the detector layer
 * (see `json.ts`'s precedent) — this reporter never unmasks, re-sorts, or
 * copies raw `matchedText` into the emitted document (T-06-03-01: only
 * `message` + `remediation` flow into `result.message.text`).
 *
 * ENG-05 / T-06-03-02: this module only reads plain `ScanResult` fields and
 * calls `JSON.stringify` + `crypto.createHash` on the scanner's OWN finding
 * metadata — it never imports a parser, never evals/requires/spawns, and
 * never re-decodes scanned content.
 */
import { createHash } from "node:crypto";

import type { Reporter } from "./interface.js";
import type {
  SarifLevel,
  SarifLocation,
  SarifLog,
  SarifReportingDescriptor,
  SarifResult,
  SarifRun,
} from "./sarif-types.js";

import type { Category, Finding, ScanResult, Severity } from "../core/types.js";

/** SARIF 2.1.0's published schema URI — pinned so consumers can validate against it. */
const SARIF_SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json";

/** The literal SARIF version this document declares conformance to. */
const SARIF_VERSION = "2.1.0" as const;

/** `tool.driver.name` — identifies immunogen as the producing tool. */
const DRIVER_NAME = "immunogen";

/**
 * Placeholder project URL for `tool.driver.informationUri`. A real published
 * repository URL can replace this constant later without touching any other
 * part of the reporter.
 */
const DRIVER_INFORMATION_URI = "https://github.com/immunogen-dev/immunogen";

/** Number of spaces used for `JSON.stringify`'s pretty-print indentation. */
const JSON_INDENT_SPACES = 2;

/**
 * Human-readable label for each closed `Category`, used to build a derived
 * rule name (never a bare echo of `ruleId`).
 */
const CATEGORY_LABELS: Record<Category, string> = {
  secrets: "Secret Exposure",
  "client-exposure": "Client-Exposed Secret",
  auth: "Authentication/Authorization",
  payment: "Payment Wiring",
  deps: "Vulnerable Dependency",
  injection: "Injection",
  "cors-headers": "CORS/Headers Misconfiguration",
  storage: "Storage Misconfiguration",
  legal: "Legal/Licensing",
  config: "Configuration",
  "ai-layer": "AI-Layer Risk",
  web: "Live Web Screening",
};

/**
 * GitHub Code Scanning's `properties["security-severity"]` numeric-string
 * bands, one per closed `Severity` member. Values are CVSS-style scores in
 * [0.0, 10.0] — GitHub buckets them into its own Critical/High/Medium/Low
 * display tiers.
 */
const SECURITY_SEVERITY_SCORE: Record<Severity, string> = {
  CRITICAL: "9.0",
  HIGH: "7.0",
  MEDIUM: "4.0",
  LOW: "2.0",
  INFO: "0.0",
};

/** Severity -> SARIF result level. */
const SEVERITY_TO_LEVEL: Record<Severity, SarifLevel> = {
  CRITICAL: "error",
  HIGH: "error",
  MEDIUM: "warning",
  LOW: "note",
  INFO: "note",
};

/** Maps a `Severity` to GitHub's `security-severity` numeric-string band. */
function mapSeverityToScore(severity: Severity): string {
  // eslint-disable-next-line security/detect-object-injection -- `severity` is typed as the closed `Severity` string-literal union from core/types.ts, never arbitrary scanned-repo content
  return SECURITY_SEVERITY_SCORE[severity];
}

/** Maps a `Severity` to a SARIF result `level`. */
function mapSeverityToLevel(severity: Severity): SarifLevel {
  // eslint-disable-next-line security/detect-object-injection -- `severity` is typed as the closed `Severity` string-literal union from core/types.ts, never arbitrary scanned-repo content
  return SEVERITY_TO_LEVEL[severity];
}

/**
 * Derives a human-readable rule `name` from a finding's `category` and
 * `detectorName` — deliberately distinct from the bare `ruleId` so GitHub's
 * alert pages and VS Code's Problems panel show something meaningful instead
 * of e.g. "SEC-01". Deterministic: the same (category, detectorName) pair
 * always derives the same name.
 */
function deriveRuleName(category: Category, detectorName: string): string {
  // eslint-disable-next-line security/detect-object-injection -- `category` is typed as the closed `Category` string-literal union from core/types.ts, never arbitrary scanned-repo content
  return `${CATEGORY_LABELS[category]} (${detectorName})`;
}

/**
 * Computes a deterministic sha256 hex digest over a finding's stable logical
 * location (`ruleId + " " + file + " " + line`) using the `node:crypto`
 * builtin. This hashes only the scanner's OWN finding metadata — never
 * scanned file content — satisfying ENG-05 / T-06-03-02. The same tuple
 * always yields the same hash, letting GitHub Code Scanning dedupe the same
 * finding across repeated scans.
 */
function computePrimaryLocationLineHash(ruleId: string, file: string, line: number): string {
  return createHash("sha256").update(`${ruleId} ${file} ${line}`).digest("hex");
}

/**
 * Builds `tool.driver.rules[]` — exactly one `SarifReportingDescriptor` per
 * DISTINCT `ruleId` in `findings`, in first-seen order. Returns both the
 * array and a `ruleId -> index` map so result mapping can set a matching
 * `ruleIndex` without a second pass.
 */
function buildRules(findings: readonly Finding[]): {
  rules: SarifReportingDescriptor[];
  ruleIndexByRuleId: Map<string, number>;
} {
  const rules: SarifReportingDescriptor[] = [];
  const ruleIndexByRuleId = new Map<string, number>();

  for (const finding of findings) {
    if (ruleIndexByRuleId.has(finding.ruleId)) continue;

    ruleIndexByRuleId.set(finding.ruleId, rules.length);
    rules.push({
      id: finding.ruleId,
      name: deriveRuleName(finding.category, finding.detectorName),
      shortDescription: { text: finding.message },
      properties: {
        "security-severity": mapSeverityToScore(finding.severity),
        tags: [finding.category],
      },
    });
  }

  return { rules, ruleIndexByRuleId };
}

/**
 * Maps a single `Finding` to a `SarifLocation`. Respects
 * `exactOptionalPropertyTypes` — `endLine` is only present on the region
 * object when the finding actually has one; it is never explicitly set to
 * `undefined`.
 */
function buildLocation(finding: Finding): SarifLocation {
  return {
    physicalLocation: {
      artifactLocation: { uri: finding.file },
      region:
        finding.endLine !== undefined
          ? { startLine: finding.line, endLine: finding.endLine }
          : { startLine: finding.line },
    },
  };
}

/**
 * Maps a single `Finding` to a `SarifResult`. `message.text` is built from
 * `finding.message` + `finding.remediation` only — `matchedText` is never
 * copied in, since it may carry (already-masked, but still best kept out of
 * a shared alert surface) matched content (T-06-03-01).
 */
function buildResult(finding: Finding, ruleIndexByRuleId: Map<string, number>): SarifResult {
  const ruleIndex = ruleIndexByRuleId.get(finding.ruleId);

  return {
    ruleId: finding.ruleId,
    ...(ruleIndex !== undefined ? { ruleIndex } : {}),
    level: mapSeverityToLevel(finding.severity),
    message: { text: `${finding.message} ${finding.remediation}`.trim() },
    locations: [buildLocation(finding)],
    partialFingerprints: {
      primaryLocationLineHash: computePrimaryLocationLineHash(
        finding.ruleId,
        finding.file,
        finding.line,
      ),
    },
  };
}

/**
 * Builds the single `SarifRun` this reporter always emits. `properties`
 * surfaces the headline A-F health grade (`score.grade`/`score.gradeLabel`)
 * in the existing SARIF properties bag — an additive touch so the grade
 * isn't lost when a caller consumes the SARIF document instead of terminal
 * or JSON output; it does not restructure any other part of the run.
 */
function buildRun(result: ScanResult): SarifRun {
  const { rules, ruleIndexByRuleId } = buildRules(result.findings);

  return {
    tool: {
      driver: {
        name: DRIVER_NAME,
        informationUri: DRIVER_INFORMATION_URI,
        rules,
      },
    },
    results: result.findings.map((finding) => buildResult(finding, ruleIndexByRuleId)),
    properties: {
      grade: result.score.grade,
      gradeLabel: result.score.gradeLabel,
    },
  };
}

export const sarifReporter: Reporter = {
  render(result: ScanResult): string {
    const log: SarifLog = {
      $schema: SARIF_SCHEMA_URI,
      version: SARIF_VERSION,
      runs: [buildRun(result)],
    };

    return JSON.stringify(log, null, JSON_INDENT_SPACES);
  },
};

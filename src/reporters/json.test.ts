import { describe, expect, it } from "vitest";

import { jsonReporter } from "./json.js";

import type { Finding, ScanResult } from "../core/types.js";

/** A single representative `Finding` literal, fully populated under strict mode. */
const SAMPLE_FINDING: Finding = {
  ruleId: "SEC-01",
  category: "secrets",
  detectorName: "secretsDetector",
  file: "src/config.ts",
  line: 12,
  severity: "CRITICAL",
  confidence: "HIGH",
  message: "Hardcoded API key detected",
  remediation: "Move the key to an environment variable.",
  matchedText: "sk_l****",
};

/** A complete `ScanResult` literal — frameworks is a real `Set`, mirroring runtime shape. */
function makeScanResult(overrides: Partial<ScanResult> = {}): ScanResult {
  return {
    target: "/repo/under/scan",
    scannedAt: "2026-06-21T00:00:00.000Z",
    stackHints: {
      frameworks: new Set(["next", "react"]),
      hasSupabase: false,
      hasFirebase: false,
      hasStripe: false,
      hasEnvFiles: true,
      hasMcpJson: false,
      hasClaudeSkills: false,
      hasCursorRules: false,
    },
    findings: [SAMPLE_FINDING],
    score: {
      score: 20,
      band: "High risk",
      verdict: "blocked",
      criticalCount: 1,
      highCount: 0,
      grade: "F",
      gradeLabel: "Critical",
    },
    llmEnriched: false,
    scanIncomplete: false,
    ...overrides,
  };
}

/** Matches any ANSI escape sequence — used to prove JSON output is colorless. */
const ANSI_ESCAPE_RE = /\[/;

describe("jsonReporter.render — valid, parseable JSON", () => {
  it("produces a string that JSON.parse does not throw on", () => {
    const result = makeScanResult();
    expect(() => {
      JSON.parse(jsonReporter.render(result));
    }).not.toThrow();
  });

  it("parses to an object with every top-level ScanResult key", () => {
    const result = makeScanResult();
    const parsed = JSON.parse(jsonReporter.render(result)) as Record<string, unknown>;

    expect(parsed).toHaveProperty("target", result.target);
    expect(parsed).toHaveProperty("scannedAt", result.scannedAt);
    expect(parsed).toHaveProperty("findings");
    expect(parsed).toHaveProperty("score");
    expect(parsed).toHaveProperty("stackHints");
    expect(parsed).toHaveProperty("llmEnriched", false);
    expect(parsed).toHaveProperty("scanIncomplete", false);
  });

  it("parses score with every ShipScore key", () => {
    const result = makeScanResult();
    const parsed = JSON.parse(jsonReporter.render(result)) as {
      score: Record<string, unknown>;
    };

    expect(parsed.score).toEqual({
      score: 20,
      band: "High risk",
      verdict: "blocked",
      criticalCount: 1,
      highCount: 0,
      grade: "F",
      gradeLabel: "Critical",
    });
  });

  it("includes the headline A-F grade and its status label in score", () => {
    const result = makeScanResult();
    const parsed = JSON.parse(jsonReporter.render(result)) as {
      score: { grade: string; gradeLabel: string };
    };

    expect(parsed.score.grade).toBe("F");
    expect(parsed.score.gradeLabel).toBe("Critical");
  });

  it("parses each finding with file/line/severity/confidence and the rest of the shape", () => {
    const result = makeScanResult();
    const parsed = JSON.parse(jsonReporter.render(result)) as {
      findings: Array<Record<string, unknown>>;
    };

    expect(parsed.findings).toHaveLength(1);
    expect(parsed.findings[0]).toMatchObject({
      ruleId: "SEC-01",
      category: "secrets",
      severity: "CRITICAL",
      confidence: "HIGH",
      file: "src/config.ts",
      line: 12,
      message: "Hardcoded API key detected",
      remediation: "Move the key to an environment variable.",
    });
  });
});

describe("jsonReporter.render — stackHints.frameworks Set serialization", () => {
  it("serializes the frameworks Set as a JSON array, not an empty object", () => {
    const result = makeScanResult();
    const parsed = JSON.parse(jsonReporter.render(result)) as {
      stackHints: { frameworks: unknown };
    };

    expect(Array.isArray(parsed.stackHints.frameworks)).toBe(true);
    expect(parsed.stackHints.frameworks).toEqual(["next", "react"]);
  });

  it("serializes an empty frameworks Set as an empty array", () => {
    const result = makeScanResult({
      stackHints: {
        frameworks: new Set(),
        hasSupabase: false,
        hasFirebase: false,
        hasStripe: false,
        hasEnvFiles: false,
        hasMcpJson: false,
        hasClaudeSkills: false,
        hasCursorRules: false,
      },
    });
    const parsed = JSON.parse(jsonReporter.render(result)) as {
      stackHints: { frameworks: unknown };
    };

    expect(parsed.stackHints.frameworks).toEqual([]);
  });
});

describe("jsonReporter.render — pure JSON, no mixed-in prose or color", () => {
  it("contains no ANSI escape sequences", () => {
    const result = makeScanResult();
    expect(ANSI_ESCAPE_RE.test(jsonReporter.render(result))).toBe(false);
  });

  it("the trimmed output starts with '{' and ends with '}' (no leading/trailing prose)", () => {
    const result = makeScanResult();
    const output = jsonReporter.render(result).trim();
    expect(output.startsWith("{")).toBe(true);
    expect(output.endsWith("}")).toBe(true);
  });

  it("does not alter or redact matchedText — passes it through verbatim", () => {
    const result = makeScanResult();
    const parsed = JSON.parse(jsonReporter.render(result)) as {
      findings: Array<{ matchedText?: string }>;
    };
    expect(parsed.findings[0]?.matchedText).toBe("sk_l****");
  });

  it("round-trips fixPrompt when present on a finding (Phase 7, LLM-01)", () => {
    const enrichedFinding: Finding = { ...SAMPLE_FINDING, fixPrompt: "FIX: rotate the leaked key immediately" };
    const result = makeScanResult({ findings: [enrichedFinding] });
    const parsed = JSON.parse(jsonReporter.render(result)) as {
      findings: Array<{ fixPrompt?: string }>;
    };
    expect(parsed.findings[0]?.fixPrompt).toBe("FIX: rotate the leaked key immediately");
  });
});

describe("jsonReporter.render — empty findings", () => {
  it("still produces valid JSON with an empty findings array", () => {
    const result = makeScanResult({ findings: [] });
    const parsed = JSON.parse(jsonReporter.render(result)) as { findings: unknown[] };
    expect(parsed.findings).toEqual([]);
  });
});

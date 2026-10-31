import { describe, expect, it } from "vitest";

import { jsonReporter } from "./json.js";
import { terminalReporter } from "./terminal.js";

import type { Finding, ScanResult } from "../core/types.js";

/** Matches any ANSI escape sequence — strips color codes so assertions are color-mode-independent. */
const ANSI_ESCAPE_RE = /\[[0-9;]*m/g;

/** Removes every ANSI escape sequence from `s`. */
function stripAnsi(s: string): string {
  return s.replace(ANSI_ESCAPE_RE, "");
}

/**
 * A live-looking full secret that must NEVER appear in any reporter output.
 * Used only in this test file — never placed into a `ScanResult` literal —
 * so its absence from the rendered output proves the reporter cannot leak
 * what it was never given, and only ever echoes the already-masked
 * `matchedText` it receives.
 */
const fullSecret = "sk_live_THISISAFULLSECRETVALUE";

/** A masked `matchedText` value, as the detector layer would emit it. */
const MASKED_MATCHED_TEXT = "sk_l****";

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
  matchedText: MASKED_MATCHED_TEXT,
};

const SECOND_FINDING: Finding = {
  ruleId: "AUTH-03",
  category: "auth",
  detectorName: "authDetector",
  file: "src/routes/admin.ts",
  line: 5,
  severity: "MEDIUM",
  confidence: "LOW",
  message: "Admin route missing an authorization check",
  remediation: "Add a role check before handling the request.",
};

/** A complete `ScanResult` literal — mirrors json.test.ts's fixture shape. */
function makeScanResult(overrides: Partial<ScanResult> = {}): ScanResult {
  return {
    target: "/repo/under/scan",
    scannedAt: "2026-06-21T00:00:00.000Z",
    stackHints: {
      frameworks: new Set(["next"]),
      hasSupabase: false,
      hasFirebase: false,
      hasStripe: false,
      hasEnvFiles: true,
      hasMcpJson: false,
      hasClaudeSkills: false,
      hasCursorRules: false,
    },
    findings: [SAMPLE_FINDING, SECOND_FINDING],
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
    diagnostics: [],
    ...overrides,
  };
}

describe("terminalReporter.render — target line", () => {
  it('renders "Scanned <path>" for a static directory target', () => {
    const result = makeScanResult({ target: "/repo/under/scan" });
    const output = stripAnsi(terminalReporter.render(result));

    expect(output).toContain("Scanned: /repo/under/scan");
  });

  it('renders "Screened <url>" for a live http(s):// URL target', () => {
    const result = makeScanResult({ target: "https://example.com" });
    const output = stripAnsi(terminalReporter.render(result));

    expect(output).toContain("Screened: https://example.com");
  });
});

describe("terminalReporter.render — score / band / verdict", () => {
  it("contains the Ship Score number, band label, and verdict after stripping ANSI", () => {
    const result = makeScanResult();
    const output = stripAnsi(terminalReporter.render(result));

    expect(output).toContain(String(result.score.score));
    expect(output).toContain(result.score.band);
    expect(output).toContain(result.score.verdict);
  });

  it("contains criticalCount and highCount in the summary", () => {
    const result = makeScanResult();
    const output = stripAnsi(terminalReporter.render(result));

    expect(output).toContain(String(result.score.criticalCount));
    expect(output).toContain(String(result.score.highCount));
  });
});

describe("terminalReporter.render — A-F grade banner (headline)", () => {
  it("contains the letter grade and its status label after stripping ANSI", () => {
    const result = makeScanResult();
    const output = stripAnsi(terminalReporter.render(result));

    expect(output).toContain("GRADE:");
    expect(output).toContain(result.score.grade);
    expect(output).toContain(result.score.gradeLabel);
  });

  it("renders the grade banner above the Ship Score line", () => {
    const result = makeScanResult();
    const output = stripAnsi(terminalReporter.render(result));

    const gradeLineIndex = output.indexOf("GRADE:");
    const scoreLineIndex = output.indexOf("Ship Score:");
    expect(gradeLineIndex).toBeGreaterThanOrEqual(0);
    expect(scoreLineIndex).toBeGreaterThan(gradeLineIndex);
  });

  it("still renders the existing Ship Score/band/verdict fields unchanged alongside the grade", () => {
    const result = makeScanResult();
    const output = stripAnsi(terminalReporter.render(result));

    expect(output).toContain(String(result.score.score));
    expect(output).toContain(result.score.band);
    expect(output).toContain(result.score.verdict);
  });
});

describe("terminalReporter.render — per-finding rendering", () => {
  it("contains each finding's file:line location after stripping ANSI", () => {
    const result = makeScanResult();
    const output = stripAnsi(terminalReporter.render(result));

    expect(output).toContain(`${SAMPLE_FINDING.file}:${SAMPLE_FINDING.line}`);
    expect(output).toContain(`${SECOND_FINDING.file}:${SECOND_FINDING.line}`);
  });

  it("contains each finding's confidence text inline", () => {
    const result = makeScanResult();
    const output = stripAnsi(terminalReporter.render(result));

    expect(output).toContain(SAMPLE_FINDING.confidence);
    expect(output).toContain(SECOND_FINDING.confidence);
  });

  it("contains each finding's severity", () => {
    const result = makeScanResult();
    const output = stripAnsi(terminalReporter.render(result));

    expect(output).toContain(SAMPLE_FINDING.severity);
    expect(output).toContain(SECOND_FINDING.severity);
  });

  it("contains each finding's message", () => {
    const result = makeScanResult();
    const output = stripAnsi(terminalReporter.render(result));

    expect(output).toContain(SAMPLE_FINDING.message);
    expect(output).toContain(SECOND_FINDING.message);
  });

  it("renders a 'No findings' line when findings is empty", () => {
    const result = makeScanResult({ findings: [] });
    const output = stripAnsi(terminalReporter.render(result));

    expect(output.toLowerCase()).toContain("no findings");
  });
});

describe("terminalReporter.render — secret safety", () => {
  it("echoes the masked matchedText verbatim", () => {
    const result = makeScanResult();
    const output = stripAnsi(terminalReporter.render(result));

    expect(output).toContain(MASKED_MATCHED_TEXT);
  });

  it("never contains a full unmasked secret — only the masked matchedText it was given", () => {
    const result = makeScanResult();
    const output = stripAnsi(terminalReporter.render(result));

    expect(output.includes(fullSecret)).toBe(false);
  });

  it("does not render a matchedText line for a finding that has none", () => {
    const result = makeScanResult();
    const output = stripAnsi(terminalReporter.render(result));

    // SECOND_FINDING has no matchedText; its absence from output for that
    // finding is implicitly proven by the full-secret-absence assertion
    // above combined with the fact SECOND_FINDING contributes no matched
    // text at all to render — this test asserts the renderer does not
    // crash or emit a stray "undefined" when matchedText is absent.
    expect(output).not.toContain("undefined");
  });
});

describe("terminalReporter.render — fixPrompt rendering", () => {
  it("contains the fixPrompt text when present on a finding", () => {
    const enrichedFinding: Finding = { ...SAMPLE_FINDING, fixPrompt: "FIX: rotate the leaked key immediately" };
    const result = makeScanResult({ findings: [enrichedFinding, SECOND_FINDING] });
    const output = stripAnsi(terminalReporter.render(result));

    expect(output).toContain("FIX: rotate the leaked key immediately");
    expect(output.toLowerCase()).toContain("fix prompt:");
  });

  it("omits the 'fix prompt:' label for a finding with no fixPrompt", () => {
    const result = makeScanResult();
    const output = stripAnsi(terminalReporter.render(result));

    expect(output.toLowerCase()).not.toContain("fix prompt:");
  });
});

describe("terminalReporter.render — color does not corrupt content", () => {
  it("stripping ANSI still leaves score, band, verdict, and every file:line present", () => {
    const result = makeScanResult();
    const raw = terminalReporter.render(result);
    const stripped = stripAnsi(raw);

    expect(stripped).toContain(String(result.score.score));
    expect(stripped).toContain(result.score.band);
    expect(stripped).toContain(result.score.verdict);
    for (const finding of result.findings) {
      expect(stripped).toContain(`${finding.file}:${finding.line}`);
    }
  });
});

describe("getReporter — format selection", () => {
  it('returns jsonReporter for "json"', async () => {
    const { getReporter } = await import("./index.js");
    expect(getReporter("json")).toBe(jsonReporter);
  });

  it('returns terminalReporter for "terminal"', async () => {
    const { getReporter } = await import("./index.js");
    expect(getReporter("terminal")).toBe(terminalReporter);
  });

  it("returns terminalReporter for undefined (default)", async () => {
    const { getReporter } = await import("./index.js");
    expect(getReporter(undefined)).toBe(terminalReporter);
  });
});

describe("terminalReporter — untrusted text cannot drive the terminal", () => {
  it("strips escape sequences and folds newlines in file names, messages, and matched text", () => {
    const hostile: Finding = {
      ...SAMPLE_FINDING,
      file: "src/\u001b[2Jevil\nFAKE LINE.ts",
      message: "bad \u001b]8;;https://attacker.example\u0007link\u001b]8;;\u0007",
      matchedText: "sk_l\u009b31m****",
    };

    const output = terminalReporter.render(makeScanResult({ findings: [hostile] }));

    expect(output).not.toContain("\u001b[2J");
    expect(output).not.toContain("\u001b]8;;");
    expect(output).not.toContain("\u0007");
    expect(output).not.toContain("\u009b");
    expect(output).toContain("src/[2Jevil FAKE LINE.ts");
  });

  it("keeps line breaks in an LLM fix prompt but strips its control characters", () => {
    const output = terminalReporter.render(
      makeScanResult({ findings: [{ ...SAMPLE_FINDING, fixPrompt: "step 1\nstep 2\u001b[A" }] }),
    );

    expect(output).toContain("step 1\nstep 2[A");
  });
});

describe("terminalReporter — degraded coverage is visible", () => {
  it("prints an incomplete-scan banner and a grouped warnings block", () => {
    const output = terminalReporter.render(
      makeScanResult({
        findings: [],
        scanIncomplete: true,
        diagnostics: [
          { level: "warn", code: "PARSE_WARN", message: "failed to parse a.ts", file: "a.ts" },
          { level: "warn", code: "PARSE_WARN", message: "failed to parse b.ts", file: "b.ts" },
          { level: "warn", code: "SCAN_TRUNCATED", message: "cap exceeded" },
        ],
      }),
    );

    expect(output).toContain("Scan incomplete");
    expect(output).toContain("Warnings (3):");
    expect(output).toContain("PARSE_WARN");
    expect(output).toContain("failed to parse b.ts");
    expect(output).toContain("SCAN_TRUNCATED");
  });

  it("ends with a newline so the shell prompt starts on its own line", () => {
    expect(terminalReporter.render(makeScanResult()).endsWith("\n")).toBe(true);
  });
});

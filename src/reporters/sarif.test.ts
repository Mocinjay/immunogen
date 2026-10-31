import { describe, expect, it } from "vitest";

import { sarifReporter } from "./sarif.js";

import type { SarifLog } from "./sarif-types.js";

import type { Finding, ScanResult } from "../core/types.js";

/** Matches any ANSI CSI escape sequence — used to prove output is colorless. */
const ANSI_ESCAPE_RE = /\x1b\[/;

/** A representative CRITICAL secrets Finding. */
const CRITICAL_FINDING: Finding = {
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

/** A second SEC-01 finding (same ruleId, different location) — proves rules[] dedup. */
const CRITICAL_FINDING_DUPLICATE_RULE: Finding = {
  ruleId: "SEC-01",
  category: "secrets",
  detectorName: "secretsDetector",
  file: "src/other.ts",
  line: 40,
  severity: "CRITICAL",
  confidence: "HIGH",
  message: "Hardcoded API key detected",
  remediation: "Move the key to an environment variable.",
  matchedText: "sk_o****",
};

/** A distinct-ruleId AI-layer finding — proves rules[] carries more than one entry. */
const AILAYER_FINDING: Finding = {
  ruleId: "AILAYER-03",
  category: "ai-layer",
  detectorName: "mcpPoisoningDetector",
  file: ".mcp.json",
  line: 8,
  severity: "HIGH",
  confidence: "MEDIUM",
  message: "Hidden instruction detected in MCP tool description",
  remediation: "Remove the hidden instruction from the tool description.",
};

/** A MEDIUM finding used to assert the warning/4.0+ severity band. */
const MEDIUM_FINDING: Finding = {
  ruleId: "CORS-01",
  category: "cors-headers",
  detectorName: "corsDetector",
  file: "src/server.ts",
  line: 5,
  severity: "MEDIUM",
  confidence: "MEDIUM",
  message: "Wildcard CORS origin detected",
  remediation: "Restrict Access-Control-Allow-Origin to known origins.",
};

/** A LOW finding used to assert the note/2.0+ severity band. */
const LOW_FINDING: Finding = {
  ruleId: "CFG-01",
  category: "config",
  detectorName: "configDetector",
  file: "src/app.ts",
  line: 3,
  severity: "LOW",
  confidence: "LOW",
  message: "Debug mode left enabled",
  remediation: "Disable debug mode before shipping.",
};

/** An INFO finding used to assert the note-or-none/low-score band. */
const INFO_FINDING: Finding = {
  ruleId: "INFO-01",
  category: "config",
  detectorName: "configDetector",
  file: "src/notes.ts",
  line: 1,
  severity: "INFO",
  confidence: "LOW",
  message: "Informational note",
  remediation: "No action required.",
};

/** A complete `ScanResult` literal, mirroring json.test.ts's factory. */
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
    findings: [CRITICAL_FINDING, CRITICAL_FINDING_DUPLICATE_RULE, AILAYER_FINDING],
    score: {
      score: 20,
      band: "High risk",
      verdict: "blocked",
      criticalCount: 2,
      highCount: 1,
      grade: "F",
      gradeLabel: "Critical",
    },
    llmEnriched: false,
    scanIncomplete: false,
    diagnostics: [],
    ...overrides,
  };
}

interface ParsedSarifResult {
  ruleId: string;
  ruleIndex?: number;
  level: string;
  message: { text: string };
  locations: Array<{
    physicalLocation: {
      artifactLocation: { uri: string };
      region: { startLine: number; endLine?: number };
    };
  }>;
  partialFingerprints: { primaryLocationLineHash: string };
}

interface ParsedSarifRule {
  id: string;
  name: string;
  shortDescription?: { text: string };
  properties?: { "security-severity"?: string; tags?: string[] };
}

interface ParsedSarifLog {
  $schema: string;
  version: string;
  runs: Array<{
    tool: { driver: { name: string; informationUri?: string; rules: ParsedSarifRule[] } };
    results: ParsedSarifResult[];
    properties?: { grade: string; gradeLabel: string };
  }>;
}

describe("sarifReporter.render — Test 1: top-level SARIF envelope", () => {
  it("produces a string that JSON.parse does not throw on, with correct $schema/version/runs", () => {
    const result = makeScanResult();
    let parsed: ParsedSarifLog;

    expect(() => {
      parsed = JSON.parse(sarifReporter.render(result)) as ParsedSarifLog;
    }).not.toThrow();

    parsed = JSON.parse(sarifReporter.render(result)) as ParsedSarifLog;
    expect(parsed.$schema).toBe("https://json.schemastore.org/sarif-2.1.0.json");
    expect(parsed.version).toBe("2.1.0");
    expect(parsed.runs).toHaveLength(1);
  });
});

describe("sarifReporter.render — Test 2: tool.driver.rules[] dedup + shape", () => {
  it("names the driver 'immunogen' and dedupes rules[] to one entry per distinct ruleId", () => {
    const result = makeScanResult();
    const parsed = JSON.parse(sarifReporter.render(result)) as ParsedSarifLog;
    const run = parsed.runs[0];
    expect(run).toBeDefined();
    if (!run) return;

    expect(run.tool.driver.name).toBe("immunogen");
    expect(run.tool.driver.rules).toHaveLength(2);

    const ids = run.tool.driver.rules.map((rule) => rule.id).sort();
    expect(ids).toEqual(["AILAYER-03", "SEC-01"]);
  });

  it("gives every rule a non-empty id, a non-empty derived name, and a numeric security-severity string", () => {
    const result = makeScanResult();
    const parsed = JSON.parse(sarifReporter.render(result)) as ParsedSarifLog;
    const run = parsed.runs[0];
    expect(run).toBeDefined();
    if (!run) return;

    for (const rule of run.tool.driver.rules) {
      expect(rule.id.length).toBeGreaterThan(0);
      expect(rule.name.length).toBeGreaterThan(0);
      // Name must be a DERIVED human name, not a bare echo of the id.
      expect(rule.name).not.toBe(rule.id);

      const securitySeverity = rule.properties?.["security-severity"];
      expect(securitySeverity).toBeDefined();
      expect(Number.isNaN(Number(securitySeverity))).toBe(false);
    }
  });

  it("keeps every result's ruleIndex consistent with the position of its ruleId in rules[]", () => {
    const result = makeScanResult();
    const parsed = JSON.parse(sarifReporter.render(result)) as ParsedSarifLog;
    const run = parsed.runs[0];
    expect(run).toBeDefined();
    if (!run) return;

    for (const sarifResult of run.results) {
      expect(sarifResult.ruleIndex).toBeDefined();
      const expectedIndex = run.tool.driver.rules.findIndex(
        (rule) => rule.id === sarifResult.ruleId,
      );
      expect(sarifResult.ruleIndex).toBe(expectedIndex);
    }
  });
});

describe("sarifReporter.render — Test 3: every result carries the required fields", () => {
  it("populates ruleId/level/message.text/locations/region/partialFingerprints on ALL results", () => {
    const result = makeScanResult();
    const parsed = JSON.parse(sarifReporter.render(result)) as ParsedSarifLog;
    const run = parsed.runs[0];
    expect(run).toBeDefined();
    if (!run) return;

    expect(run.results).toHaveLength(3);

    const findings = [CRITICAL_FINDING, CRITICAL_FINDING_DUPLICATE_RULE, AILAYER_FINDING];
    run.results.forEach((sarifResult, index) => {
      const finding = findings.at(index);
      expect(finding).toBeDefined();
      if (!finding) return;

      expect(sarifResult.ruleId).toBe(finding.ruleId);
      expect(["error", "warning", "note", "none"]).toContain(sarifResult.level);
      expect(sarifResult.message.text.length).toBeGreaterThan(0);

      const location = sarifResult.locations[0];
      expect(location).toBeDefined();
      if (!location) return;

      expect(location.physicalLocation.artifactLocation.uri).toBe(finding.file);
      expect(location.physicalLocation.artifactLocation.uri.startsWith("/")).toBe(false);
      expect(location.physicalLocation.region.startLine).toBe(finding.line);

      expect(sarifResult.partialFingerprints.primaryLocationLineHash.length).toBeGreaterThan(0);
    });
  });
});

describe("sarifReporter.render — Test 4: severity → level/security-severity mapping", () => {
  it("maps CRITICAL to level 'error' and security-severity >= 9.0", () => {
    const result = makeScanResult({ findings: [CRITICAL_FINDING] });
    const parsed = JSON.parse(sarifReporter.render(result)) as ParsedSarifLog;
    const run = parsed.runs[0];
    expect(run).toBeDefined();
    if (!run) return;

    const sarifResult = run.results[0];
    expect(sarifResult).toBeDefined();
    if (!sarifResult) return;
    expect(sarifResult.level).toBe("error");

    const rule = run.tool.driver.rules[0];
    expect(rule).toBeDefined();
    if (!rule) return;
    expect(Number(rule.properties?.["security-severity"])).toBeGreaterThanOrEqual(9.0);
  });

  it("maps HIGH to level 'error' and security-severity >= 7.0", () => {
    const result = makeScanResult({ findings: [AILAYER_FINDING] });
    const parsed = JSON.parse(sarifReporter.render(result)) as ParsedSarifLog;
    const run = parsed.runs[0];
    expect(run).toBeDefined();
    if (!run) return;

    const sarifResult = run.results[0];
    expect(sarifResult).toBeDefined();
    if (!sarifResult) return;
    expect(sarifResult.level).toBe("error");

    const rule = run.tool.driver.rules[0];
    expect(rule).toBeDefined();
    if (!rule) return;
    expect(Number(rule.properties?.["security-severity"])).toBeGreaterThanOrEqual(7.0);
  });

  it("maps MEDIUM to level 'warning' and security-severity >= 4.0", () => {
    const result = makeScanResult({ findings: [MEDIUM_FINDING] });
    const parsed = JSON.parse(sarifReporter.render(result)) as ParsedSarifLog;
    const run = parsed.runs[0];
    expect(run).toBeDefined();
    if (!run) return;

    const sarifResult = run.results[0];
    expect(sarifResult).toBeDefined();
    if (!sarifResult) return;
    expect(sarifResult.level).toBe("warning");

    const rule = run.tool.driver.rules[0];
    expect(rule).toBeDefined();
    if (!rule) return;
    expect(Number(rule.properties?.["security-severity"])).toBeGreaterThanOrEqual(4.0);
  });

  it("maps LOW to level 'note'", () => {
    const result = makeScanResult({ findings: [LOW_FINDING] });
    const parsed = JSON.parse(sarifReporter.render(result)) as ParsedSarifLog;
    const run = parsed.runs[0];
    expect(run).toBeDefined();
    if (!run) return;

    const sarifResult = run.results[0];
    expect(sarifResult).toBeDefined();
    if (!sarifResult) return;
    expect(sarifResult.level).toBe("note");
  });

  it("maps INFO to level 'note' or 'none'", () => {
    const result = makeScanResult({ findings: [INFO_FINDING] });
    const parsed = JSON.parse(sarifReporter.render(result)) as ParsedSarifLog;
    const run = parsed.runs[0];
    expect(run).toBeDefined();
    if (!run) return;

    const sarifResult = run.results[0];
    expect(sarifResult).toBeDefined();
    if (!sarifResult) return;
    expect(["note", "none"]).toContain(sarifResult.level);
  });
});

describe("sarifReporter.render — Test 5: empty findings", () => {
  it("renders a valid SARIF run with empty results[] and empty rules[] — no crash", () => {
    const result = makeScanResult({ findings: [] });
    let parsed: ParsedSarifLog;

    expect(() => {
      parsed = JSON.parse(sarifReporter.render(result)) as ParsedSarifLog;
    }).not.toThrow();

    parsed = JSON.parse(sarifReporter.render(result)) as ParsedSarifLog;
    const run = parsed.runs[0];
    expect(run).toBeDefined();
    if (!run) return;

    expect(run.results).toEqual([]);
    expect(run.tool.driver.rules).toEqual([]);
  });
});

describe("sarifReporter.render — Test 6: fingerprint stability + uniqueness", () => {
  it("produces different hashes for findings at different file:line locations", () => {
    const result = makeScanResult({
      findings: [CRITICAL_FINDING, CRITICAL_FINDING_DUPLICATE_RULE],
    });
    const parsed = JSON.parse(sarifReporter.render(result)) as ParsedSarifLog;
    const run = parsed.runs[0];
    expect(run).toBeDefined();
    if (!run) return;

    const [first, second] = run.results;
    expect(first).toBeDefined();
    expect(second).toBeDefined();
    if (!first || !second) return;

    expect(first.partialFingerprints.primaryLocationLineHash).not.toBe(
      second.partialFingerprints.primaryLocationLineHash,
    );
  });

  it("produces a deterministic hash for the same logical location across two render() calls", () => {
    const result = makeScanResult({ findings: [CRITICAL_FINDING] });
    const firstRender = JSON.parse(sarifReporter.render(result)) as ParsedSarifLog;
    const secondRender = JSON.parse(sarifReporter.render(result)) as ParsedSarifLog;

    const firstRun = firstRender.runs[0];
    const secondRun = secondRender.runs[0];
    expect(firstRun).toBeDefined();
    expect(secondRun).toBeDefined();
    if (!firstRun || !secondRun) return;

    const firstResult = firstRun.results[0];
    const secondResult = secondRun.results[0];
    expect(firstResult).toBeDefined();
    expect(secondResult).toBeDefined();
    if (!firstResult || !secondResult) return;

    expect(firstResult.partialFingerprints.primaryLocationLineHash).toBe(
      secondResult.partialFingerprints.primaryLocationLineHash,
    );
  });
});

describe("sarifReporter.render — Test 8: headline A-F grade surfaced in run.properties", () => {
  it("carries score.grade/gradeLabel into runs[0].properties without restructuring the SARIF document", () => {
    const result = makeScanResult();
    const parsed = JSON.parse(sarifReporter.render(result)) as ParsedSarifLog;
    const run = parsed.runs[0];
    expect(run).toBeDefined();
    if (!run) return;

    expect(run.properties?.grade).toBe(result.score.grade);
    expect(run.properties?.gradeLabel).toBe(result.score.gradeLabel);
  });
});

describe("sarifReporter.render — Test 7: pure JSON, no mixed-in prose or color", () => {
  it("contains no ANSI escape sequences", () => {
    const result = makeScanResult();
    expect(ANSI_ESCAPE_RE.test(sarifReporter.render(result))).toBe(false);
  });

  it("the trimmed output starts with '{' and ends with '}' (no leading/trailing prose)", () => {
    const result = makeScanResult();
    const output = sarifReporter.render(result).trim();
    expect(output.startsWith("{")).toBe(true);
    expect(output.endsWith("}")).toBe(true);
  });
});

describe("sarifReporter — artifact URIs, tool identity, and notifications", () => {
  it("percent-encodes repo paths and anchors them to %SRCROOT%, leaving live-URL findings absolute", () => {
    const log = JSON.parse(
      sarifReporter.render(
        makeScanResult({
          findings: [
            { ...CRITICAL_FINDING, file: "src/my file#1.ts" },
            { ...CRITICAL_FINDING, ruleId: "WEB-EXPOSED", file: "https://example.com/.env" },
          ],
        }),
      ),
    ) as SarifLog;

    const locations = log.runs[0]?.results.map((result) => result.locations[0]?.physicalLocation.artifactLocation);
    expect(locations).toEqual([
      { uri: "src/my%20file%231.ts", uriBaseId: "%SRCROOT%" },
      { uri: "https://example.com/.env" },
    ]);
  });

  it("identifies the real project and version", () => {
    const driver = (JSON.parse(sarifReporter.render(makeScanResult())) as SarifLog).runs[0]?.tool.driver;

    expect(driver?.informationUri).toBe("https://github.com/Mocinjay/immunogen");
    expect(driver?.version).toMatch(/^\d+\.\d+\.\d+/);
  });

  it("reports diagnostics as tool execution notifications", () => {
    const log = JSON.parse(
      sarifReporter.render(
        makeScanResult({ diagnostics: [{ level: "warn", code: "PARSE_WARN", message: "failed to parse a.ts", file: "a.ts" }] }),
      ),
    ) as SarifLog;

    expect(log.runs[0]?.invocations?.[0]?.toolExecutionNotifications).toEqual([
      expect.objectContaining({ level: "warning", descriptor: { id: "PARSE_WARN" }, message: { text: "failed to parse a.ts" } }),
    ]);
  });
});

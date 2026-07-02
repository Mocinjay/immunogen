/**
 * AI-layer end-to-end integration test — Phase 6 (Plan 06-04) success
 * criteria 1, 2, 3, and 4-fire.
 *
 * Calls the real, public `scan()` (src/index.ts) over the on-disk fixture
 * directories created by this plan and asserts that AILAYER-01, AILAYER-03,
 * and AILAYER-04 each fire with the expected file/line/severity shape, that
 * the clean fixture stays silent, and that `sarifReporter`/`getReporter`
 * render a criteria-4-valid SARIF 2.1.0 document from that live scan output.
 *
 * Fixture-path resolution mirrors
 * tests/integration/phase5-coverage.test.ts: `dirname(fileURLToPath(...))`
 * relative to THIS test file, then `join(..., "tests", "fixtures", ...)` up
 * to the repo root — this test lives three directories deep
 * (src/detectors/ai-layer/), one directory deeper than
 * phase5-coverage.test.ts (tests/integration/), so the `join()` call below
 * walks up three levels instead of two.
 *
 * No mocking of detectors or of the OSV client here: these fixtures contain
 * no dependency manifest, so `osvDetector`'s glob pre-filter never matches
 * any file in them and it is never invoked — no network-safety mock is
 * needed (contrast with phase5-coverage.test.ts's `nextjs-kitchen-sink`
 * fixture, which does contain a package.json/lockfile).
 */
import { describe, expect, it } from "vitest";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { getReporter } from "../../reporters/index.js";
import { sarifReporter } from "../../reporters/sarif.js";

import type { SarifLog } from "../../reporters/sarif-types.js";

const { scan } = await import("../../index.js");

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES_ROOT = join(__dirname, "..", "..", "..", "tests", "fixtures");

const MCP_TOOL_POISONING_ROOT = join(FIXTURES_ROOT, "vulnerable-apps", "mcp-tool-poisoning");
const AI_LAYER_RULES_ROOT = join(FIXTURES_ROOT, "vulnerable-apps", "ai-layer-rules");
const MCP_LEAST_PRIVILEGE_ROOT = join(FIXTURES_ROOT, "vulnerable-apps", "mcp-least-privilege");
const AI_LAYER_CLEAN_ROOT = join(FIXTURES_ROOT, "clean-apps", "ai-layer-clean");

describe("ai-layer e2e — criterion 1: mcp-tool-poisoning fixture fires AILAYER-03", () => {
  it("reports at least one AILAYER-03 finding at a .mcp.json file:line with severity CRITICAL or HIGH", async () => {
    const result = await scan(MCP_TOOL_POISONING_ROOT);

    const ailayer03Findings = result.findings.filter((finding) => finding.ruleId === "AILAYER-03");

    expect(ailayer03Findings.length).toBeGreaterThanOrEqual(1);
    for (const finding of ailayer03Findings) {
      expect(finding.file.endsWith(".mcp.json")).toBe(true);
      expect(finding.line).toBeGreaterThanOrEqual(1);
      expect(["CRITICAL", "HIGH"]).toContain(finding.severity);
    }
  });
});

describe("ai-layer e2e — criterion 2: ai-layer-rules fixture fires AILAYER-01", () => {
  it("reports at least one AILAYER-01 finding at a .cursor/rules file:line", async () => {
    const result = await scan(AI_LAYER_RULES_ROOT);

    const ailayer01Findings = result.findings.filter((finding) => finding.ruleId === "AILAYER-01");

    expect(ailayer01Findings.length).toBeGreaterThanOrEqual(1);
    for (const finding of ailayer01Findings) {
      expect(finding.file.endsWith(".cursor/rules")).toBe(true);
      expect(finding.line).toBeGreaterThanOrEqual(1);
    }
  });
});

describe("ai-layer e2e — criterion 3: mcp-least-privilege fixture fires AILAYER-04", () => {
  it("reports at least one AILAYER-04 finding with severity MEDIUM", async () => {
    const result = await scan(MCP_LEAST_PRIVILEGE_ROOT);

    const ailayer04Findings = result.findings.filter((finding) => finding.ruleId === "AILAYER-04");

    expect(ailayer04Findings.length).toBeGreaterThanOrEqual(1);
    for (const finding of ailayer04Findings) {
      expect(finding.severity).toBe("MEDIUM");
    }
  });
});

describe("ai-layer e2e — zero false positives on the clean fixture", () => {
  it("reports zero ai-layer findings for the clean fixture", async () => {
    const result = await scan(AI_LAYER_CLEAN_ROOT);

    const aiLayerFindings = result.findings.filter((finding) => finding.category === "ai-layer");

    expect(aiLayerFindings).toEqual([]);
  });
});

describe("ai-layer e2e — criterion 4: SARIF rendering of a live scan is valid SARIF 2.1.0", () => {
  it("sarifReporter.render(await scan(...)) parses as SARIF 2.1.0 with rules[] including AILAYER-03 and partialFingerprints on every result", async () => {
    const result = await scan(MCP_TOOL_POISONING_ROOT);

    const rendered = sarifReporter.render(result);
    const parsed = JSON.parse(rendered) as SarifLog;

    expect(parsed.$schema).toBe("https://json.schemastore.org/sarif-2.1.0.json");
    expect(parsed.version).toBe("2.1.0");

    const run = parsed.runs[0];
    expect(run).toBeDefined();
    expect(run?.tool.driver.rules.length).toBeGreaterThanOrEqual(1);
    expect(run?.tool.driver.rules.some((rule) => rule.id === "AILAYER-03")).toBe(true);

    expect(run?.results.length).toBeGreaterThanOrEqual(1);
    for (const sarifResult of run?.results ?? []) {
      expect(typeof sarifResult.partialFingerprints?.primaryLocationLineHash).toBe("string");
      expect(sarifResult.partialFingerprints?.primaryLocationLineHash.length).toBeGreaterThan(0);
    }
  });

  it("getReporter('sarif') returns a reporter whose render output parses as SARIF (guards the Task 2 wiring)", async () => {
    const result = await scan(MCP_TOOL_POISONING_ROOT);

    const reporter = getReporter("sarif");
    const parsed = JSON.parse(reporter.render(result)) as SarifLog;

    expect(parsed.$schema).toBe("https://json.schemastore.org/sarif-2.1.0.json");
    expect(parsed.version).toBe("2.1.0");
    expect(Array.isArray(parsed.runs)).toBe(true);
  });
});

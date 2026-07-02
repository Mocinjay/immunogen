/**
 * Phase 5 coverage integration test — ROADMAP Phase 5 success criteria 1, 3,
 * and 5-fire.
 *
 * Calls the real, public `scan()` (src/index.ts) over the deliberately
 * vulnerable `tests/fixtures/vulnerable-apps/nextjs-kitchen-sink/` fixture
 * app and asserts that every one of the 17 phase requirement ruleIds (+
 * SEC-04, the Supabase service_role signal) fires at least once, that the
 * ROADMAP criterion-1 ruleIds each carry file/line/severity, and that
 * ScanResult.scanIncomplete is true on this offline-degraded run.
 *
 * NETWORK SAFETY: `osvDetector` (src/detectors/deps/osv-detector.ts) calls
 * `queryOsvBatch` (./osv-client.js) unconditionally — `ScanOptions.offline`
 * is NOT read anywhere in the detector or in DetectorContext, so passing
 * `{ offline: true }` to `scan()` alone does NOT prevent a real network call.
 * This test mocks `queryOsvBatch` at the module boundary (the SAME pattern
 * `src/detectors/deps/osv-detector.test.ts` already uses) to force the
 * offline-fallback branch deterministically — this is the only mechanism
 * that guarantees this test never makes a real network call.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import type { OsvResult } from "../../src/detectors/deps/osv-client.js";

// Mocked BEFORE importing `scan()` so the mocked module graph is in place
// for every detector that transitively imports osv-client.js.
const queryOsvBatchMock = vi.fn<(queries: Array<{ name: string; version: string }>) => Promise<OsvResult[]>>();

vi.mock("../../src/detectors/deps/osv-client.js", () => ({
  queryOsvBatch: (queries: Array<{ name: string; version: string }>) => queryOsvBatchMock(queries),
}));

const { scan } = await import("../../src/index.js");

const __dirname = dirname(fileURLToPath(import.meta.url));
const KITCHEN_SINK_ROOT = join(__dirname, "..", "fixtures", "vulnerable-apps", "nextjs-kitchen-sink");

/**
 * Every requirement ruleId this phase's 17 REQUIREMENTS.md ids actually
 * emit, PLUS SEC-04 (the Supabase service_role signal, emitted by the same
 * secretsDetector file as SEC-01/05/06). Per the 05-0X-SUMMARYs' ruleId
 * reconciliation: requirement label "SEC-02" emits ruleId "SEC-05"
 * (committed .env), and requirement label "SEC-03" emits ruleId "SEC-06"
 * (keyword-anchored entropy) — both reflected here by their EMITTED id, not
 * their requirement label.
 */
const EXPECTED_RULE_IDS = [
  "SEC-01",
  "SEC-05",
  "SEC-06",
  "SEC-04",
  "BUNDLE-01",
  "AUTH-01",
  "AUTH-02",
  "AUTH-03",
  "PAY-01",
  "DEP-01",
  "INJECT-01",
  "CORS-01",
  "HDR-01",
  "STORAGE-01",
  "STORAGE-02",
  "LEGAL-01",
  "CONFIG-01",
  "CONFIG-02",
];

/** ROADMAP criterion 1's named ruleIds — each must carry file + line + severity. */
const CRITERION_1_RULE_IDS = ["SEC-01", "SEC-05", "BUNDLE-01", "AUTH-01", "PAY-01"];

afterEach(() => {
  queryOsvBatchMock.mockReset();
});

describe("Phase 5 coverage — vulnerable kitchen-sink fixture, full scan()", () => {
  it("fires every one of the 17 requirement ruleIds (+SEC-04) on a real scan() call", async () => {
    queryOsvBatchMock.mockRejectedValue(new Error("network unavailable (test stub — never a real call)"));

    const result = await scan(KITCHEN_SINK_ROOT, { offline: true });

    const presentRuleIds = new Set(result.findings.map((finding) => finding.ruleId));

    const missing = EXPECTED_RULE_IDS.filter((ruleId) => !presentRuleIds.has(ruleId));
    expect(missing, `missing expected ruleIds: ${missing.join(", ")}`).toEqual([]);
  });

  it("ROADMAP criterion 1 ruleIds (SEC-01, SEC-05, BUNDLE-01, AUTH-01, PAY-01) each have file + line + severity", async () => {
    queryOsvBatchMock.mockRejectedValue(new Error("network unavailable (test stub — never a real call)"));

    const result = await scan(KITCHEN_SINK_ROOT, { offline: true });

    for (const ruleId of CRITERION_1_RULE_IDS) {
      const finding = result.findings.find((candidate) => candidate.ruleId === ruleId);
      expect(finding, `expected at least one finding for ${ruleId}`).toBeDefined();
      expect(finding?.file).toBeTruthy();
      expect(finding?.line).toBeGreaterThan(0);
      expect(finding?.severity).toBeTruthy();
    }
  });

  it("sets ScanResult.scanIncomplete = true when the OSV detector degrades to its offline fallback", async () => {
    queryOsvBatchMock.mockRejectedValue(new Error("network unavailable (test stub — never a real call)"));

    const result = await scan(KITCHEN_SINK_ROOT, { offline: true });

    expect(result.scanIncomplete).toBe(true);
    expect(result.findings.some((finding) => finding.ruleId === "DEP-OFFLINE")).toBe(true);
  });

  it("at least one finding's file does NOT contain 'fixtures/' — proves the detector saw the in-repo relative path", async () => {
    queryOsvBatchMock.mockRejectedValue(new Error("network unavailable (test stub — never a real call)"));

    const result = await scan(KITCHEN_SINK_ROOT, { offline: true });

    expect(result.findings.some((finding) => !finding.file.includes("fixtures/"))).toBe(true);
  });

  it("never calls the real OSV.dev network endpoint (queryOsvBatch is always the mock)", async () => {
    queryOsvBatchMock.mockRejectedValue(new Error("network unavailable (test stub — never a real call)"));

    await scan(KITCHEN_SINK_ROOT, { offline: true });

    expect(queryOsvBatchMock).toHaveBeenCalled();
  });
});

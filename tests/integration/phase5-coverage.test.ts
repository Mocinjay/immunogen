/**
 * Detector coverage integration test.
 *
 * Calls the real, public `scan()` (src/index.ts) over the deliberately
 * vulnerable `tests/fixtures/vulnerable-apps/nextjs-kitchen-sink/` fixture
 * app and asserts that every core ruleId (incl. SEC-04, the Supabase
 * service_role signal) fires at least once, that the headline ruleIds each
 * carry file/line/severity, and that
 * ScanResult.scanIncomplete is true on this offline-degraded run.
 *
 * NETWORK SAFETY: every scan here passes `{ offline: true }`, which
 * `osvDetector` (src/detectors/deps/osv-detector.ts) honors via
 * `DetectorContext.offline` by skipping `queryOsvBatch` entirely and taking
 * the offline-fallback branch. `queryOsvBatch` is ALSO mocked at the module
 * boundary (the SAME pattern `src/detectors/deps/osv-detector.test.ts`
 * uses) as a belt-and-braces guard, and the last test below proves the
 * offline option never even reaches that seam.
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
 * Every core ruleId the kitchen-sink fixture must trigger, including SEC-04
 * (the Supabase service_role signal), SEC-05 (committed .env) and SEC-06
 * (keyword-anchored entropy).
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

/** Headline ruleIds — each must carry file + line + severity. */
const CRITERION_1_RULE_IDS = ["SEC-01", "SEC-05", "BUNDLE-01", "AUTH-01", "PAY-01"];

afterEach(() => {
  queryOsvBatchMock.mockReset();
});

describe("detector coverage — vulnerable kitchen-sink fixture, full scan()", () => {
  it("fires every one of the 17 requirement ruleIds (+SEC-04) on a real scan() call", async () => {
    queryOsvBatchMock.mockRejectedValue(new Error("network unavailable (test stub — never a real call)"));

    const result = await scan(KITCHEN_SINK_ROOT, { offline: true });

    const presentRuleIds = new Set(result.findings.map((finding) => finding.ruleId));

    const missing = EXPECTED_RULE_IDS.filter((ruleId) => !presentRuleIds.has(ruleId));
    expect(missing, `missing expected ruleIds: ${missing.join(", ")}`).toEqual([]);
  });

  it("headline ruleIds (SEC-01, SEC-05, BUNDLE-01, AUTH-01, PAY-01) each have file + line + severity", async () => {
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

  it("never reaches the OSV.dev network seam when scanning with { offline: true }", async () => {
    queryOsvBatchMock.mockRejectedValue(new Error("network unavailable (test stub — never a real call)"));

    await scan(KITCHEN_SINK_ROOT, { offline: true });

    expect(queryOsvBatchMock).not.toHaveBeenCalled();
  });
});

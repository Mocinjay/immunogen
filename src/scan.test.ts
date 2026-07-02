/**
 * End-to-end test for `scan()` — proves the real ingest -> runDetectors ->
 * computeScore pipeline (src/index.ts, Plan 04-04) against two committed,
 * on-disk fixtures: tests/fixtures/scan/with-secret (a fabricated CRITICAL
 * secret) and tests/fixtures/scan/clean (no secrets). Mirrors
 * src/core/ingest/ingest.test.ts's style, but uses repo-relative on-disk
 * fixture directories directly rather than a temp-dir helper, since these
 * fixtures are committed, not generated per-test.
 */
import { describe, expect, it } from "vitest";

import { scan } from "./index.js";

const WITH_SECRET_FIXTURE = "tests/fixtures/scan/with-secret";
const CLEAN_FIXTURE = "tests/fixtures/scan/clean";

describe("scan — end-to-end: ingest -> runDetectors -> computeScore -> assemble", () => {
  it("returns a populated ScanResult for the with-secret fixture (criterion 1, SCORE-02)", async () => {
    const result = await scan(WITH_SECRET_FIXTURE);

    expect(result.score.score).toBeGreaterThanOrEqual(0);
    expect(result.score.score).toBeLessThanOrEqual(100);
    expect(["Ready to ship", "Low risk", "Moderate risk", "High risk"]).toContain(result.score.band);
    expect(["pass", "blocked"]).toContain(result.score.verdict);
    expect(result.findings.length).toBeGreaterThanOrEqual(1);

    const findingWithLocation = result.findings.find(
      (f) => f.file.length > 0 && f.line >= 1 && (["HIGH", "MEDIUM", "LOW"] as const).includes(f.confidence),
    );
    expect(findingWithLocation).toBeDefined();
  });

  it("yields score <= 25 AND verdict 'blocked' for the with-secret (CRITICAL) fixture (criterion 3)", async () => {
    const result = await scan(WITH_SECRET_FIXTURE);

    expect(result.score.score).toBeLessThanOrEqual(25);
    expect(result.score.verdict).toBe("blocked");
  });

  it("yields verdict !== 'blocked', a high score, and zero secrets findings for the clean fixture (criterion 5)", async () => {
    const result = await scan(CLEAN_FIXTURE);

    expect(result.score.verdict).not.toBe("blocked");
    expect(result.score.score).toBeGreaterThanOrEqual(90);

    const secretsFindings = result.findings.filter((f) => f.category === "secrets");
    expect(secretsFindings).toHaveLength(0);
  });

  it("sets target/scannedAt/llmEnriched/scanIncomplete correctly for the with-secret fixture", async () => {
    const result = await scan(WITH_SECRET_FIXTURE);

    expect(result.target).toBe(WITH_SECRET_FIXTURE);
    expect(new Date(result.scannedAt).toString()).not.toBe("Invalid Date");
    expect(result.llmEnriched).toBe(false);
    expect(result.scanIncomplete).toBe(false);
  });

  it("sets target/scannedAt/llmEnriched/scanIncomplete correctly for the clean fixture", async () => {
    const result = await scan(CLEAN_FIXTURE);

    expect(result.target).toBe(CLEAN_FIXTURE);
    expect(new Date(result.scannedAt).toString()).not.toBe("Invalid Date");
    expect(result.llmEnriched).toBe(false);
    expect(result.scanIncomplete).toBe(false);
  });

  it("never throws and never calls process.exit for a valid directory (library-first)", async () => {
    await expect(scan(CLEAN_FIXTURE)).resolves.toBeDefined();
    await expect(scan(WITH_SECRET_FIXTURE)).resolves.toBeDefined();
  });
});

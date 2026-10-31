/**
 * End-to-end test for `scan()` — proves the real ingest -> runDetectors ->
 * computeScore pipeline (src/index.ts, Plan 04-04) against two committed,
 * on-disk fixtures: tests/fixtures/scan/with-secret (a fabricated CRITICAL
 * secret) and tests/fixtures/scan/clean (no secrets). Mirrors
 * src/core/ingest/ingest.test.ts's style, but uses repo-relative on-disk
 * fixture directories directly rather than a temp-dir helper, since these
 * fixtures are committed, not generated per-test.
 */
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";

import { scan } from "./index.js";

// OSV.dev is stubbed at the module boundary (same seam as
// tests/golden/golden.test.ts) so this suite is hermetic: a sandbox, an
// offline laptop, or a corporate proxy can never flip `scanIncomplete` or
// the finding count. The stub reports a fixed 25 advisories for `next` (the
// fixture's only dependency), like the real OSV response for next@14.0.0.
vi.mock("./detectors/deps/osv-client.js", () => ({
  queryOsvBatch: (queries: Array<{ name: string; version: string }>) =>
    Promise.resolve(
      queries.map((query) =>
        query.name === "next"
          ? { vulns: Array.from({ length: 25 }, (_, index) => ({ id: `GHSA-test-next-${String(index)}` })) }
          : {},
      ),
    ),
}));

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

describe("scan — offline option", () => {
  it("never queries OSV with { offline: true } and reports the dependency check as incomplete", async () => {
    const result = await scan("tests/fixtures/scan/with-secret", { offline: true });

    expect(result.findings.some((finding) => finding.ruleId === "DEP-OFFLINE")).toBe(true);
    expect(result.findings.some((finding) => finding.message.includes("GHSA-test-next-"))).toBe(false);
    expect(result.scanIncomplete).toBe(true);
  });
});

describe("scan — diagnostics reach the ScanResult", () => {
  it("reports an unparseable source file as a PARSE_WARN diagnostic instead of dropping it silently", async () => {
    const root = await mkdtemp(join(tmpdir(), "immunogen-diag-"));
    try {
      // eslint-disable-next-line security/detect-non-literal-fs-filename -- test-owned temp dir
      await writeFile(join(root, "broken.ts"), "export const = <<< broken(((");

      const result = await scan(root, { offline: true, noLlm: true });

      expect(result.diagnostics).toEqual([expect.objectContaining({ code: "PARSE_WARN", file: "broken.ts" })]);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});

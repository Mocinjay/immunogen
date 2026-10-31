/**
 * The release-gating golden-file suite.
 *
 * Consolidates the finding-set contract for the whole scan pipeline into
 * ONE suite:
 *
 *   1. Vulnerable fixtures (tests/golden/fixture-manifest.ts
 *      VULNERABLE_FIXTURES) — each asserts the EXACT normalized
 *      ruleId->count summary via `toMatchSnapshot()`. The first run writes
 *      tests/golden/__snapshots__/golden.test.ts.snap; that file is
 *      committed and IS the human-auditable expected-finding contract. Any
 *      drift in ruleIds or counts breaks CI.
 *
 *   2. Clean fixtures (CLEAN_FIXTURES) — each asserts `result.findings`
 *      is exactly `[]` under the OSV mock resolving `[]` (without the mock
 *      these are NOT genuinely zero).
 *
 *   3. Zip-Slip rejection — a ZIP whose entry name is `../../etc/passwd`
 *      must make `scan()` reject, and the literal escape target under
 *      `tmpdir()` must never be created (mirrors
 *      src/core/ingest/input-resolver.test.ts).
 *
 * NETWORK SAFETY: `osvDetector` (src/detectors/deps/osv-detector.ts) calls
 * `queryOsvBatch` (./osv-client.js) unconditionally for every scanned
 * package.json dependency. This suite mocks `queryOsvBatch` at the module
 * boundary BEFORE the dynamic `import("../../src/index.js")` — the SAME
 * seam tests/integration/phase5-false-positive.test.ts and
 * tests/integration/phase5-coverage.test.ts already use — so the real
 * OSV.dev endpoint is structurally never reachable from this suite.
 */
import { existsSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

import { writeZipFile } from "../helpers/make-zip.js";
import { CLEAN_FIXTURES, summarize, VULNERABLE_FIXTURES } from "./fixture-manifest.js";

import type { OsvResult } from "../../src/detectors/deps/osv-client.js";

// Mocked BEFORE importing `scan()` so the mocked module graph is in place
// for every detector (including osvDetector) that transitively imports
// osv-client.js. This ordering is mandatory — importing scan() first would
// bind the real module before vi.mock's factory can intercept it.
const queryOsvBatchMock = vi.fn<(queries: Array<{ name: string; version: string }>) => Promise<OsvResult[]>>();

vi.mock("../../src/detectors/deps/osv-client.js", () => ({
  queryOsvBatch: (queries: Array<{ name: string; version: string }>) => queryOsvBatchMock(queries),
}));

const { scan } = await import("../../src/index.js");

/** Headline spot-check ruleIds — each must carry file/line/severity. */
const CRITERION_1_RULE_IDS = ["SEC-01", "SEC-05", "BUNDLE-01", "AUTH-01", "PAY-01"];

const tempDirsToClean: string[] = [];

afterEach(async () => {
  queryOsvBatchMock.mockReset();
  while (tempDirsToClean.length > 0) {
    const dir = tempDirsToClean.pop();
    if (dir) {
      await rm(dir, { recursive: true, force: true });
    }
  }
});

describe("golden suite — vulnerable fixtures assert exact ruleId/count summaries", () => {
  for (const fixture of VULNERABLE_FIXTURES) {
    it(`${fixture.name}: normalized finding summary matches the committed snapshot`, async () => {
      if (fixture.osvMock === "reject") {
        queryOsvBatchMock.mockRejectedValue(new Error("network unavailable (test stub — never a real call)"));
      } else {
        queryOsvBatchMock.mockResolvedValue([]);
      }

      const result = await scan(fixture.dir);

      expect(summarize(result.findings)).toMatchSnapshot();
    });
  }

  it("kitchen-sink: headline ruleIds (SEC-01, SEC-05, BUNDLE-01, AUTH-01, PAY-01) each carry file + line + severity", async () => {
    queryOsvBatchMock.mockRejectedValue(new Error("network unavailable (test stub — never a real call)"));

    const kitchenSink = VULNERABLE_FIXTURES.find((fixture) => fixture.name === "nextjs-kitchen-sink");
    expect(kitchenSink, "nextjs-kitchen-sink must be declared in VULNERABLE_FIXTURES").toBeDefined();

    const result = await scan(kitchenSink?.dir ?? "");

    for (const ruleId of CRITERION_1_RULE_IDS) {
      const finding = result.findings.find((candidate) => candidate.ruleId === ruleId);
      expect(finding, `expected at least one finding for ${ruleId}`).toBeDefined();
      expect(finding?.file).toBeTruthy();
      expect(finding?.line).toBeGreaterThan(0);
      expect(finding?.severity).toBeTruthy();
    }
  });
});

describe("golden suite — clean fixtures assert ZERO findings", () => {
  for (const fixture of CLEAN_FIXTURES) {
    it(`${fixture.name}: yields zero findings under the OSV mock resolving []`, async () => {
      queryOsvBatchMock.mockResolvedValue([]);

      const result = await scan(fixture.dir);

      expect(result.findings, `expected zero findings, got: ${JSON.stringify(result.findings)}`).toEqual([]);
    });
  }
});

describe("golden suite — path-traversal ZIP is rejected before any bytes land outside the extraction root", () => {
  it("rejects a ZIP whose entry name uses ../../ traversal and writes nothing outside the extraction root", async () => {
    queryOsvBatchMock.mockResolvedValue([]);

    const zipParentDir = await mkdtemp(join(tmpdir(), "immunogen-golden-malicious-"));
    tempDirsToClean.push(zipParentDir);
    const zipPath = join(zipParentDir, "malicious.zip");
    // Uniquely-named sentinel rather than `etc/passwd`, so the existence check
    // below can't collide with a real system file — on Linux `tmpdir()` is
    // `/tmp` and `resolve(tmpdir(), "..", "..", "etc", "passwd")` is the actual
    // `/etc/passwd` (exists independent of this test). Mirrors the fix in
    // src/core/ingest/input-resolver.test.ts.
    const sentinel = "immunogen-zipslip-sentinel.txt";
    await writeZipFile(zipPath, { [`../../${sentinel}`]: "malicious content\n" });

    await expect(scan(zipPath)).rejects.toThrow();

    // Structural property: the traversal target must never have been
    // created anywhere outside the (now-discarded) extraction temp root —
    // mirrors src/core/ingest/input-resolver.test.ts's own assertion.
    const escapeTarget = resolve(tmpdir(), "..", "..", sentinel);
    // eslint-disable-next-line security/detect-non-literal-fs-filename -- test asserts a fixed, locally-derived path was never created
    expect(existsSync(escapeTarget)).toBe(false);
  });
});

describe("golden suite — network safety", () => {
  it("never calls the real OSV.dev network endpoint across any vulnerable or clean run (queryOsvBatch is always the mock)", async () => {
    queryOsvBatchMock.mockResolvedValue([]);

    await scan(CLEAN_FIXTURES[0]?.dir ?? "");

    expect(queryOsvBatchMock).toHaveBeenCalled();
  });
});

/**
 * CJS dual-import verification — proves `require('immunogen')` resolves
 * against the BUILT dist (not src) and its `.scan(...)` returns a
 * well-formed ScanResult (DIST-02).
 *
 * This is a standalone node script, NOT a vitest test: it requires the real
 * dist/index.cjs the same way a downstream CJS consumer would via the
 * package's "exports" map (`"require": "./dist/index.cjs"`), so it proves
 * the SHIPPED artifact works — not a vitest-transpiled view of src/. It is
 * invoked directly via `node tests/dist/dual-import.test.cjs` after a build,
 * never picked up by vitest.config.ts's include globs (those match
 * `*.test.ts`, not `*.test.cjs`).
 *
 * The scan/clean fixture is offline-safe (no OSV network dependency needed
 * for a pass/verdict result) and is the same fixture src/scan.test.ts uses
 * for its "clean" assertions. This test only asserts the API SHAPE resolves
 * correctly through the built entry — exact finding counts are the golden
 * suite's job (08-01), not this dual-import proof's.
 */
const { scan } = require("../../dist/index.cjs");

const CLEAN_FIXTURE = "tests/fixtures/scan/clean";

(async () => {
  try {
    const result = await scan(CLEAN_FIXTURE);

    if (!Array.isArray(result.findings)) {
      throw new Error(
        `CJS dual-import FAILED: result.findings is not an array (got ${typeof result.findings})`,
      );
    }

    if (
      typeof result.score.score !== "number" ||
      result.score.score < 0 ||
      result.score.score > 100
    ) {
      throw new Error(
        `CJS dual-import FAILED: result.score.score must be a number in [0,100] (got ${String(result.score.score)})`,
      );
    }

    if (result.score.verdict !== "pass" && result.score.verdict !== "blocked") {
      throw new Error(
        `CJS dual-import FAILED: result.score.verdict must be "pass" or "blocked" (got ${String(result.score.verdict)})`,
      );
    }

    console.log(
      `CJS dual-import OK: require("../../dist/index.cjs") -> score=${result.score.score} verdict=${result.score.verdict} findings=${result.findings.length}`,
    );
  } catch (err) {
    console.error(err instanceof Error ? err.message : String(err));
    process.exit(1);
  }
})();

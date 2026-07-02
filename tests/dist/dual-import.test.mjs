/**
 * ESM dual-import verification — proves `import { scan } from "immunogen"`
 * resolves against the BUILT dist (not src) and returns a well-formed
 * ScanResult (DIST-02).
 *
 * This is a standalone node script, NOT a vitest test: it imports the real
 * dist/index.js the same way a downstream ESM consumer would via the
 * package's "exports" map (`"import": "./dist/index.js"`), so it proves the
 * SHIPPED artifact works — not a vitest-transpiled view of src/. It is
 * invoked directly via `node tests/dist/dual-import.test.mjs` after a build,
 * never picked up by vitest.config.ts's include globs (those match
 * `*.test.ts`, not `*.test.mjs`).
 *
 * The scan/clean fixture is offline-safe (no OSV network dependency needed
 * for a pass/verdict result) and is the same fixture src/scan.test.ts uses
 * for its "clean" assertions. This test only asserts the API SHAPE resolves
 * correctly through the built entry — exact finding counts are the golden
 * suite's job (08-01), not this dual-import proof's.
 */
import { scan } from "../../dist/index.js";

const CLEAN_FIXTURE = "tests/fixtures/scan/clean";

const result = await scan(CLEAN_FIXTURE);

if (!Array.isArray(result.findings)) {
  throw new Error(
    `ESM dual-import FAILED: result.findings is not an array (got ${typeof result.findings})`,
  );
}

if (
  typeof result.score.score !== "number" ||
  result.score.score < 0 ||
  result.score.score > 100
) {
  throw new Error(
    `ESM dual-import FAILED: result.score.score must be a number in [0,100] (got ${String(result.score.score)})`,
  );
}

if (result.score.verdict !== "pass" && result.score.verdict !== "blocked") {
  throw new Error(
    `ESM dual-import FAILED: result.score.verdict must be "pass" or "blocked" (got ${String(result.score.verdict)})`,
  );
}

console.log(
  `ESM dual-import OK: import { scan } from "../../dist/index.js" -> score=${result.score.score} verdict=${result.score.verdict} findings=${result.findings.length}`,
);

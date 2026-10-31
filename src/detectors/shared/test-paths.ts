/**
 * The one false-positive allowlist for test, fixture, mock, and example code.
 *
 * Every detector used to carry its own copy of this check, and the copies had
 * drifted: most skipped `.test.`/`.stories.` files only, one also `.spec.`,
 * three also `tests/`/`testdata/` — so `foo.spec.ts` was suppressed by one
 * detector and scanned by nineteen. Detectors now share these two functions.
 */

/** Directory names whose contents are test scaffolding, not shipped code. */
const TEST_DIRECTORY_SEGMENTS = new Set([
  "__tests__",
  "__mocks__",
  "__fixtures__",
  "fixtures",
  "mocks",
  "examples",
  "tests",
  "testdata",
]);

/** Test / story file names across JS/TS (`.test.`, `.spec.`, `.stories.`), Python and Go. */
const TEST_BASENAME_RE = /\.(?:test|spec|stories)\.|^test_[^/]*\.py$|_test\.(?:py|go)$|^conftest\.py$/;

/** True when any directory segment of `filePath` is a test/fixture/mock/example directory. */
export function isInTestDirectory(filePath: string): boolean {
  const segments = filePath.split("/");
  return segments.slice(0, -1).some((segment) => TEST_DIRECTORY_SEGMENTS.has(segment));
}

/**
 * True when `filePath` is test, fixture, mock, example, or story code: it sits
 * in a test directory, or its file name marks it as a test or story. Findings
 * there are not launch blockers.
 */
export function isTestOrFixturePath(filePath: string): boolean {
  if (isInTestDirectory(filePath)) {
    return true;
  }
  return TEST_BASENAME_RE.test(filePath.slice(filePath.lastIndexOf("/") + 1));
}

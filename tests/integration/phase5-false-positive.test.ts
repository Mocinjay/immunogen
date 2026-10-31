/**
 * Phase 5 false-positive regression test — ROADMAP Phase 5 success criteria
 * 2, 4, and 5-clean.
 *
 * Two cases, both calling the real, public `scan()` (src/index.ts):
 *
 *   1. `tests/fixtures/clean-apps/nextjs-clean/` — a realistic, SAFE Next.js
 *      app with next/stripe/@supabase/supabase-js/firebase deps (so every
 *      stack gate is ACTIVE) that deliberately exercises every FP-prone
 *      pattern the Phase 5 detector set recognizes — and must still yield
 *      zero findings, proving suppression is by safe-pattern recognition,
 *      not by an inactive stack gate (criteria 2, 5-clean).
 *
 *   2. `tests/fixtures/clean-apps/tests-path-only/` — a tiny fixture whose
 *      only JS/TS file lives under `__tests__/` and deliberately contains a
 *      fake Stripe live-secret-key literal, a `NEXT_PUBLIC_SECRET` env
 *      reference, and an unsanitized `dangerouslySetInnerHTML` — patterns
 *      that WOULD fire SEC-01/BUNDLE-01/INJECT-01 anywhere else in a repo —
 *      and must yield zero findings, proving every detector's `__tests__/`
 *      path-segment allowlist suppresses them (criterion 4).
 *
 * NETWORK SAFETY: `osvDetector` (src/detectors/deps/osv-detector.ts) calls
 * `queryOsvBatch` (./osv-client.js) for every scanned package.json
 * dependency unless `scan()` is given `{ offline: true }`, so this test
 * mocks `queryOsvBatch` at the module boundary (the SAME pattern
 * `src/detectors/deps/osv-detector.test.ts` and
 * `tests/integration/phase5-coverage.test.ts` already use) to guarantee
 * neither case ever makes a real network call, regardless of whether the
 * `offline` option is passed to `scan()`.
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
const CLEAN_APP_ROOT = join(__dirname, "..", "fixtures", "clean-apps", "nextjs-clean");
const TESTS_PATH_ONLY_ROOT = join(__dirname, "..", "fixtures", "clean-apps", "tests-path-only");

afterEach(() => {
  queryOsvBatchMock.mockReset();
});

describe("Phase 5 false-positive regression — clean app, full scan()", () => {
  it("yields zero findings on a realistic clean app with all stack gates active (criteria 2, 5-clean)", async () => {
    // No vulnerable dep in this fixture's package.json, so the mock never
    // needs to resolve a hit — an empty array is the correct "no advisory
    // data" response and keeps this case from touching the network.
    queryOsvBatchMock.mockResolvedValue([]);

    const result = await scan(CLEAN_APP_ROOT);

    expect(result.findings, `expected zero findings, got: ${JSON.stringify(result.findings)}`).toEqual([]);
  });

  it("activates every stack gate (next/stripe/supabase/firebase deps present) yet still yields zero findings", async () => {
    queryOsvBatchMock.mockResolvedValue([]);

    const result = await scan(CLEAN_APP_ROOT);

    expect(result.stackHints.frameworks.has("nextjs")).toBe(true);
    expect(result.stackHints.hasStripe).toBe(true);
    expect(result.stackHints.hasSupabase).toBe(true);
    expect(result.stackHints.hasFirebase).toBe(true);
    expect(result.findings).toEqual([]);
  });
});

describe("Phase 5 false-positive regression — __tests__-only path, full scan() (criterion 4)", () => {
  it("yields zero findings when the only JS/TS file lives under __tests__/, despite containing patterns that would otherwise fire SEC-01/BUNDLE-01/INJECT-01", async () => {
    queryOsvBatchMock.mockResolvedValue([]);

    const result = await scan(TESTS_PATH_ONLY_ROOT);

    expect(result.findings, `expected zero findings, got: ${JSON.stringify(result.findings)}`).toEqual([]);
  });

  it("never calls the real OSV.dev network endpoint in either case (queryOsvBatch is always the mock)", async () => {
    queryOsvBatchMock.mockResolvedValue([]);

    await scan(CLEAN_APP_ROOT);
    await scan(TESTS_PATH_ONLY_ROOT);

    expect(queryOsvBatchMock).toHaveBeenCalled();
  });
});

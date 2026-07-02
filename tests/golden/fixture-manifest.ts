/**
 * Single declarative manifest of every fixture the golden suite
 * (tests/golden/golden.test.ts) drives, plus the pure `summarize()` helper
 * that normalizes a scan's `Finding[]` into a sorted, snapshot-friendly
 * ruleId -> count map.
 *
 * This file intentionally hardcodes NO expected counts — it only declares
 * WHICH fixture directories exist and WHICH `queryOsvBatch` mock mode each
 * vulnerable fixture requires to stay deterministic and network-free. The
 * actual expected finding counts/ruleIds live in the committed Vitest
 * snapshot (tests/golden/__snapshots__/golden.test.ts.snap), which IS the
 * human-auditable golden-file contract per STACK.md's golden-file guidance.
 *
 * Fixture dirs are repo-relative strings passed straight to `scan()`,
 * matching the existing convention in src/scan.test.ts (e.g.
 * "tests/fixtures/scan/clean").
 */
import type { Finding } from "../../src/core/types.js";

/** The two deterministic modes the golden suite can put `queryOsvBatch` in. */
export type OsvMockMode = "reject" | "resolveEmpty";

export interface VulnerableFixture {
  /** Short, human-readable name — used as the snapshot key. */
  name: string;
  /** Repo-relative fixture directory, passed straight to scan(). */
  dir: string;
  /** Which queryOsvBatch mock mode this fixture's scan must run under. */
  osvMock: OsvMockMode;
}

export interface CleanFixture {
  /** Short, human-readable name — used in per-fixture assertion messages. */
  name: string;
  /** Repo-relative fixture directory, passed straight to scan(). */
  dir: string;
}

/**
 * Vulnerable fixtures the golden suite snapshots. `osvMock` is chosen per
 * critical_facts in 08-01-PLAN.md: "reject" exercises the OSV
 * offline-fallback path (deterministic DEP-01/DEP-OFFLINE), "resolveEmpty"
 * is used for AI-layer-only fixtures (and scan/with-secret per the plan)
 * where no live vuln data is needed to reach a deterministic result.
 */
export const VULNERABLE_FIXTURES: VulnerableFixture[] = [
  {
    name: "nextjs-kitchen-sink",
    dir: "tests/fixtures/vulnerable-apps/nextjs-kitchen-sink",
    osvMock: "reject",
  },
  {
    name: "ai-layer-rules",
    dir: "tests/fixtures/vulnerable-apps/ai-layer-rules",
    osvMock: "resolveEmpty",
  },
  {
    name: "mcp-tool-poisoning",
    dir: "tests/fixtures/vulnerable-apps/mcp-tool-poisoning",
    osvMock: "resolveEmpty",
  },
  {
    name: "mcp-least-privilege",
    dir: "tests/fixtures/vulnerable-apps/mcp-least-privilege",
    osvMock: "resolveEmpty",
  },
  {
    name: "scan-with-secret",
    dir: "tests/fixtures/scan/with-secret",
    osvMock: "reject",
  },
];

/**
 * Clean fixtures the golden suite asserts are genuinely ZERO findings.
 * These are only zero under the OSV mock resolving `[]` — a real/absent
 * network call injects a spurious DEP-OFFLINE (and, for scan/clean,
 * LEGAL-01) that would break this assumption (critical_facts item 2).
 */
export const CLEAN_FIXTURES: CleanFixture[] = [
  { name: "nextjs-clean", dir: "tests/fixtures/clean-apps/nextjs-clean" },
  { name: "tests-path-only", dir: "tests/fixtures/clean-apps/tests-path-only" },
  { name: "ai-layer-clean", dir: "tests/fixtures/clean-apps/ai-layer-clean" },
  { name: "scan-clean", dir: "tests/fixtures/scan/clean" },
];

/**
 * Folds a `Finding[]` into a plain, deterministically-ordered
 * `Record<ruleId, count>` — keys sorted ascending so the object is stable
 * across runs and safe to feed straight into `toMatchSnapshot()`.
 */
export function summarize(findings: Finding[]): Record<string, number> {
  const counts = new Map<string, number>();

  for (const finding of findings) {
    counts.set(finding.ruleId, (counts.get(finding.ruleId) ?? 0) + 1);
  }

  const sortedEntries = Array.from(counts.entries()).sort(([ruleIdA], [ruleIdB]) =>
    ruleIdA.localeCompare(ruleIdB),
  );

  return Object.fromEntries(sortedEntries);
}

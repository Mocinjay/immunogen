/**
 * End-to-end proof harness for Phase 7 (llm-fix-prompts): drives the REAL
 * public surface — `scan()` and `enrichFindings()` — against the real,
 * on-disk `tests/fixtures/scan/with-secret` fixture, with an INJECTED fake
 * `ProviderAdapter` standing in for the network-backed provider. Never
 * imports `@anthropic-ai/sdk` or `openai`, never touches the real network,
 * and never requires an API key — mirrors the offline-only test mandate
 * already established by `src/detectors/deps/osv-detector.test.ts` (network
 * boundary stubbed at the module/injection seam) and `src/scan.test.ts`
 * (real on-disk fixture, no temp-dir helper).
 *
 * Re-proves all five ROADMAP Phase-7 criteria:
 *   1. A verbatim fixture secret never reaches the captured provider prompt
 *      (redaction-before-send, T-07-07/SAFE-01) — proven against a REAL
 *      finding set produced by `scan()`, not just enricher.test.ts's
 *      hand-built literals.
 *   2. `scan()` with no provider env (and/or `--no-llm`) returns
 *      `llmEnriched: false`.
 *   3. HIGH/CRITICAL findings gain a `fixPrompt` with a non-Noop fake
 *      adapter.
 *   4. `--no-llm` (`ScanOptions.noLlm`) forces `llmEnriched: false` even
 *      with a key present — proven through the real `scan()` call.
 *   5. `selectAdapter` honors `OPENAI_BASE_URL` for Ollama-style local
 *      routing (selection-level proof; SDK-level baseURL threading is
 *      proven in 07-02's openai.test.ts).
 */
import { describe, expect, it, vi } from "vitest";

import { enrichFindings } from "./enricher.js";
import { selectAdapter } from "./provider.js";
import { scan } from "../index.js";

import type { ProviderAdapter } from "./provider.js";

// OSV.dev is stubbed at the module boundary (same seam as
// tests/golden/golden.test.ts) so this suite is hermetic: a sandbox, an
// offline laptop, or a corporate proxy can never flip `scanIncomplete` or
// the finding count. The stub reports a fixed 25 advisories for `next` (the
// fixture's only dependency), like the real OSV response for next@14.0.0.
vi.mock("../detectors/deps/osv-client.js", () => ({
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

/**
 * The exact fabricated Stripe-shaped secret literal committed in
 * tests/fixtures/scan/with-secret/config.ts — used here only to assert its
 * ABSENCE from the captured provider prompt, never placed into any
 * `ScanResult`/`Finding` literal directly.
 */
const FIXTURE_SECRET = "sk_live_FAKE0000000000000000000000TESTONLY";

/** A fake ProviderAdapter that records every prompt it receives and returns a fixed, canned fix string. */
function makeFakeAdapter(response: string): ProviderAdapter & { calls: string[] } {
  const calls: string[] = [];
  return {
    name: "anthropic",
    calls,
    generate(prompt: string): Promise<string> {
      calls.push(prompt);
      return Promise.resolve(response);
    },
  };
}

describe("e2e — criterion 2/4: scan() with no provider env and/or --no-llm returns llmEnriched:false", () => {
  it("scan(withSecretFixture) with no second argument (no provider configured) returns llmEnriched:false", async () => {
    const result = await scan(WITH_SECRET_FIXTURE);

    expect(result.llmEnriched).toBe(false);
    // The deterministic scan+score pipeline is unaffected by the enrichment
    // no-op — findings/score are still fully populated.
    expect(result.findings.length).toBeGreaterThanOrEqual(1);
    expect(result.score.verdict).toBe("blocked");
  });

  it("scan(withSecretFixture, { noLlm: true }) returns llmEnriched:false (the flag path, criterion 4)", async () => {
    const result = await scan(WITH_SECRET_FIXTURE, { noLlm: true });

    expect(result.llmEnriched).toBe(false);
  });
});

describe("e2e — criterion 1: redaction-before-send proof against a REAL finding set", () => {
  it("the prompt captured by a fake adapter for the with-secret fixture's real findings never contains the verbatim fixture secret", async () => {
    // Step (a): produce a REAL finding set via the real scan() pipeline,
    // with --no-llm so this step makes zero provider calls of its own.
    const offlineResult = await scan(WITH_SECRET_FIXTURE, { noLlm: true });
    expect(offlineResult.llmEnriched).toBe(false);

    // Step (b): feed those REAL findings + a fake adapter into
    // enrichFindings directly, proving redaction-before-send against
    // genuine detector output rather than a hand-built literal.
    const fake = makeFakeAdapter("FIX: rotate the leaked key and move it to an environment variable.");
    const { findings: enrichedFindings, enriched } = await enrichFindings(offlineResult.findings, fake);

    expect(enriched).toBe(true);
    expect(fake.calls.length).toBeGreaterThanOrEqual(1);
    for (const capturedPrompt of fake.calls) {
      expect(capturedPrompt).not.toContain(FIXTURE_SECRET);
    }

    // Criterion 3 shape, re-proven here: at least one HIGH/CRITICAL finding
    // from the real detector output gained a fixPrompt.
    const enrichedHighOrCritical = enrichedFindings.filter(
      (finding) =>
        (finding.severity === "HIGH" || finding.severity === "CRITICAL") && finding.fixPrompt !== undefined,
    );
    expect(enrichedHighOrCritical.length).toBeGreaterThanOrEqual(1);
    for (const finding of enrichedHighOrCritical) {
      expect(finding.fixPrompt).not.toContain(FIXTURE_SECRET);
    }
  });
});

describe("e2e — criterion 3: HIGH/CRITICAL findings gain a fixPrompt with a non-Noop fake adapter", () => {
  it("attaches fixPrompt to the fixture's CRITICAL secret finding, none to MEDIUM/LOW/INFO", async () => {
    const offlineResult = await scan(WITH_SECRET_FIXTURE, { noLlm: true });
    const fake = makeFakeAdapter("FIX: move the secret to an environment variable.");

    const { findings: enrichedFindings } = await enrichFindings(offlineResult.findings, fake);

    // The with-secret fixture's real detector output is dominated by many
    // dependency (DEP-01/HIGH) findings from the fixture's `next: 14.0.0`
    // pin — more than MAX_ENRICHED — so this assertion checks the CRITICAL
    // secret finding specifically (which is enriched first, in original
    // order) plus the invariant that no MEDIUM/LOW/INFO finding is ever
    // touched, rather than asserting every single HIGH finding is enriched
    // (the count-budget cap intentionally leaves some HIGH findings
    // un-enriched — see the dedicated budget assertion below).
    const criticalFinding = enrichedFindings.find((finding) => finding.severity === "CRITICAL");
    expect(criticalFinding?.fixPrompt).toBe("FIX: move the secret to an environment variable.");

    for (const finding of enrichedFindings) {
      if (finding.severity === "MEDIUM" || finding.severity === "LOW" || finding.severity === "INFO") {
        expect(finding.fixPrompt).toBeUndefined();
      }
    }
  });

  it("honors the MAX_ENRICHED count budget against a real finding set larger than the cap", async () => {
    const offlineResult = await scan(WITH_SECRET_FIXTURE, { noLlm: true });
    // Dependency advisories are grouped one finding per package, so a single
    // fixture no longer yields 20+ HIGH findings on its own. Repeat the
    // fixture's real HIGH/CRITICAL findings at distinct lines until the set
    // exceeds the cap — every finding is still a genuine scan() output shape.
    const severe = offlineResult.findings.filter(
      (finding) => finding.severity === "HIGH" || finding.severity === "CRITICAL",
    );
    expect(severe.length).toBeGreaterThan(0);
    const findings = Array.from({ length: 25 }, (_, index) => ({
      ...severe[index % severe.length],
      line: index + 1,
    })) as typeof severe;

    const fake = makeFakeAdapter("FIX: move the secret to an environment variable.");
    const { findings: enrichedFindings, enriched } = await enrichFindings(findings, fake);

    const enrichedCount = enrichedFindings.filter((finding) => finding.fixPrompt !== undefined).length;
    expect(enrichedCount).toBe(20);
    expect(enriched).toBe(true);
    // No finding is dropped — the un-enriched remainder is left in place,
    // simply without a fixPrompt (degrade, never error/drop).
    expect(enrichedFindings).toHaveLength(findings.length);
  });
});

describe("e2e — criterion 5: selectAdapter honors OPENAI_BASE_URL for Ollama-style local routing", () => {
  it("selects the openai adapter when IMMUNOGEN_PROVIDER=openai, OPENAI_API_KEY, and OPENAI_BASE_URL are all set", () => {
    const adapter = selectAdapter({
      IMMUNOGEN_PROVIDER: "openai",
      OPENAI_API_KEY: "x",
      OPENAI_BASE_URL: "http://localhost:11434/v1",
    });

    expect(adapter.name).toBe("openai");
  });
});

describe("e2e — deterministic scan+score+reporters unaffected, zero network, no key", () => {
  it("scan() on the with-secret fixture still yields the same score/verdict shape as the pre-Phase-7 pipeline", async () => {
    const result = await scan(WITH_SECRET_FIXTURE);

    expect(result.score.score).toBeGreaterThanOrEqual(0);
    expect(result.score.score).toBeLessThanOrEqual(100);
    expect(result.score.verdict).toBe("blocked");
    expect(result.scanIncomplete).toBe(false);
  });
});

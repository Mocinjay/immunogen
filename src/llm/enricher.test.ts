import { describe, expect, it } from "vitest";

import { enrichFindings } from "./enricher.js";
import { NoopAdapter } from "./adapters/index.js";

import type { ProviderAdapter } from "./provider.js";

import type { Finding, Severity } from "../core/types.js";

/**
 * A verbatim, fabricated Anthropic-shaped API key — used ONLY as test input
 * data, never a real credential. Its absence from the captured prompt is
 * this suite's redaction-before-send proof (mirrors src/llm/redactor.test.ts's
 * fixture style, per the plan's read_first list).
 */
const FAKE_ANTHROPIC_KEY = "sk-ant-api03-FAKE0000000000000000000000TESTONLY";

/** Builds a minimal, fully-typed Finding literal with the given severity/matchedText overrides. */
function makeFinding(overrides: Partial<Finding> & { severity: Severity }): Finding {
  return {
    ruleId: "SEC-01",
    category: "secrets",
    detectorName: "secretsDetector",
    file: "src/config.ts",
    line: 12,
    confidence: "HIGH",
    message: "Hardcoded API key detected",
    remediation: "Move the key to an environment variable.",
    ...overrides,
  };
}

/** A fake ProviderAdapter that records every prompt it was called with and returns a fixed string. */
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

describe("enrichFindings — Noop short-circuit (offline default)", () => {
  it("returns enriched:false and makes no adapter calls with a NoopAdapter", async () => {
    const findings = [makeFinding({ severity: "CRITICAL" })];

    const result = await enrichFindings(findings, new NoopAdapter());

    expect(result.enriched).toBe(false);
    expect(result.findings[0]?.fixPrompt).toBeUndefined();
  });

  it("also short-circuits for a fake adapter literally named noop, without calling generate", async () => {
    const fake = makeFakeAdapter("FIX: rotate the key");
    const noopNamedFake: ProviderAdapter & { calls: string[] } = { ...fake, name: "noop" };
    const findings = [makeFinding({ severity: "HIGH" })];

    const result = await enrichFindings(findings, noopNamedFake);

    expect(result.enriched).toBe(false);
    expect(noopNamedFake.calls).toHaveLength(0);
  });
});

describe("enrichFindings — attaches fixPrompt for HIGH/CRITICAL with a real fake adapter", () => {
  it("attaches the fake adapter's response as fixPrompt to a CRITICAL finding and reports enriched:true", async () => {
    const fake = makeFakeAdapter("FIX: rotate the key");
    const findings = [makeFinding({ severity: "CRITICAL" })];

    const result = await enrichFindings(findings, fake);

    expect(result.enriched).toBe(true);
    expect(result.findings[0]?.fixPrompt).toBe("FIX: rotate the key");
  });

  it("attaches fixPrompt to a HIGH finding too", async () => {
    const fake = makeFakeAdapter("FIX: rotate the key");
    const findings = [makeFinding({ severity: "HIGH" })];

    const result = await enrichFindings(findings, fake);

    expect(result.findings[0]?.fixPrompt).toBe("FIX: rotate the key");
  });

  it("never mutates the input findings array or its objects", async () => {
    const fake = makeFakeAdapter("FIX: rotate the key");
    const original = makeFinding({ severity: "CRITICAL" });
    const findings = [original];

    const result = await enrichFindings(findings, fake);

    expect(original.fixPrompt).toBeUndefined();
    expect(findings[0]).toBe(original);
    expect(result.findings[0]).not.toBe(original);
  });

  it("preserves original ordering", async () => {
    const fake = makeFakeAdapter("FIX: rotate the key");
    const findings = [
      makeFinding({ severity: "CRITICAL", file: "a.ts" }),
      makeFinding({ severity: "LOW", file: "b.ts" }),
      makeFinding({ severity: "HIGH", file: "c.ts" }),
    ];

    const result = await enrichFindings(findings, fake);

    expect(result.findings.map((f) => f.file)).toEqual(["a.ts", "b.ts", "c.ts"]);
  });
});

describe("enrichFindings — selection is HIGH/CRITICAL only", () => {
  it("does not call the adapter and attaches no fixPrompt for MEDIUM/LOW/INFO findings", async () => {
    const fake = makeFakeAdapter("FIX: rotate the key");
    const findings = [
      makeFinding({ severity: "MEDIUM" }),
      makeFinding({ severity: "LOW" }),
      makeFinding({ severity: "INFO" }),
    ];

    const result = await enrichFindings(findings, fake);

    expect(fake.calls).toHaveLength(0);
    expect(result.enriched).toBe(false);
    for (const finding of result.findings) {
      expect(finding.fixPrompt).toBeUndefined();
    }
  });

  it("only sends HIGH/CRITICAL findings when the set is mixed", async () => {
    const fake = makeFakeAdapter("FIX: rotate the key");
    const findings = [
      makeFinding({ severity: "CRITICAL" }),
      makeFinding({ severity: "MEDIUM" }),
      makeFinding({ severity: "HIGH" }),
      makeFinding({ severity: "LOW" }),
    ];

    await enrichFindings(findings, fake);

    expect(fake.calls).toHaveLength(2);
  });
});

describe("enrichFindings — redaction-before-send proof (T-07-07, SAFE-01)", () => {
  it("the captured prompt for a finding whose matchedText contains a verbatim Anthropic key does NOT contain that verbatim key", async () => {
    const fake = makeFakeAdapter("FIX: rotate the key");
    const findings = [
      makeFinding({
        severity: "CRITICAL",
        matchedText: `const key = "${FAKE_ANTHROPIC_KEY}";`,
      }),
    ];

    await enrichFindings(findings, fake);

    expect(fake.calls).toHaveLength(1);
    expect(fake.calls[0]).not.toContain(FAKE_ANTHROPIC_KEY);
    expect(fake.calls[0]).toContain("[REDACTED]");
  });

  it("also redacts a verbatim key embedded in the finding's message", async () => {
    const fake = makeFakeAdapter("FIX: rotate the key");
    const findings = [
      makeFinding({
        severity: "HIGH",
        message: `Hardcoded key found: ${FAKE_ANTHROPIC_KEY}`,
      }),
    ];

    await enrichFindings(findings, fake);

    expect(fake.calls[0]).not.toContain(FAKE_ANTHROPIC_KEY);
  });
});

describe("enrichFindings — count budget (MAX_ENRICHED)", () => {
  it("caps the number of enriched findings at 20, leaving the rest un-enriched without error", async () => {
    const fake = makeFakeAdapter("FIX: rotate the key");
    const findings = Array.from({ length: 25 }, (_, i) =>
      makeFinding({ severity: "CRITICAL", file: `file-${i}.ts` }),
    );

    const result = await enrichFindings(findings, fake);

    expect(fake.calls).toHaveLength(20);
    const enrichedCount = result.findings.filter((f) => f.fixPrompt !== undefined).length;
    expect(enrichedCount).toBe(20);
    expect(result.enriched).toBe(true);
    expect(result.findings).toHaveLength(25);
  });
});

describe("enrichFindings — per-finding adapter failure does not abort the pass", () => {
  it("leaves a throwing finding un-enriched while others still succeed", async () => {
    const calls: string[] = [];
    let callCount = 0;
    const flakyAdapter: ProviderAdapter = {
      name: "anthropic",
      generate(prompt: string): Promise<string> {
        calls.push(prompt);
        callCount += 1;
        if (callCount === 1) {
          return Promise.reject(new Error("provider unavailable"));
        }
        return Promise.resolve("FIX: rotate the key");
      },
    };
    const findings = [
      makeFinding({ severity: "CRITICAL", file: "first.ts" }),
      makeFinding({ severity: "CRITICAL", file: "second.ts" }),
    ];

    const result = await enrichFindings(findings, flakyAdapter);

    expect(result.findings[0]?.fixPrompt).toBeUndefined();
    expect(result.findings[1]?.fixPrompt).toBe("FIX: rotate the key");
    expect(result.enriched).toBe(true);
  });

  it("reports enriched:false when every call throws", async () => {
    const throwingAdapter: ProviderAdapter = {
      name: "anthropic",
      generate(): Promise<string> {
        return Promise.reject(new Error("always fails"));
      },
    };
    const findings = [makeFinding({ severity: "CRITICAL" })];

    const result = await enrichFindings(findings, throwingAdapter);

    expect(result.enriched).toBe(false);
    expect(result.findings[0]?.fixPrompt).toBeUndefined();
  });

  it("also degrades gracefully when generate resolves to an empty string", async () => {
    const emptyAdapter: ProviderAdapter = {
      name: "anthropic",
      generate(): Promise<string> {
        return Promise.resolve("");
      },
    };
    const findings = [makeFinding({ severity: "CRITICAL" })];

    const result = await enrichFindings(findings, emptyAdapter);

    expect(result.enriched).toBe(false);
    expect(result.findings[0]?.fixPrompt).toBeUndefined();
  });
});

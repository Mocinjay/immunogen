import { describe, expect, it } from "vitest";

import { checkFallback, FALLBACK_VULNERABLE_NPM } from "./osv-fallback.js";

describe("checkFallback — bundled offline vulnerable-version list", () => {
  it("flags lodash 4.17.20 (below the 4.17.21 fix) with an advisory id and severity", () => {
    const hit = checkFallback("lodash", "4.17.20");

    expect(hit).toBeDefined();
    expect(hit?.advisoryId).toMatch(/\S+/);
    expect(hit?.severity).toMatch(/^(CRITICAL|HIGH|MEDIUM|LOW|INFO)$/);
  });

  it("does NOT flag lodash 4.17.21 (at the fixed version)", () => {
    const hit = checkFallback("lodash", "4.17.21");

    expect(hit).toBeUndefined();
  });

  it("does NOT flag lodash versions above the fixed floor", () => {
    const hit = checkFallback("lodash", "4.17.22");

    expect(hit).toBeUndefined();
  });

  it("flags minimist 1.2.5 (below the 1.2.6 fix) and axios 1.5.0 (below the 1.6.0 fix)", () => {
    expect(checkFallback("minimist", "1.2.5")).toBeDefined();
    expect(checkFallback("axios", "1.5.0")).toBeDefined();
  });

  it("does NOT flag the safe/current minimist and axios versions", () => {
    expect(checkFallback("minimist", "1.2.8")).toBeUndefined();
    expect(checkFallback("axios", "1.7.0")).toBeUndefined();
  });

  it("does NOT flag patched backport releases on older lines (semver 5.7.2/6.3.1, minimist 0.2.4, ws 7.5.10)", () => {
    expect(checkFallback("semver", "5.7.2")).toBeUndefined();
    expect(checkFallback("semver", "6.3.1")).toBeUndefined();
    expect(checkFallback("minimist", "0.2.4")).toBeUndefined();
    expect(checkFallback("ws", "7.5.10")).toBeUndefined();
  });

  it("still flags versions below the backport on that line, and lines with no backport", () => {
    expect(checkFallback("semver", "5.7.1")).toBeDefined();
    expect(checkFallback("semver", "6.3.0")).toBeDefined();
    expect(checkFallback("semver", "5.6.0")).toBeDefined();
    expect(checkFallback("semver", "4.3.6")).toBeDefined();
    expect(checkFallback("ws", "7.5.9")).toBeDefined();
  });

  it("does NOT flag a package that is not in the bundled list", () => {
    const hit = checkFallback("some-unlisted-pkg", "1.0.0");

    expect(hit).toBeUndefined();
  });

  it("handles a malformed/non-numeric version string without throwing, returning no hit", () => {
    // "latest" and "" are not numeric at all — cannot be compared under any
    // operator-stripping rule, so they must resolve to no-hit, never throw.
    expect(() => checkFallback("lodash", "latest")).not.toThrow();
    expect(checkFallback("lodash", "latest")).toBeUndefined();

    expect(() => checkFallback("lodash", "")).not.toThrow();
    expect(checkFallback("lodash", "")).toBeUndefined();
  });

  it("handles a true multi-operator semver RANGE (not a single pinned version) without throwing", () => {
    // A real range expression (two clauses) is not reducible by stripping
    // ONE leading operator — per the action spec, only a single leading
    // operator is stripped, so this remains unparseable and must not throw.
    expect(() => checkFallback("lodash", ">=1.0.0 <2.0.0")).not.toThrow();
    expect(checkFallback("lodash", ">=1.0.0 <2.0.0")).toBeUndefined();
  });

  it("strips a single leading range operator (^, ~, >=, =, v) before comparing", () => {
    // 4.17.20 is vulnerable regardless of which single leading operator prefixes it.
    expect(checkFallback("lodash", "v4.17.20")).toBeDefined();
    expect(checkFallback("lodash", "=4.17.20")).toBeDefined();
  });

  it("bundles at least 15 entries, including the canonical lodash/minimist/axios examples", () => {
    expect(FALLBACK_VULNERABLE_NPM.length).toBeGreaterThanOrEqual(15);

    const names = FALLBACK_VULNERABLE_NPM.map((entry) => entry.name);
    expect(names).toContain("lodash");
    expect(names).toContain("minimist");
    expect(names).toContain("axios");
  });

  it("every bundled entry carries name, vulnerableBelow, advisoryId, severity, and title", () => {
    for (const entry of FALLBACK_VULNERABLE_NPM) {
      expect(entry.name).toMatch(/\S+/);
      expect(entry.vulnerableBelow).toMatch(/^\d+\.\d+\.\d+$/);
      expect(entry.advisoryId).toMatch(/\S+/);
      expect(entry.severity).toMatch(/^(CRITICAL|HIGH|MEDIUM|LOW|INFO)$/);
      expect(entry.title).toMatch(/\S+/);
      for (const fix of entry.backportFixes ?? []) {
        expect(fix).toMatch(/^\d+\.\d+\.\d+$/);
      }
    }
  });
});

import { describe, expect, it } from "vitest";

import { cspDetector } from "./csp-detector.js";

import type { DetectorContext, StackHints } from "../../core/types.js";

/** StackHints with "nextjs" present — the stack gate this detector requires to ever fire. */
const NEXTJS_STACK_HINTS: StackHints = {
  frameworks: new Set(["nextjs"]),
  hasSupabase: false,
  hasFirebase: false,
  hasStripe: false,
  hasEnvFiles: false,
  hasMcpJson: false,
  hasClaudeSkills: false,
  hasCursorRules: false,
};

/** StackHints with an empty frameworks set — the non-Next.js gate-off case (Test 4). */
const NON_NEXTJS_STACK_HINTS: StackHints = {
  frameworks: new Set(),
  hasSupabase: false,
  hasFirebase: false,
  hasStripe: false,
  hasEnvFiles: false,
  hasMcpJson: false,
  hasClaudeSkills: false,
  hasCursorRules: false,
};

/** Builds a DetectorContext literal for `content` at the given `filePath` and `stackHints`, without the ingestion layer. */
function makeContext(
  content: string,
  filePath = "next.config.js",
  stackHints: StackHints = NEXTJS_STACK_HINTS,
): DetectorContext {
  return {
    filePath,
    content,
    stackHints,
    fileSet: new Map(),
  };
}

describe("cspDetector — HDR-01 (missing Content-Security-Policy in next.config)", () => {
  it("flags a next.config.js with a headers() export but no CSP as MEDIUM under nextjs stack", async () => {
    const ctx = makeContext(
      [
        "module.exports = {",
        "  async headers() {",
        "    return [{ source: '/(.*)', headers: [{ key: 'X-Frame-Options', value: 'DENY' }] }];",
        "  },",
        "};",
      ].join("\n"),
      "next.config.js",
    );

    const findings = await cspDetector.detect(ctx);

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      ruleId: "HDR-01",
      category: "cors-headers",
      severity: "MEDIUM",
      file: "next.config.js",
      line: 1,
    });
    expect(["LOW", "MEDIUM"]).toContain(findings[0]?.confidence);
  });

  it("flags a next.config.ts with no headers() export at all as HDR-01 (no CSP configured)", async () => {
    const ctx = makeContext(
      ["import type { NextConfig } from 'next';", "", "const config: NextConfig = {};", "", "export default config;"].join(
        "\n",
      ),
      "next.config.ts",
    );

    const findings = await cspDetector.detect(ctx);

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      ruleId: "HDR-01",
      severity: "MEDIUM",
      file: "next.config.ts",
      line: 1,
    });
  });

  it("does NOT flag a next.config.js whose content includes Content-Security-Policy (clean)", async () => {
    const ctx = makeContext(
      [
        "module.exports = {",
        "  async headers() {",
        "    return [{",
        "      source: '/(.*)',",
        "      headers: [{ key: 'Content-Security-Policy', value: \"default-src 'self'\" }],",
        "    }];",
        "  },",
        "};",
      ].join("\n"),
      "next.config.js",
    );

    const findings = await cspDetector.detect(ctx);

    expect(findings).toHaveLength(0);
  });

  it("does NOT flag a CSP-less next.config.js when stackHints.frameworks lacks nextjs (stack gate no-op)", async () => {
    const ctx = makeContext(
      ["module.exports = {", "  async headers() { return []; },", "};"].join("\n"),
      "next.config.js",
      NON_NEXTJS_STACK_HINTS,
    );

    const findings = await cspDetector.detect(ctx);

    expect(findings).toHaveLength(0);
  });

  it("does NOT flag the forbidden absence inside a __tests__/fixtures path (FP allowlist guard)", async () => {
    const ctx = makeContext(
      ["module.exports = {", "  async headers() { return []; },", "};"].join("\n"),
      "src/__tests__/fixtures/next.config.js",
    );

    const findings = await cspDetector.detect(ctx);

    expect(findings).toHaveLength(0);
  });
});

describe("cspDetector — no-throw contract", () => {
  // NOTE: this detector is an ABSENCE check — empty/malformed content with no
  // "Content-Security-Policy" substring legitimately satisfies the
  // absence condition under an active nextjs stack hint, so the no-throw
  // contract is exercised here via the NON-nextjs stack gate (a definite
  // [] outcome) rather than asserting [] on every input regardless of
  // stack hints, which would contradict the detector's own behavior spec.
  it("resolves to [] for empty content when the stack gate is off (and never rejects)", async () => {
    const ctx = makeContext("", "next.config.js", NON_NEXTJS_STACK_HINTS);

    await expect(cspDetector.detect(ctx)).resolves.toEqual([]);
  });

  it("resolves to [] for malformed/binary-ish content without rejecting (stack gate off)", async () => {
    const ctx = makeContext(" � garbled content", "next.config.js", NON_NEXTJS_STACK_HINTS);

    await expect(cspDetector.detect(ctx)).resolves.toEqual([]);
  });

  it("never rejects for malformed content under an active nextjs stack gate (absence check still resolves, not throws)", async () => {
    const ctx = makeContext(" � garbled content");

    // Active nextjs gate + no CSP marker in the garbled text is a legitimate
    // single-finding absence result (not a [] outcome) — the assertion under
    // test is the PROMISE RESOLVES (no rejection), not that findings is empty.
    await expect(cspDetector.detect(ctx)).resolves.toHaveLength(1);
  });
});

describe("cspDetector — config", () => {
  it("declares category cors-headers and a name of 'csp'", () => {
    expect(cspDetector.config.name).toBe("csp");
    expect(cspDetector.config.category).toBe("cors-headers");
  });

  it("declares globs scoped to next.config.* variants", () => {
    expect(cspDetector.config.globs).toContain("next.config.js");
    expect(cspDetector.config.globs).toContain("next.config.ts");
  });

  it("declares requiresStack containing nextjs", () => {
    expect(cspDetector.config.requiresStack).toContain("nextjs");
  });
});

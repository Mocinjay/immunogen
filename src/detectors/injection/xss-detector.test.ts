import { describe, expect, it } from "vitest";

import { buildAstCache } from "../../core/parse/ast-cache.js";
import { xssDetector } from "./xss-detector.js";

import type { DetectorContext, StackHints } from "../../core/types.js";

/** Minimal StackHints — xssDetector is framework-agnostic (no stack gate). */
const STACK_HINTS: StackHints = {
  frameworks: new Set(),
  hasSupabase: false,
  hasFirebase: false,
  hasStripe: false,
  hasEnvFiles: false,
  hasMcpJson: false,
  hasClaudeSkills: false,
  hasCursorRules: false,
};

/**
 * Builds a DetectorContext for `content` at `filePath` with a REAL `ctx.ast`
 * from the project's own `buildAstCache` (JSX is parsed — plugins include
 * "jsx"), the same path the registry uses.
 */
function makeContext(content: string, filePath = "src/components/Bio.tsx"): DetectorContext {
  const { astCache } = buildAstCache(new Map([[filePath, content]]));
  return {
    filePath,
    content,
    ast: astCache.get(filePath),
    stackHints: STACK_HINTS,
    fileSet: new Map([[filePath, content]]),
  };
}

describe("xssDetector — INJECT-01 vulnerable (non-literal, no sanitizer)", () => {
  it("flags dangerouslySetInnerHTML with a non-literal value as INJECT-01 HIGH/MEDIUM", async () => {
    const content = [
      "export function Bio({ userBio }) {",
      "  return <div dangerouslySetInnerHTML={{ __html: userBio }} />;",
      "}",
      "",
    ].join("\n");
    const ctx = makeContext(content);

    const findings = await xssDetector.detect(ctx);

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      ruleId: "INJECT-01",
      category: "injection",
      severity: "HIGH",
      confidence: "MEDIUM",
      file: "src/components/Bio.tsx",
      line: 2,
    });
  });
});

describe("xssDetector — INJECT-01 clean (literal value)", () => {
  it("produces zero findings for a string-literal __html", async () => {
    const content = [
      "export function Static() {",
      '  return <div dangerouslySetInnerHTML={{ __html: "<b>static</b>" }} />;',
      "}",
      "",
    ].join("\n");
    const ctx = makeContext(content);

    const findings = await xssDetector.detect(ctx);

    expect(findings).toHaveLength(0);
  });

  it("produces zero findings for a template literal with no expressions", async () => {
    const content = [
      "export function Static() {",
      "  return <div dangerouslySetInnerHTML={{ __html: `<b>static</b>` }} />;",
      "}",
      "",
    ].join("\n");
    const ctx = makeContext(content);

    const findings = await xssDetector.detect(ctx);

    expect(findings).toHaveLength(0);
  });
});

describe("xssDetector — INJECT-01 clean (sanitizer present)", () => {
  it("produces zero findings when DOMPurify.sanitize wraps the value inline", async () => {
    const content = [
      "import DOMPurify from 'dompurify';",
      "export function Bio({ userBio }) {",
      "  return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(userBio) }} />;",
      "}",
      "",
    ].join("\n");
    const ctx = makeContext(content);

    const findings = await xssDetector.detect(ctx);

    expect(findings).toHaveLength(0);
  });

  it("produces zero findings when DOMPurify.sanitize appears elsewhere in the file", async () => {
    const content = [
      "import DOMPurify from 'dompurify';",
      "export function Bio({ userBio }) {",
      "  const clean = DOMPurify.sanitize(userBio);",
      "  return <div dangerouslySetInnerHTML={{ __html: clean }} />;",
      "}",
      "",
    ].join("\n");
    const ctx = makeContext(content);

    const findings = await xssDetector.detect(ctx);

    expect(findings).toHaveLength(0);
  });
});

describe("xssDetector — INJECT-01 clean (no dangerouslySetInnerHTML)", () => {
  it("produces zero findings for a file with no dangerouslySetInnerHTML", async () => {
    const content = ["export function Plain({ name }) {", "  return <div>{name}</div>;", "}", ""].join("\n");
    const ctx = makeContext(content);

    const findings = await xssDetector.detect(ctx);

    expect(findings).toHaveLength(0);
  });
});

describe("xssDetector — INJECT-01 clean (FP allowlist path)", () => {
  it("produces zero findings for vulnerable JSX inside a fixtures path", async () => {
    const content = [
      "export function Bio({ userBio }) {",
      "  return <div dangerouslySetInnerHTML={{ __html: userBio }} />;",
      "}",
      "",
    ].join("\n");
    const ctx = makeContext(content, "src/__tests__/fixtures/bio.tsx");

    const findings = await xssDetector.detect(ctx);

    expect(findings).toHaveLength(0);
  });
});

describe("xssDetector — no-AST guard (PITFALLS Pitfall 3)", () => {
  it("produces zero findings and does not throw when ctx.ast is undefined", async () => {
    const ctx: DetectorContext = {
      filePath: "src/components/Bio.tsx",
      content: "const x = <div dangerouslySetInnerHTML={{ __html: userBio }} />;",
      ast: undefined,
      stackHints: STACK_HINTS,
      fileSet: new Map(),
    };

    await expect(xssDetector.detect(ctx)).resolves.toEqual([]);
  });
});

describe("xssDetector — config", () => {
  it("declares name 'xss' and category 'injection'", () => {
    expect(xssDetector.config.name).toBe("xss");
    expect(xssDetector.config.category).toBe("injection");
  });
});

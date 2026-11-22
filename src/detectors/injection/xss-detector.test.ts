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

describe("xssDetector — INJECT-01 beyond React (the video's <script> username)", () => {
  async function sinks(content: string, filePath = "src/profile.ts"): Promise<string[]> {
    const findings = await xssDetector.detect(makeContext(content, filePath));
    return findings.map((finding) => `${finding.ruleId} L${finding.line} ${finding.matchedText ?? ""}`);
  }

  it.each([
    ["innerHTML with a template literal", "card.innerHTML = `<h2>${user.username}</h2>`;", "INJECT-01 L1 innerHTML"],
    ["innerHTML with a property read", "el.innerHTML = comment.body;", "INJECT-01 L1 innerHTML"],
    ["innerHTML += concatenation", "list.innerHTML += '<li>' + item.name + '</li>';", "INJECT-01 L1 innerHTML"],
    ["insertAdjacentHTML", "feed.insertAdjacentHTML('beforeend', `<p>${post.text}</p>`);", "INJECT-01 L1 insertAdjacentHTML"],
    ["document.write", "document.write('<b>' + params.get('name') + '</b>');", "INJECT-01 L1 document.write"],
  ])("flags %s", async (_label, code, expected) => {
    expect(await sinks(code)).toEqual([expected]);
  });

  it.each([
    ["a literal innerHTML", "el.innerHTML = '<span>Loading…</span>';"],
    ["clearing innerHTML", 'el.innerHTML = "";'],
    ["textContent", "el.textContent = user.username;"],
    ["a sanitized value", "el.innerHTML = DOMPurify.sanitize(`<h2>${user.username}</h2>`);"],
    ["an escaped value", "el.innerHTML = `<h2>${escapeHtml(user.username)}</h2>`;"],
  ])("does NOT flag %s", async (_label, code) => {
    expect(await sinks(code)).toEqual([]);
  });

  it("flags server HTML built from request input (reflected XSS)", async () => {
    const express = 'app.get("/hello", (req, res) => { res.send(`<h1>Hello ${req.query.name}</h1>`); });';
    expect(await sinks(express, "server/index.ts")).toEqual(["INJECT-01 L1 res.send"]);
    const next = ["export async function GET(req) {", '  const q = req.nextUrl.searchParams.get("q");', "  return new Response(`<p>Results for ${q}</p>`, { headers: { 'content-type': 'text/html' } });", "}"].join("\n");
    expect(await sinks(next, "app/search/route.ts")).toEqual(["INJECT-01 L3 new Response"]);
  });

  it("does NOT flag server responses without request input or without HTML", async () => {
    expect(await sinks('app.get("/", (req, res) => { res.send(`<h1>${APP_NAME}</h1>`); });', "server/index.ts")).toEqual([]);
    expect(await sinks('app.get("/", (req, res) => { res.send(`Hello ${req.query.name}`); });', "server/index.ts")).toEqual([]);
  });

  it("flags Vue v-html and Svelte {@html} with non-literal values", async () => {
    expect(await sinks('<template>\n  <div v-html="user.bio"></div>\n</template>', "src/components/Bio.vue")).toEqual(["INJECT-01 L2 v-html"]);
    expect(await sinks("<p>{@html comment.body}</p>", "src/lib/Comment.svelte")).toEqual(["INJECT-01 L1 {@html}"]);
    expect(await sinks('<div v-html="\'<b>static</b>\'"></div>', "src/components/Static.vue")).toEqual([]);
    expect(await sinks('<script>import DOMPurify from "dompurify";</script>\n<div v-html="clean(user.bio)"></div>', "src/components/Safe.vue")).toEqual([]);
  });
});

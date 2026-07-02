import { describe, expect, it } from "vitest";

import { buildAstCache } from "../../core/parse/ast-cache.js";
import { routeAuthDetector } from "./route-auth-detector.js";

import type { DetectorContext, StackHints } from "../../core/types.js";

/**
 * StackHints with Next.js present — the gate AUTH-01 reads
 * (frameworks.has("nextjs")).
 */
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

/** StackHints with no Next.js — proves the stack gate (Test 5). */
const NO_NEXTJS_STACK_HINTS: StackHints = {
  ...NEXTJS_STACK_HINTS,
  frameworks: new Set(),
};

/**
 * Builds a DetectorContext for `content` at `filePath` with a REAL `ctx.ast`,
 * produced by the project's own `buildAstCache` (the same code path the
 * registry uses to populate `ScanContext.astCache`). This gives the detector
 * a genuine @babel `File` node to walk, not a hand-built stub.
 */
function makeContext(content: string, filePath: string, stackHints: StackHints = NEXTJS_STACK_HINTS): DetectorContext {
  const { astCache } = buildAstCache(new Map([[filePath, content]]));
  return {
    filePath,
    content,
    ast: astCache.get(filePath),
    stackHints,
    fileSet: new Map([[filePath, content]]),
  };
}

const ROUTE_PATH = "app/api/users/route.ts";

describe("routeAuthDetector — AUTH-01 vulnerable (no auth call)", () => {
  it("flags an exported GET handler with no auth call as AUTH-01 CRITICAL/MEDIUM at the handler line", async () => {
    const content = ["export async function GET(req) {", "  return Response.json({ ok: true });", "}", ""].join("\n");
    const ctx = makeContext(content, ROUTE_PATH);

    const findings = await routeAuthDetector.detect(ctx);

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      ruleId: "AUTH-01",
      category: "auth",
      severity: "CRITICAL",
      confidence: "MEDIUM",
      file: ROUTE_PATH,
      line: 1,
    });
  });

  it("flags an exported DELETE handler with no auth call as one AUTH-01 finding", async () => {
    const content = [
      "// line 1 comment",
      "export async function DELETE(req) {",
      "  return new Response(null, { status: 204 });",
      "}",
      "",
    ].join("\n");
    const ctx = makeContext(content, ROUTE_PATH);

    const findings = await routeAuthDetector.detect(ctx);

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ ruleId: "AUTH-01", severity: "CRITICAL", line: 2 });
  });
});

describe("routeAuthDetector — AUTH-01 clean (auth call present, file-scoped)", () => {
  it("produces zero findings when the handler calls getServerSession", async () => {
    const content = [
      "import { getServerSession } from 'next-auth';",
      "export async function GET(req) {",
      "  const session = await getServerSession();",
      "  if (!session) return new Response('Unauthorized', { status: 401 });",
      "  return Response.json({ ok: true });",
      "}",
      "",
    ].join("\n");
    const ctx = makeContext(content, ROUTE_PATH);

    const findings = await routeAuthDetector.detect(ctx);

    expect(findings).toHaveLength(0);
  });

  it("produces zero findings when the handler calls auth()", async () => {
    const content = [
      "import { auth } from '@/auth';",
      "export async function POST(req) {",
      "  const session = await auth();",
      "  return Response.json({ ok: true });",
      "}",
      "",
    ].join("\n");
    const ctx = makeContext(content, ROUTE_PATH);

    const findings = await routeAuthDetector.detect(ctx);

    expect(findings).toHaveLength(0);
  });

  it("produces zero findings when the handler calls supabase.auth.getUser()", async () => {
    const content = [
      "export async function GET(req) {",
      "  const { data } = await supabase.auth.getUser();",
      "  return Response.json(data);",
      "}",
      "",
    ].join("\n");
    const ctx = makeContext(content, ROUTE_PATH);

    const findings = await routeAuthDetector.detect(ctx);

    expect(findings).toHaveLength(0);
  });

  it("produces zero findings when the handler calls verifyToken or getUserFromRequest", async () => {
    const content = [
      "export async function PUT(req) {",
      "  const user = await getUserFromRequest(req);",
      "  if (!verifyToken(user)) return new Response('no', { status: 401 });",
      "  return Response.json({ ok: true });",
      "}",
      "",
    ].join("\n");
    const ctx = makeContext(content, ROUTE_PATH);

    const findings = await routeAuthDetector.detect(ctx);

    expect(findings).toHaveLength(0);
  });
});

describe("routeAuthDetector — AUTH-01 clean (false-positive suppression)", () => {
  it("produces zero findings when a leading // public endpoint comment is present", async () => {
    const content = [
      "// public endpoint",
      "export async function GET(req) {",
      "  return Response.json({ status: 'ok' });",
      "}",
      "",
    ].join("\n");
    const ctx = makeContext(content, ROUTE_PATH);

    const findings = await routeAuthDetector.detect(ctx);

    expect(findings).toHaveLength(0);
  });

  it("produces zero findings when the route path contains a public segment", async () => {
    const content = ["export async function GET(req) {", "  return Response.json({ status: 'ok' });", "}", ""].join("\n");
    const ctx = makeContext(content, "app/api/public/health/route.ts");

    const findings = await routeAuthDetector.detect(ctx);

    expect(findings).toHaveLength(0);
  });
});

describe("routeAuthDetector — AUTH-01 clean (stack gate)", () => {
  it("produces zero findings when the repo is not a Next.js app", async () => {
    const content = ["export async function GET(req) {", "  return Response.json({ status: 'ok' });", "}", ""].join("\n");
    const ctx = makeContext(content, ROUTE_PATH, NO_NEXTJS_STACK_HINTS);

    const findings = await routeAuthDetector.detect(ctx);

    expect(findings).toHaveLength(0);
  });
});

describe("routeAuthDetector — AUTH-01 clean (not a route file)", () => {
  it("produces zero findings for a GET-named export in a non-route helpers file", async () => {
    const content = [
      "export async function GET(req) {",
      "  return Response.json({ helper: true });",
      "}",
      "",
    ].join("\n");
    // The detector's globs only match **/app/**/route.{ts,tsx,js,jsx}; a
    // helpers.ts file is never handed to this detector by the registry, and
    // the detector itself rejects non-route filenames defensively.
    const ctx = makeContext(content, "app/api/users/helpers.ts");

    const findings = await routeAuthDetector.detect(ctx);

    expect(findings).toHaveLength(0);
  });
});

describe("routeAuthDetector — no-AST guard (PITFALLS Pitfall 3)", () => {
  it("produces zero findings and does not throw when ctx.ast is undefined", async () => {
    const ctx: DetectorContext = {
      filePath: ROUTE_PATH,
      content: "export async function GET(req) { return Response.json({}); }",
      ast: undefined,
      stackHints: NEXTJS_STACK_HINTS,
      fileSet: new Map(),
    };

    await expect(routeAuthDetector.detect(ctx)).resolves.toEqual([]);
  });
});

describe("routeAuthDetector — config", () => {
  it("declares name 'route-auth', category 'auth', and requiresStack nextjs", () => {
    expect(routeAuthDetector.config.name).toBe("route-auth");
    expect(routeAuthDetector.config.category).toBe("auth");
    expect(routeAuthDetector.config.requiresStack).toContain("nextjs");
  });
});

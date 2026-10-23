import { describe, expect, it } from "vitest";

import { buildAstCache } from "../../core/parse/ast-cache.js";
import { serverRouteAuthDetector } from "./server-route-auth-detector.js";

import type { DetectorContext, StackHints } from "../../core/types.js";

const EXPRESS_STACK: StackHints = {
  frameworks: new Set(["express"]),
  hasSupabase: false,
  hasFirebase: false,
  hasStripe: false,
  hasEnvFiles: false,
  hasMcpJson: false,
  hasClaudeSkills: false,
  hasCursorRules: false,
};

const SERVER_PATH = "server/index.ts";

function makeContext(
  content: string,
  options: { filePath?: string; stack?: StackHints; otherFiles?: Record<string, string> } = {},
): DetectorContext {
  const filePath = options.filePath ?? SERVER_PATH;
  const { astCache } = buildAstCache(new Map([[filePath, content]]));
  return {
    filePath,
    content,
    ast: astCache.get(filePath),
    stackHints: options.stack ?? EXPRESS_STACK,
    fileSet: new Map([[filePath, content], ...Object.entries(options.otherFiles ?? {})]),
  };
}

async function summarize(content: string, options?: Parameters<typeof makeContext>[1]): Promise<string[]> {
  const findings = await serverRouteAuthDetector.detect(makeContext(content, options));
  return findings.map((finding) => `${finding.severity} ${finding.matchedText ?? ""} L${String(finding.line)}`);
}

describe("serverRouteAuthDetector — unprotected routes", () => {
  it("flags unauthenticated Express routes: mutations CRITICAL, GET HIGH", async () => {
    const content = [
      "const app = express();",
      "app.post('/api/admin/reset', async (req, res) => { await db.reset(); res.json({ ok: true }); });",
      "app.get('/api/users', async (req, res) => res.json(await db.users.all()));",
    ].join("\n");

    expect(await summarize(content)).toEqual(["CRITICAL POST /api/admin/reset L2", "HIGH GET /api/users L3"]);
  });

  it("flags a router route with a named handler", async () => {
    const content = "const router = Router();\nrouter.delete('/projects/:id', deleteProject);";

    expect(await summarize(content)).toEqual(["CRITICAL DELETE /projects/:id L2"]);
  });

  it("names the framework in the message", async () => {
    const content = "app.post('/x', (c) => c.json({}));";
    const findings = await serverRouteAuthDetector.detect(
      makeContext(content, { stack: { ...EXPRESS_STACK, frameworks: new Set(["hono"]) } }),
    );

    expect(findings[0]?.message).toBe("Hono route POST /x has no authentication or authorization check.");
  });

  it("flags Fastify's route({ method, url, handler }) form", async () => {
    const content = "fastify.route({ method: 'PUT', url: '/orders/:id', handler: async (req, reply) => update(req.body) });";

    expect(await summarize(content, { stack: { ...EXPRESS_STACK, frameworks: new Set(["fastify"]) } })).toEqual([
      "CRITICAL PUT /orders/:id L1",
    ]);
  });
});

describe("serverRouteAuthDetector — protected or public routes", () => {
  it.each([
    ["an auth middleware argument", "app.post('/api/x', requireAuth, (req, res) => res.json({}));"],
    ["passport.authenticate", "app.post('/api/x', passport.authenticate('jwt', { session: false }), (req, res) => res.json({}));"],
    ["a Fastify preHandler", "fastify.post('/api/x', { preHandler: [fastify.authenticate] }, async (req) => ({}));"],
    ["an auth call in the handler", "app.post('/api/x', async (req, res) => { const user = await getCurrentUser(req); });"],
    ["a req.user check in the handler", "app.post('/api/x', (req, res) => { if (!req.user) return res.sendStatus(401); });"],
    ["a Hono jwtPayload read", "app.post('/api/x', (c) => { const p = c.get('jwtPayload'); return c.json(p); });"],
    ["a Koa ctx.state.user read", "router.post('/api/x', async (ctx) => { ctx.assert(ctx.state.user, 401); });"],
    ["a webhook signature check", "app.post('/api/hook', (req, res) => { stripe.webhooks.constructEvent(req.body, sig, secret); });"],
    ["a global auth middleware registered first", "app.use(requireAuth);\napp.post('/api/x', (req, res) => res.json({}));"],
    ["a prefix-scoped auth middleware", "app.use('/api', authMiddleware);\napp.post('/api/x', (req, res) => res.json({}));"],
    ["a public-by-nature path", "app.post('/api/auth/login', (req, res) => res.json({}));"],
    ["a health check", "app.get('/health', (req, res) => res.send('ok'));"],
    ["a // public comment", "// public\napp.post('/api/newsletter', (req, res) => res.json({}));"],
    ["a client-side axios call", "axios.get('/api/users');\naxios.post('/api/users', { name });"],
  ])("does NOT flag %s", async (_label, content) => {
    expect(await summarize(content)).toEqual([]);
  });

  it("still flags a route registered BEFORE the global auth middleware", async () => {
    const content = "app.post('/api/early', (req, res) => res.json({}));\napp.use(requireAuth);";

    expect(await summarize(content)).toEqual(["CRITICAL POST /api/early L1"]);
  });

  it("does not let a prefix-scoped middleware cover other paths", async () => {
    const content = "app.use('/admin', requireAuth);\napp.post('/api/x', (req, res) => res.json({}));";

    expect(await summarize(content)).toEqual(["CRITICAL POST /api/x L2"]);
  });

  it("downgrades to MEDIUM/LOW when another file registers auth middleware", async () => {
    const content = "router.post('/projects', (req, res) => res.json({}));";
    const findings = await serverRouteAuthDetector.detect(
      makeContext(content, {
        filePath: "server/routes/projects.ts",
        otherFiles: { "server/index.ts": "app.use('/api', requireAuth, projectsRouter);" },
      }),
    );

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ severity: "MEDIUM", confidence: "LOW" });
    expect(findings[0]?.message).toContain("verify this router is mounted behind it");
  });
});

describe("serverRouteAuthDetector — gates", () => {
  it("does nothing without an Express/Fastify/Hono/Koa stack", async () => {
    const content = "app.post('/api/x', (req, res) => res.json({}));";

    expect(await summarize(content, { stack: { ...EXPRESS_STACK, frameworks: new Set(["nextjs"]) } })).toEqual([]);
  });

  it("skips test files", async () => {
    expect(await summarize("app.post('/api/x', (req, res) => res.json({}));", { filePath: "server/app.test.ts" })).toEqual([]);
  });
});

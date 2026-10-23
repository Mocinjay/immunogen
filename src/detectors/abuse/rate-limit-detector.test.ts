import { describe, expect, it } from "vitest";

import { rateLimitDetector } from "./rate-limit-detector.js";

import type { DetectorContext, StackHints } from "../../core/types.js";

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

async function summarize(content: string, filePath: string, otherFiles: Record<string, string> = {}): Promise<string[]> {
  const ctx: DetectorContext = {
    filePath,
    content,
    stackHints: STACK_HINTS,
    fileSet: new Map([[filePath, content], ...Object.entries(otherFiles)]),
  };
  return (await rateLimitDetector.detect(ctx)).map(
    (finding) => `${finding.severity}/${finding.confidence} L${String(finding.line)} ${finding.message.slice(0, 20)}`,
  );
}

const CHAT_ROUTE = [
  'import OpenAI from "openai";',
  "const openai = new OpenAI();",
  "export async function POST(req: Request) {",
  "  return Response.json(await openai.chat.completions.create({ model: 'gpt-4o', messages: [] }));",
  "}",
].join("\n");

describe("rateLimitDetector — AI endpoints", () => {
  it("flags a Next.js route that calls an LLM with no limiter as HIGH", async () => {
    expect(await summarize(CHAT_ROUTE, "app/api/chat/route.ts")).toEqual(["HIGH/MEDIUM L3 AI endpoint calls a "]);
  });

  it.each([
    ["the Vercel AI SDK in a server action", '"use server";\nimport { streamText } from "ai";\nexport async function ask(q) { return streamText({ prompt: q }); }', "app/actions.ts"],
    ["an Express route using Anthropic", 'import Anthropic from "@anthropic-ai/sdk";\napp.post("/api/ask", async (req, res) => {});', "server/index.ts"],
    ["a FastAPI route using openai", "from openai import OpenAI\n@app.post(\"/chat\")\nasync def chat(q: str):\n    ...", "main.py"],
    ["a Go handler using go-openai", 'import "github.com/sashabaranov/go-openai"\nr.POST("/chat", chat)', "main.go"],
  ])("flags %s", async (_label, content, path) => {
    const result = await summarize(content, path);
    expect(result).toHaveLength(1);
    expect(result[0]).toMatch(/^HIGH\/MEDIUM/);
  });

  it.each([
    ["a limiter in the file", `import { Ratelimit } from "@upstash/ratelimit";\n${CHAT_ROUTE}\nconst { success } = await ratelimit.limit(ip);`],
    ["a SlowAPI decorator", 'from openai import OpenAI\n@app.post("/chat")\n@limiter.limit("5/minute")\nasync def chat():\n    ...'],
  ])("does NOT flag an AI endpoint with %s", async (_label, content) => {
    expect(await summarize(content, content.includes("def ") ? "main.py" : "app/api/chat/route.ts")).toEqual([]);
  });

  it("does NOT flag when middleware applies a limiter globally", async () => {
    const middleware = 'import { Ratelimit } from "@upstash/ratelimit";\nexport default async function middleware(req) { await ratelimit.limit(ip); }';

    expect(await summarize(CHAT_ROUTE, "app/api/chat/route.ts", { "middleware.ts": middleware })).toEqual([]);
    expect(await summarize(CHAT_ROUTE, "app/api/chat/route.ts", { "server.ts": "app.use(rateLimit({ windowMs: 60000, max: 10 }));" })).toEqual([]);
  });

  it("drops to LOW/LOW when a rate-limit library is installed but not applied here", async () => {
    const result = await summarize(CHAT_ROUTE, "app/api/chat/route.ts", {
      "package.json": JSON.stringify({ dependencies: { "@upstash/ratelimit": "2.0.0" } }),
    });

    expect(result).toEqual(["LOW/LOW L3 AI endpoint calls a "]);
  });

  it("does NOT flag non-endpoint files that use an LLM (scripts, libraries)", async () => {
    expect(await summarize('import OpenAI from "openai";\nexport const client = new OpenAI();', "lib/openai.ts")).toEqual([]);
  });
});

describe("rateLimitDetector — authentication endpoints", () => {
  it.each([
    ["a Next.js login route", "export async function POST(req) { await signIn(req); }", "app/api/auth/login/route.ts"],
    ["an Express sign-up route", 'app.post("/api/signup", async (req, res) => {});', "server/auth.ts"],
    ["a Flask password reset", '@app.route("/forgot-password", methods=["POST"])\ndef forgot():\n    ...', "app.py"],
    ["a Go register route", 'r.POST("/register", register)', "main.go"],
  ])("flags %s as MEDIUM", async (_label, content, path) => {
    const result = await summarize(content, path);
    expect(result).toHaveLength(1);
    expect(result[0]).toMatch(/^MEDIUM\/MEDIUM .*Authentication endpo/);
  });

  it("does NOT flag non-auth endpoints without LLM calls", async () => {
    expect(await summarize('app.post("/api/orders", async (req, res) => {});', "server/orders.ts")).toEqual([]);
  });

  it("skips test files", async () => {
    expect(await summarize(CHAT_ROUTE, "app/api/chat/route.test.ts")).toEqual([]);
  });
});

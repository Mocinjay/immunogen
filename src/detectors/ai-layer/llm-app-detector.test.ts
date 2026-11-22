import { describe, expect, it } from "vitest";

import { buildAstCache } from "../../core/parse/ast-cache.js";
import { llmAppDetector } from "./llm-app-detector.js";

import type { DetectorContext, StackHints } from "../../core/types.js";

const STACK_HINTS: StackHints = {
  frameworks: new Set(["nextjs"]),
  hasSupabase: false,
  hasFirebase: false,
  hasStripe: false,
  hasEnvFiles: false,
  hasMcpJson: false,
  hasClaudeSkills: false,
  hasCursorRules: false,
};

const lines = (...parts: string[]): string => parts.join("\n");

async function summarize(content: string, filePath = "app/api/support/route.ts"): Promise<string[]> {
  const { astCache } = buildAstCache(new Map([[filePath, content]]));
  const ctx: DetectorContext = { filePath, content, ast: astCache.get(filePath), stackHints: STACK_HINTS, fileSet: new Map([[filePath, content]]) };
  const findings = await llmAppDetector.detect(ctx);
  return findings.map((finding) => `${finding.ruleId} ${finding.severity} L${finding.line} ${finding.matchedText ?? ""}`);
}

const SUPPORT_BOT = lines(
  'import { streamText, tool } from "ai";',
  'import { openai } from "@ai-sdk/openai";',
  "export async function POST(req: Request) {",
  "  const { messages } = await req.json();",
  "  return streamText({",
  '    model: openai("gpt-4o"),',
  '    system: "You are a support assistant. Only refund orders under $20.",',
  "    messages,",
  "    tools: {",
  "      lookupOrder: tool({ parameters: z.object({ id: z.string() }), execute: async ({ id }) => getOrder(id) }),",
  "      issueRefund: tool({ parameters: z.object({ orderId: z.string() }), execute: async ({ orderId }) => stripe.refunds.create({ payment_intent: orderId }) }),",
  "    },",
  "  }).toDataStreamResponse();",
  "}",
);

describe("llmAppDetector — AILAYER-07 privileged tools without approval", () => {
  it("flags the video's refund-on-request support bot (Vercel AI SDK)", async () => {
    expect(await summarize(SUPPORT_BOT)).toEqual(["AILAYER-07 HIGH L11 issueRefund"]);
  });

  it("flags OpenAI and Anthropic function tools by name", async () => {
    const openai = lines(
      'import OpenAI from "openai";',
      "const res = await client.chat.completions.create({",
      "  model: 'gpt-4o', messages,",
      "  tools: [{ type: 'function', function: { name: 'update_user_role', parameters: {} } }, { type: 'function', function: { name: 'get_weather' } }],",
      "});",
    );
    expect(await summarize(openai)).toEqual(["AILAYER-07 HIGH L4 update_user_role"]);
    const anthropic = lines('import Anthropic from "@anthropic-ai/sdk";', "await client.messages.create({ tools: [{ name: 'apply_discount', input_schema: {} }], messages });");
    expect(await summarize(anthropic)).toEqual(["AILAYER-07 HIGH L2 apply_discount"]);
  });

  it("flags LangChain tools", async () => {
    const code = lines('import { DynamicStructuredTool } from "@langchain/core/tools";', "const t = new DynamicStructuredTool({ name: 'run_sql', func: async ({ q }) => db.query(q) });");
    expect(await summarize(code, "lib/agent.ts")).toEqual(["AILAYER-07 HIGH L2 run_sql"]);
  });

  it.each([
    ["a tool that needs approval", SUPPORT_BOT.replace("issueRefund: tool({", "issueRefund: tool({ needsApproval: true,")],
    ["read-only tools", SUPPORT_BOT.replace(/\s+issueRefund: tool\(.*\n/, "\n")],
    ["a file with no LLM SDK", 'const tools = { issueRefund: () => {} };'],
  ])("does NOT flag %s", async (_label, code) => {
    expect(await summarize(code)).toEqual([]);
  });
});

describe("llmAppDetector — AILAYER-08 request input in the system prompt", () => {
  it("flags request text interpolated into system / instructions / a system message", async () => {
    const vercel = lines('import { generateText } from "ai";', "export async function POST(req) {", "  const { persona, prompt } = await req.json();", "  return generateText({ model, system: `You are ${persona}.`, prompt });", "}");
    expect(await summarize(vercel)).toEqual(["AILAYER-08 MEDIUM L4 system"]);
    const openai = lines(
      'import OpenAI from "openai";',
      "export async function POST(req) {",
      "  const body = await req.json();",
      "  await client.chat.completions.create({ messages: [{ role: 'system', content: 'Rules: ' + body.rules }, { role: 'user', content: body.q }] });",
      "}",
    );
    expect(await summarize(openai)).toEqual(["AILAYER-08 MEDIUM L4 system"]);
  });

  it("does NOT flag user input in user messages or a fixed system prompt", async () => {
    const code = lines('import { generateText } from "ai";', "export async function POST(req) {", "  const { prompt } = await req.json();", '  return generateText({ model, system: "You are helpful.", messages: [{ role: "user", content: prompt }] });', "}");
    expect(await summarize(code)).toEqual([]);
  });
});

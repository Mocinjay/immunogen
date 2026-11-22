import { describe, expect, it } from "vitest";

import { buildAstCache } from "../../core/parse/ast-cache.js";
import { massAssignmentDetector } from "./mass-assignment-detector.js";

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

async function summarize(content: string, filePath = "app/api/signup/route.ts"): Promise<string[]> {
  const { astCache } = buildAstCache(new Map([[filePath, content]]));
  const ctx: DetectorContext = { filePath, content, ast: astCache.get(filePath), stackHints: STACK_HINTS, fileSet: new Map([[filePath, content]]) };
  const findings = await massAssignmentDetector.detect(ctx);
  return findings.map((finding) => `${finding.ruleId} ${finding.severity} L${finding.line} ${finding.matchedText ?? ""}`);
}

describe("massAssignmentDetector — AUTH-10 flags", () => {
  it.each([
    ["a Prisma sign-up that saves the whole body", lines("export async function POST(req) {", "  const body = await req.json();", "  await prisma.user.create({ data: body });", "}"), "AUTH-10 HIGH L3 user"],
    ["a spread of the body", lines("export async function POST(req) {", "  const body = await req.json();", "  await prisma.user.create({ data: { ...body, password: hash } });", "}"), "AUTH-10 HIGH L3 user"],
    ["rest-of-body after removing the password", lines("export async function POST(req) {", "  const { password, ...rest } = await req.json();", "  await prisma.user.create({ data: { ...rest, passwordHash: await hash(password) } });", "}"), "AUTH-10 HIGH L3 user"],
    ["role read from the request (the video's \"role\": \"admin\")", lines("export async function POST(req) {", "  const { email, password, role } = await req.json();", "  await prisma.user.create({ data: { email, password, role } });", "}"), "AUTH-10 HIGH L3 user"],
    ["isAdmin with a default", lines("export async function POST(req) {", "  const body = await req.json();", "  await prisma.user.create({ data: { email: body.email, isAdmin: body.isAdmin ?? false } });", "}"), "AUTH-10 HIGH L3 user"],
  ])("flags %s", async (_label, code, expected) => {
    expect(await summarize(code)).toEqual([expected]);
  });

  it("flags Mongoose and Express shapes", async () => {
    expect(await summarize('app.post("/api/register", async (req, res) => { const user = new User(req.body); await user.save(); });', "server/auth.ts")).toEqual([
      "AUTH-10 HIGH L1 User",
    ]);
    expect(await summarize("export const update = async (req, res) => { await User.findByIdAndUpdate(req.user.id, req.body); };", "server/controllers/users.ts")).toEqual([
      "AUTH-10 HIGH L1 User",
    ]);
  });

  it("flags Supabase sign-up metadata and table updates", async () => {
    const signUp = lines(
      "export async function POST(req) {",
      "  const { email, password, role } = await req.json();",
      "  await supabase.auth.signUp({ email, password, options: { data: { role } } });",
      "}",
    );
    expect(await summarize(signUp)).toEqual(["AUTH-10 HIGH L3 auth"]);
    const update = lines("export async function PATCH(req) {", "  const body = await req.json();", '  await supabase.from("profiles").update(body).eq("id", user.id);', "}");
    expect(await summarize(update, "app/api/profile/route.ts")).toEqual(["AUTH-10 HIGH L3 profiles"]);
  });

  it("flags a Server Action that passes its object argument through", async () => {
    const action = lines('"use server";', "export async function updateSettings(input: SettingsInput) {", "  const session = await auth();", "  await db.account.update({ where: { id: session.user.id }, data: input });", "}");
    expect(await summarize(action, "app/settings/actions.ts")).toEqual(["AUTH-10 HIGH L4 account"]);
  });

  it("rates a wholesale write into a non-user record MEDIUM", async () => {
    const code = lines("export async function POST(req) {", "  const body = await req.json();", "  await prisma.order.create({ data: body });", "}");
    expect(await summarize(code, "app/api/orders/route.ts")).toEqual(["AUTH-10 MEDIUM L3 order"]);
  });
});

describe("massAssignmentDetector — AUTH-10 stays quiet", () => {
  it.each([
    ["explicit field copying", lines("export async function POST(req) {", "  const body = await req.json();", "  await prisma.user.create({ data: { email: body.email, name: body.name } });", "}")],
    ["a schema-parsed body", lines("export async function POST(req) {", "  const data = SignUp.parse(await req.json());", "  await prisma.user.create({ data });", "}")],
    ["a server-assigned role", lines("export async function POST(req) {", "  const { email } = await req.json();", '  await prisma.user.create({ data: { email, role: "user" } });', "}")],
    ["an admin endpoint that sets roles", lines("export async function PATCH(req) {", "  if (session.user.role !== \"admin\") return forbidden();", "  const { role } = await req.json();", "  await prisma.user.update({ where: { id }, data: { role } });", "}")],
    ["a webhook HMAC over the raw body", lines("export async function POST(req) {", "  const body = await req.text();", '  const sig = crypto.createHmac("sha256", secret).update(body).digest("hex");', "}")],
    ["passing the body to an SDK", lines("export async function POST(req) {", "  const body = await req.json();", "  return openai.chat.completions.create(body);", "}")],
    ["Express res.set headers", 'app.get("/x", (req, res) => { res.set(req.query); });'],
    ["Server Action primitive parameters", lines('"use server";', "export async function rename(id: string, name: string) {", "  await prisma.project.update({ where: { id }, data: { name } });", "}")],
  ])("does NOT flag %s", async (_label, code) => {
    expect(await summarize(code)).toEqual([]);
  });

  it("does NOT flag non-server files", async () => {
    expect(await summarize("export function save(body) { return prisma.user.create({ data: body }); }", "lib/users.ts")).toEqual([]);
  });
});

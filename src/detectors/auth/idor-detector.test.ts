import { describe, expect, it } from "vitest";

import { buildAstCache } from "../../core/parse/ast-cache.js";
import { idorDetector } from "./idor-detector.js";

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

function makeContext(content: string, filePath: string): DetectorContext {
  const { astCache } = buildAstCache(new Map([[filePath, content]]));
  return { filePath, content, ast: astCache.get(filePath), stackHints: STACK_HINTS, fileSet: new Map([[filePath, content]]) };
}

async function summarize(content: string, filePath = "app/api/orders/[id]/route.ts"): Promise<string[]> {
  const findings = await idorDetector.detect(makeContext(content, filePath));
  return findings.map((finding) => `${finding.ruleId} ${finding.severity}/${finding.confidence} L${finding.line} ${finding.matchedText ?? ""}`);
}

const lines = (...parts: string[]): string => parts.join("\n");

describe("idorDetector — AUTH-08 flags unscoped by-id access", () => {
  it("flags a Next.js route that reads an order by the URL id after only authenticating", async () => {
    const code = lines(
      'import { auth } from "@/auth";',
      "export async function GET(req: Request, { params }: { params: Promise<{ id: string }> }) {",
      "  const session = await auth();",
      '  if (!session) return new Response("Unauthorized", { status: 401 });',
      "  const { id } = await params;",
      "  const order = await prisma.order.findUnique({ where: { id } });",
      "  return Response.json(order);",
      "}",
    );
    expect(await summarize(code)).toEqual(["AUTH-08 HIGH/LOW L6 order"]);
  });

  it("flags a delete by id as HIGH/MEDIUM", async () => {
    const code = lines(
      "export async function DELETE(req, context) {",
      "  const session = await getServerSession(authOptions);",
      "  await prisma.note.delete({ where: { id: context.params.id } });",
      "}",
    );
    expect(await summarize(code, "app/api/notes/[id]/route.ts")).toEqual(["AUTH-08 HIGH/MEDIUM L3 note"]);
  });

  it("flags the /account?id= server page from the video", async () => {
    const code = lines(
      "export default async function AccountPage({ searchParams }) {",
      "  const session = await auth();",
      "  const { id } = await searchParams;",
      "  const account = await db.account.findFirst({ where: { id: Number(id) } });",
      "  return <Profile account={account} />;",
      "}",
    );
    expect(await summarize(code, "app/account/page.tsx")).toEqual(["AUTH-08 HIGH/LOW L4 account"]);
  });

  it("flags Mongoose findByIdAndUpdate in an Express controller that reads req.user", async () => {
    const code = lines(
      "export const updateProfile = async (req, res) => {",
      "  if (!req.user) return res.sendStatus(401);",
      "  const profile = await Profile.findByIdAndUpdate(req.params.id, { bio: req.body.bio });",
      "  res.json(profile);",
      "};",
    );
    expect(await summarize(code, "server/controllers/profile.ts")).toEqual(["AUTH-08 HIGH/MEDIUM L3 Profile"]);
  });

  it("flags a Drizzle update scoped only by the request id", async () => {
    const code = lines(
      '"use server";',
      "export async function renameDocument(id: string, title: string) {",
      "  const user = await currentUser();",
      "  await db.update(documents).set({ title }).where(eq(documents.id, id));",
      "}",
    );
    // Server Action arguments are request input only via the seeds/sources — `id` here is a plain parameter.
    expect(await summarize(code, "app/actions/documents.ts")).toEqual([]);

    const fromForm = lines(
      '"use server";',
      "export async function renameDocument(formData: FormData) {",
      "  const user = await currentUser();",
      '  const id = formData.get("id") as string;',
      "  await db.update(documents).set({ title: 'x' }).where(eq(documents.id, id));",
      "}",
    );
    expect(await summarize(fromForm, "app/actions/documents.ts")).toEqual(["AUTH-08 HIGH/MEDIUM L5 documents"]);
  });
});

describe("idorDetector — AUTH-08 stays quiet on scoped or public access", () => {
  it.each([
    [
      "a filter that includes the owner",
      lines(
        "export async function GET(req, { params }) {",
        "  const session = await auth();",
        "  const order = await prisma.order.findFirst({ where: { id: params.id, userId: session.user.id } });",
        "}",
      ),
    ],
    [
      "an ownership comparison after the fetch",
      lines(
        "export async function GET(req, { params }) {",
        "  const session = await auth();",
        "  const order = await prisma.order.findUnique({ where: { id: params.id } });",
        "  if (order.userId !== session.user.id) return new Response(null, { status: 404 });",
        "}",
      ),
    ],
    [
      "an admin handler with a role check",
      lines(
        "export async function DELETE(req, { params }) {",
        "  const session = await auth();",
        '  if (session.user.role !== "admin") return new Response(null, { status: 403 });',
        "  await prisma.order.delete({ where: { id: params.id } });",
        "}",
      ),
    ],
    [
      "an unauthenticated handler (AUTH-01's finding)",
      lines("export async function GET(req, { params }) {", "  return Response.json(await prisma.order.findUnique({ where: { id: params.id } }));", "}"),
    ],
    [
      "a read of a public catalog model",
      lines(
        "export async function GET(req, { params }) {",
        "  const session = await auth();",
        "  return Response.json(await prisma.product.findUnique({ where: { id: params.id } }));",
        "}",
      ),
    ],
    [
      "a lookup by the session's own id",
      lines("export async function GET() {", "  const session = await auth();", "  return Response.json(await prisma.user.findUnique({ where: { id: session.user.id } }));", "}"),
    ],
    [
      "a child lookup scoped by a server-resolved parent id",
      lines(
        "export async function DELETE(req, { params }) {",
        "  const session = await auth();",
        "  const cart = await getCartFor(session.user.id);",
        "  await prisma.cartItem.delete({ where: { cartId: cart.id, id: params.itemId } });",
        "}",
      ),
    ],
    [
      "a webhook handler (server-to-server)",
      lines(
        "export async function POST(req) {",
        "  const event = stripe.webhooks.constructEvent(body, sig, secret);",
        "  const session = await auth();",
        "  await prisma.order.update({ where: { id: req.query.id }, data: { paid: true } });",
        "}",
      ),
    ],
  ])("does NOT flag %s", async (_label, code) => {
    expect(await summarize(code)).toEqual([]);
  });

  it("does NOT flag client components or test files", async () => {
    const code = lines('"use client";', "const session = await auth();", "prisma.order.delete({ where: { id: params.id } });");
    expect(await summarize(code, "app/orders/page.tsx")).toEqual([]);
    const server = lines("export async function DELETE(req, { params }) {", "  const s = await auth();", "  await prisma.order.delete({ where: { id: params.id } });", "}");
    expect(await summarize(server, "app/api/orders/[id]/route.test.ts")).toEqual([]);
  });
});

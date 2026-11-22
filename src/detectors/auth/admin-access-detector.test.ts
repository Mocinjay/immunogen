import { describe, expect, it } from "vitest";

import { buildAstCache } from "../../core/parse/ast-cache.js";
import { adminAccessDetector } from "./admin-access-detector.js";

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

/** Runs the detector on `target` with every file in `files` in the shared fileSet. */
async function summarize(files: Record<string, string>, target: string): Promise<string[]> {
  const fileSet = new Map(Object.entries(files));
  const content = fileSet.get(target) ?? "";
  const { astCache } = buildAstCache(new Map([[target, content]]));
  const ctx: DetectorContext = { filePath: target, content, ast: astCache.get(target), stackHints: STACK_HINTS, fileSet };
  const findings = await adminAccessDetector.detect(ctx);
  return findings.map((finding) => `${finding.ruleId} ${finding.severity}/${finding.confidence} ${finding.matchedText ?? ""}`);
}

const OPEN_PAGE = lines("export default async function AdminPage() {", "  const users = await prisma.user.findMany();", "  return <UserTable users={users} />;", "}");
const ROLE_LAYOUT = lines(
  "export default async function AdminLayout({ children }) {",
  "  const session = await auth();",
  '  if (session?.user.role !== "admin") redirect("/");',
  "  return children;",
  "}",
);

describe("adminAccessDetector — AUTH-09 admin pages", () => {
  it("flags an admin page with no role check anywhere (the 'just type /admin' case)", async () => {
    expect(await summarize({ "app/admin/page.tsx": OPEN_PAGE }, "app/admin/page.tsx")).toEqual(["AUTH-09 HIGH/MEDIUM app/admin"]);
  });

  it("reports an admin area once, on its first page", async () => {
    const files = { "app/admin/page.tsx": OPEN_PAGE, "app/admin/users/page.tsx": OPEN_PAGE, "app/admin/payments/page.tsx": OPEN_PAGE };
    expect(await summarize(files, "app/admin/page.tsx")).toEqual(["AUTH-09 HIGH/MEDIUM app/admin"]);
    expect(await summarize(files, "app/admin/users/page.tsx")).toEqual([]);
  });

  it("flags a client-only role gate as MEDIUM/LOW", async () => {
    const page = lines(
      '"use client";',
      "export default function AdminPage() {",
      "  const { data } = useSession();",
      '  if (data?.user.role !== "admin") return null;',
      "  return <Dashboard />;",
      "}",
    );
    expect(await summarize({ "app/(admin)/dashboard/page.tsx": page }, "app/(admin)/dashboard/page.tsx")).toEqual([
      "AUTH-09 MEDIUM/LOW app/(admin)",
    ]);
  });

  it.each([
    ["a server layout that checks the role", { "app/admin/layout.tsx": ROLE_LAYOUT }],
    ["middleware that checks the admin role", { "middleware.ts": 'if (req.nextUrl.pathname.startsWith("/admin") && token?.role !== "admin") return deny();' }],
  ])("does NOT flag an admin page protected by %s", async (_label, extra) => {
    expect(await summarize({ "app/admin/page.tsx": OPEN_PAGE, ...extra }, "app/admin/page.tsx")).toEqual([]);
  });

  it("does NOT flag a server page that checks the role itself, or non-admin pages", async () => {
    const page = lines("export default async function Page() {", "  await requireAdmin();", "  return <div />;", "}");
    expect(await summarize({ "app/admin/page.tsx": page }, "app/admin/page.tsx")).toEqual([]);
    expect(await summarize({ "app/dashboard/page.tsx": OPEN_PAGE }, "app/dashboard/page.tsx")).toEqual([]);
  });
});

describe("adminAccessDetector — AUTH-09 admin endpoints", () => {
  it("flags an admin route handler that authenticates but checks no role", async () => {
    const route = lines(
      "export async function DELETE() {",
      "  const session = await auth();",
      '  if (!session) return new Response("Unauthorized", { status: 401 });',
      "  await prisma.user.deleteMany();",
      "}",
    );
    expect(await summarize({ "app/api/admin/users/route.ts": route }, "app/api/admin/users/route.ts")).toEqual(["AUTH-09 HIGH/MEDIUM route"]);
  });

  it("does NOT repeat AUTH-01 for an admin route with no authentication at all", async () => {
    const route = lines("export async function DELETE() {", "  await prisma.user.deleteMany();", "}");
    expect(await summarize({ "app/api/admin/users/route.ts": route }, "app/api/admin/users/route.ts")).toEqual([]);
  });

  it("does NOT flag an admin route handler that checks the role", async () => {
    const route = lines("export async function DELETE() {", "  const session = await auth();", '  if (session.user.role !== "admin") return forbidden();', "}");
    expect(await summarize({ "app/api/admin/users/route.ts": route }, "app/api/admin/users/route.ts")).toEqual([]);
  });

  it("flags an Express /admin route behind login-only middleware", async () => {
    const server = lines('router.delete("/admin/users/:id", requireAuth, async (req, res) => {', "  await User.findByIdAndDelete(req.params.id);", "});");
    expect(await summarize({ "server/routes.ts": server }, "server/routes.ts")).toEqual(["AUTH-09 HIGH/MEDIUM /admin/users/:id"]);
  });

  it.each([
    ["role middleware on the route", 'router.delete("/admin/users/:id", requireAuth, requireAdmin, handler);', {}],
    ["a role-guarded /admin mount elsewhere", 'router.delete("/admin/users/:id", requireAuth, handler);', { "server/app.ts": 'app.use("/admin", requireAuth, adminOnly, adminRouter);' }],
    ["an HTTP client call to an /admin URL", 'const res = await axios.get("/admin/users", { headers: { Authorization: token } });', {}],
  ])("does NOT flag %s", async (_label, server, extra) => {
    expect(await summarize({ "server/routes.ts": server, ...extra }, "server/routes.ts")).toEqual([]);
  });

  it("treats every route in an admin router file as an admin route", async () => {
    const router = lines('router.get("/stats", authenticate, async (req, res) => {', "  res.json(await getStats());", "});");
    expect(await summarize({ "server/routes/admin.ts": router }, "server/routes/admin.ts")).toEqual(["AUTH-09 HIGH/MEDIUM /stats"]);
  });
});

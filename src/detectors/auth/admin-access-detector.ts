/**
 * adminAccessDetector — AUTH-09: an admin area reachable without an admin
 * role check. "Just type /admin": AI-built apps routinely ship an admin
 * dashboard that checks the visitor is signed in (or nothing at all) but
 * never that they are an admin, or that hides the admin UI in the browser
 * while every admin action stays callable.
 *
 * What counts as admin: a path segment `admin`, `(admin)`, `admin-panel`,
 * `backoffice`, `superadmin`, `staff`, ... (App Router, Pages Router, API
 * routes, Server Action modules, route files), or an Express / Fastify /
 * Hono / Koa route registered on an `/admin...` path.
 *
 * Role evidence (any one suppresses): a role comparison or role/permission
 * helper (auth-evidence.ts ROLE_CHECK_RE) in the file itself, in a server
 * `layout` above an admin page, in a `middleware.ts` / `proxy.ts` that
 * mentions admin, in role-named middleware on the route
 * (`router.get("/admin/x", requireAdmin, h)`), or in role-named middleware
 * on an `app.use("/admin", requireAdmin, adminRouter)` mount anywhere in the
 * repo.
 *
 * Findings:
 *   - an admin API endpoint / Server Action / route that authenticates the
 *     caller but checks no role — HIGH/MEDIUM ("any signed-in user can call
 *     it"). An admin endpoint with no authentication at all is AUTH-01's
 *     CRITICAL finding and is not repeated here;
 *   - an admin page with no server-side role check — HIGH/MEDIUM, reported
 *     once per admin area (on its first unprotected page) rather than once
 *     per page;
 *   - an admin page gated only in the browser (a role check inside a
 *     `"use client"` page or layout) — MEDIUM/LOW: it hides the screen, but
 *     the data and actions behind it must enforce the role on the server.
 *
 * AST + text (ENG-05): reads `ctx.ast` and `ctx.content`; never evaluates
 * scanned source. No-throw contract: returns `[]` on any failure.
 */
import { isBabelFile, traverseAst } from "../ast/ast-utils.js";
import { isTestOrFixturePath } from "../shared/test-paths.js";
import { isClientModule } from "../shared/server-entry.js";
import { isAuthCall, ROLE_CHECK_RE, USER_IDENTITY_READ_RE } from "./auth-evidence.js";

import type { Detector, DetectorContext, Finding } from "../../core/types.js";
import type { CallExpression, File, Node } from "@babel/types";

/** A path segment naming an admin area. */
const ADMIN_SEGMENT_RE = /^\(?(?:admin[\w-]*|superadmin|super-admin|backoffice|back-office|staff)\)?$/i;

/** A file stem naming admin code (`admin.ts`, `adminActions.ts`, `admin-routes.js`). */
const ADMIN_STEM_RE = /^admin[\w.-]*$/i;

/** Route-path text naming an admin route (`/admin`, `/api/admin/users`). */
const ADMIN_ROUTE_PATH_RE = /(?:^|\/)(?:admin|administrator|superadmin|backoffice)(?:[/-]|$)/i;

/** Receivers that are server or router objects (so `axios.get("/users", opts)` is never mistaken for a route). */
const SERVER_RECEIVER_RE = /^(?:app|server|fastify|hono|router|routes|r|admin)$|(?:Router|Routes|router|routes|App|app)$/;

/** Route-registration methods (Express / Fastify / Hono / Koa). */
const ROUTE_METHODS = new Set(["get", "post", "put", "patch", "delete", "all"]);

/** Middleware text that enforces a role rather than just a login (`requireAdmin`, `adminOnly`, `checkRole('admin')`). */
const ROLE_MIDDLEWARE_TEXT_RE = /admin|role|permission|staff|superuser|moderator/i;

/** Middleware / helper references that authenticate without calling (`router.get("/x", requireAuth, h)`). */
const AUTH_REFERENCE_RE =
  /\b(?:require|ensure|check|verify|validate|with|protect)\w*?(?:Auth|Authenticated|Session|User|LoggedIn|SignedIn|Token)\b|\bauthenticate(?:d|Token|User|JWT)?\b|\bisAuthenticated\b|\bauthMiddleware\b|\bpassport\.authenticate\b|\bclerkMiddleware\b|\bauth\.protect\b/;

/** Next.js middleware basenames (`proxy.ts` is its Next.js 16 name). */
const MIDDLEWARE_BASENAMES = new Set(["middleware.ts", "middleware.js", "proxy.ts", "proxy.js"]);

/** `app.use("/admin...", mw1, mw2, router)` — captures the argument list after the mount path. */
const ADMIN_MOUNT_RE = /\.use\(\s*["'`][^"'`]*admin[^"'`]*["'`]\s*,([^)]*)\)/gi;

/** Basename stem without extension. */
function stemOf(filePath: string): string {
  const basename = filePath.split("/").at(-1) ?? "";
  return basename.replace(/\.[^.]+$/, "");
}

/** The admin area root (`app/admin`, `app/(admin)`, `pages/api/admin`) a path belongs to, if any. */
function adminRoot(filePath: string): string | undefined {
  const segments = filePath.split("/");
  const index = segments.slice(0, -1).findIndex((segment) => ADMIN_SEGMENT_RE.test(segment));
  return index === -1 ? undefined : segments.slice(0, index + 1).join("/");
}

/** True for a Next.js App Router page or a Pages Router page (not an API route). */
function pageKind(filePath: string): "app-page" | "pages-page" | undefined {
  const segments = filePath.split("/");
  const basename = segments.at(-1) ?? "";
  if (/^page\.(?:tsx|jsx|ts|js)$/.test(basename) && segments.includes("app")) {
    return "app-page";
  }
  if (/(?:^|\/)pages\/(?!api\/).+\.(?:tsx|jsx|ts|js)$/.test(filePath) && !basename.startsWith("_")) {
    return "pages-page";
  }
  return undefined;
}

/** True for a server-side admin endpoint file: Next route handler, Pages API route, or Server Action module. */
function isEndpointFile(filePath: string, content: string): boolean {
  const segments = filePath.split("/");
  const basename = segments.at(-1) ?? "";
  return (
    (/^route\.(?:ts|tsx|js|jsx|mjs)$/.test(basename) && segments.includes("app")) ||
    /(?:^|\/)pages\/api\/.+\.(?:ts|tsx|js|jsx|mjs)$/.test(filePath) ||
    /^\s*["']use server["']/m.test(content)
  );
}

/** Repo-wide role enforcement covering admin routes: Next.js middleware, or a role-guarded `app.use("/admin", ...)` mount. */
function repoGuardsAdmin(fileSet: ReadonlyMap<string, string>): boolean {
  for (const [path, content] of fileSet) {
    if (!/admin/i.test(content)) {
      continue;
    }
    const basename = path.split("/").at(-1) ?? "";
    if (MIDDLEWARE_BASENAMES.has(basename) && ROLE_CHECK_RE.test(content)) {
      return true;
    }
    for (const mount of content.matchAll(ADMIN_MOUNT_RE)) {
      // Every argument but the last (the mounted router) is middleware.
      const middleware = (mount[1] ?? "").split(",").slice(0, -1).join(",");
      if (ROLE_MIDDLEWARE_TEXT_RE.test(middleware) || ROLE_CHECK_RE.test(middleware)) {
        return true;
      }
    }
  }
  return false;
}

/** True when a Next.js middleware enforces authentication (signed-in), whatever the role. */
function repoMiddlewareAuthenticates(fileSet: ReadonlyMap<string, string>): boolean {
  for (const [path, content] of fileSet) {
    if (MIDDLEWARE_BASENAMES.has(path.split("/").at(-1) ?? "") && (AUTH_REFERENCE_RE.test(content) || /\bauth\s*\(|getToken\(|getSession\(|withAuth|next-auth\/middleware/.test(content))) {
      return true;
    }
  }
  return false;
}

/** Ancestor layouts of an App Router page, as [path, content] pairs. */
function ancestorLayouts(filePath: string, fileSet: ReadonlyMap<string, string>): Array<[string, string]> {
  const directory = filePath.slice(0, filePath.lastIndexOf("/") + 1);
  const layouts: Array<[string, string]> = [];
  for (const [path, content] of fileSet) {
    if (/\/layout\.(?:tsx|jsx|ts|js)$/.test(path) && directory.startsWith(path.slice(0, path.lastIndexOf("/") + 1))) {
      layouts.push([path, content]);
    }
  }
  return layouts;
}

/** How an admin page is gated: on the server, only in the browser, or not at all. */
function pageGate(filePath: string, content: string, fileSet: ReadonlyMap<string, string>): "server" | "client" | "none" {
  const kind = pageKind(filePath);
  let clientGate = false;
  const sources: Array<[string, string]> = [[filePath, content], ...(kind === "app-page" ? ancestorLayouts(filePath, fileSet) : [])];
  for (const [path, source] of sources) {
    if (!ROLE_CHECK_RE.test(source)) {
      continue;
    }
    const serverSide =
      path.endsWith(filePath) && kind === "pages-page"
        ? /\bgetServerSideProps\b/.test(source)
        : !isClientModule(source);
    if (serverSide) {
      return "server";
    }
    clientGate = true;
  }
  return clientGate ? "client" : "none";
}

/** True when the parsed file authenticates the caller (an auth helper call, `req.user`, or auth middleware). */
function authenticates(ast: File, content: string): boolean {
  if (USER_IDENTITY_READ_RE.test(content) || AUTH_REFERENCE_RE.test(content)) {
    return true;
  }
  let found = false;
  traverseAst(ast, {
    CallExpression(path) {
      found ||= isAuthCall(path.node);
    },
  });
  return found;
}

/** Source text of a node. */
function sourceOf(content: string, node: Node): string {
  return content.slice(node.start ?? 0, node.end ?? 0);
}

/**
 * For an `app.get("/admin/x", ...mw, handler)` registration: its path and
 * the middleware text, when the path is an admin path — or any path, for a
 * router file that is itself admin code (`routes/admin.ts`, mounted at /admin).
 */
function adminRouteRegistration(call: CallExpression, content: string, adminRouter: boolean): { path: string; middleware: string } | undefined {
  const callee = call.callee;
  if (
    callee.type !== "MemberExpression" ||
    callee.property.type !== "Identifier" ||
    !ROUTE_METHODS.has(callee.property.name) ||
    callee.object.type !== "Identifier" ||
    !SERVER_RECEIVER_RE.test(callee.object.name)
  ) {
    return undefined;
  }
  const first = call.arguments.at(0);
  const path = first?.type === "StringLiteral" ? first.value : first?.type === "TemplateLiteral" && first.expressions.length === 0 ? first.quasis.at(0)?.value.cooked : undefined;
  if (path === undefined || !path.startsWith("/") || (!adminRouter && !ADMIN_ROUTE_PATH_RE.test(path)) || call.arguments.length < 2) {
    return undefined;
  }
  const middleware = call.arguments
    .slice(1, -1)
    .map((argument) => sourceOf(content, argument))
    .join(",");
  return { path, middleware };
}

const REMEDIATION =
  "Check the admin role on the server for every admin page and action — e.g. in a server layout or middleware for /admin (redirect or 403 unless session.user.role === \"admin\"), and again inside each admin API route / Server Action. Hiding links or checking the role in the browser is not access control.";

export const adminAccessDetector: Detector = {
  config: {
    name: "admin-access",
    category: "auth",
    globs: ["**/*.{ts,tsx,js,jsx,mjs,cjs,mts,cts}"],
    usesAst: true,
  },

  detect(ctx: DetectorContext): Promise<Finding[]> {
    try {
      if (isTestOrFixturePath(ctx.filePath) || !isBabelFile(ctx.ast)) {
        return Promise.resolve([]);
      }
      const ast = ctx.ast;
      const root = adminRoot(ctx.filePath);
      const inAdminFile = root !== undefined || ADMIN_STEM_RE.test(stemOf(ctx.filePath));
      const fileChecksRole = ROLE_CHECK_RE.test(ctx.content);

      // 1. Admin pages — one finding per admin area.
      const page = pageKind(ctx.filePath);
      if (page !== undefined && root !== undefined) {
        if (fileChecksRole && !isClientModule(ctx.content) && page === "app-page") {
          return Promise.resolve([]);
        }
        if (repoGuardsAdmin(ctx.fileSet)) {
          return Promise.resolve([]);
        }
        const gate = pageGate(ctx.filePath, ctx.content, ctx.fileSet);
        if (gate === "server") {
          return Promise.resolve([]);
        }
        // Report on the area's first page with the same gate, so a ten-page admin area is one finding.
        const firstPeer = [...ctx.fileSet.keys()]
          .filter((path) => adminRoot(path) === root && pageKind(path) !== undefined && !isTestOrFixturePath(path))
          .filter((path) => pageGate(path, ctx.fileSet.get(path) ?? "", ctx.fileSet) === gate)
          .sort()
          .at(0);
        if (firstPeer !== undefined && firstPeer !== ctx.filePath) {
          return Promise.resolve([]);
        }
        return Promise.resolve([
          {
            ruleId: "AUTH-09",
            category: "auth",
            detectorName: "admin-access",
            file: ctx.filePath,
            line: 1,
            severity: gate === "client" ? "MEDIUM" : "HIGH",
            confidence: gate === "client" ? "LOW" : "MEDIUM",
            message:
              gate === "client"
                ? `Admin area ${root} is gated only in the browser — the role check runs in a client component, so the admin data and actions behind it must still enforce the role on the server.`
                : `Admin area ${root} has no server-side role check — anyone who types /admin (or any signed-in user) gets the admin screen and every action on it.`,
            remediation: REMEDIATION,
            matchedText: root,
          },
        ]);
      }

      // 2. Admin endpoints (route handlers, Pages API, Server Actions) in an admin path or admin-named module.
      if (inAdminFile && isEndpointFile(ctx.filePath, ctx.content)) {
        if (fileChecksRole || repoGuardsAdmin(ctx.fileSet)) {
          return Promise.resolve([]);
        }
        if (!authenticates(ast, ctx.content) && !repoMiddlewareAuthenticates(ctx.fileSet)) {
          // Unauthenticated: AUTH-01 already reports it as CRITICAL/HIGH.
          return Promise.resolve([]);
        }
        const line = ctx.content.split("\n").findIndex((text) => /export\s+(?:default|async|const|function)/.test(text)) + 1;
        return Promise.resolve([
          {
            ruleId: "AUTH-09",
            category: "auth",
            detectorName: "admin-access",
            file: ctx.filePath,
            line: Math.max(line, 1),
            severity: "HIGH",
            confidence: "MEDIUM",
            message: "Admin endpoint checks that the caller is signed in but not that they are an admin — any user can call it.",
            remediation: REMEDIATION,
            matchedText: stemOf(ctx.filePath),
          },
        ]);
      }

      // 3. Server-framework routes registered on /admin paths (or in an admin-named router file).
      if (fileChecksRole || repoGuardsAdmin(ctx.fileSet)) {
        return Promise.resolve([]);
      }
      const fileAuthenticates = authenticates(ast, ctx.content);
      const findings: Finding[] = [];
      traverseAst(ast, {
        CallExpression(path) {
          const route = adminRouteRegistration(path.node, ctx.content, inAdminFile);
          if (route === undefined || ROLE_MIDDLEWARE_TEXT_RE.test(route.middleware)) {
            return;
          }
          if (!fileAuthenticates && !AUTH_REFERENCE_RE.test(route.middleware)) {
            return;
          }
          findings.push({
            ruleId: "AUTH-09",
            category: "auth",
            detectorName: "admin-access",
            file: ctx.filePath,
            line: path.node.loc?.start.line ?? 1,
            severity: "HIGH",
            confidence: "MEDIUM",
            message: `Admin route ${route.path} checks that the caller is signed in but not that they are an admin — any user can call it.`,
            remediation: REMEDIATION,
            matchedText: route.path,
          });
        },
      });
      return Promise.resolve(findings);
    } catch {
      return Promise.resolve([]);
    }
  },
};

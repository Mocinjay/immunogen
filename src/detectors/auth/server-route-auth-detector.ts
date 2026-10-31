/**
 * serverRouteAuthDetector — CAT-3 AUTH-01 for Node server frameworks:
 * Express, Fastify, Hono, and Koa routes registered with no authentication
 * or authorization check. The Next.js entry points (route handlers, Pages
 * API routes, Server Actions) are covered by route-auth-detector.ts; this
 * detector covers the `app.post("/api/x", handler)` style every other
 * AI-scaffolded backend uses.
 *
 * A route registration is a call `<receiver>.<method>("/path", ...args)`
 * where `<method>` is get/post/put/patch/delete/all, the path is a string
 * literal starting with `/`, and the last argument is the handler — an
 * inline function, or a named function when the receiver is a server or
 * router object (`app`, `router`, `server`, `fastify`, `userRoutes`, ...).
 * Fastify's `fastify.route({ method, url, handler })` form is recognized
 * too. A client-side `axios.get("/api/x")` never matches: it has no handler.
 *
 * A route is protected when any of these hold:
 *   - a middleware/hook argument between the path and the handler looks
 *     like auth (`requireAuth`, `passport.authenticate("jwt")`,
 *     `{ preHandler: [fastify.authenticate] }`, `bearerAuth(...)`, ...);
 *   - the handler calls a recognized auth helper (auth-evidence.ts), reads
 *     the authenticated identity (`req.user`, `req.session`, `req.auth`,
 *     `ctx.state.user`, `c.get("jwtPayload")`), or verifies a webhook
 *     signature / shared secret / API-key header;
 *   - an auth-looking `.use(...)` / `.addHook(...)` earlier in the same file
 *     covers it (globally, or by a matching path prefix);
 *   - its path is public by nature (health, login, signup, OAuth callback,
 *     ...) or carries a `public` segment, or a `// public` comment marks it.
 * When some OTHER file registers auth-looking middleware (a router mounted
 * behind `app.use("/admin", requireAuth, adminRouter)`), findings drop to
 * MEDIUM/LOW with a "verify the mount covers this route" message instead of
 * disappearing — a router mounted outside that middleware is exactly the
 * bug worth a look.
 *
 * Severity: state-changing methods are CRITICAL, GET is HIGH (many GETs
 * are deliberately public). Confidence MEDIUM, as for the Next.js rule.
 *
 * AST-only (ENG-05): reads `ctx.ast` and slices `ctx.content` by node
 * offsets; never evaluates scanned source.
 *
 * No-throw contract (src/core/types.ts Detector.detect): the whole body runs
 * inside a try/catch returning `[]` on any failure.
 */
import { isBabelFile, traverseAst } from "../ast/ast-utils.js";
import { isAuthCall, NON_SESSION_AUTH_RE, PUBLIC_BY_NATURE_SEGMENTS } from "./auth-evidence.js";

import type { Detector, DetectorContext, Finding, Severity } from "../../core/types.js";
import type { CallExpression, Node, ObjectExpression } from "@babel/types";

/** Stack hints for the frameworks this detector covers, with their display names. */
const SERVER_FRAMEWORKS: ReadonlyArray<[string, string]> = [
  ["express", "Express"],
  ["fastify", "Fastify"],
  ["hono", "Hono"],
  ["koa", "Koa"],
];

/** Route-registration method names. */
const ROUTE_METHODS = new Set(["get", "post", "put", "patch", "delete", "all"]);

/** Receivers that are server or router objects, so a named (non-inline) handler still counts as a route. */
const SERVER_RECEIVER_RE = /^(?:app|server|api|fastify|hono|router|routes|r)$|(?:Router|Routes|router|routes|App|app)$/;

/** Text of a middleware, hook, or `.use()` argument that looks like an auth check. */
const AUTH_LIKE_TEXT_RE = /auth|protect|verify|session|jwt|login|guard|permission|role|admin|token|api_?key|passport|clerk|signed_?in/i;

/** Handler text that reads the authenticated identity set by an auth middleware. */
const IDENTITY_READ_RE =
  /\b(?:req|request)\.(?:user|session|auth|isAuthenticated)\b|\bctx\.state\.(?:user|auth)\b|\bc\.get\(\s*['"`](?:user|session|auth|jwtPayload)['"`]\s*\)|\bc\.var\.(?:user|session|auth)\b/;

/** `.use()` / `.addHook()` registering middleware for every following route (or a path prefix). */
const MIDDLEWARE_METHODS = new Set(["use", "addHook"]);

/** Cross-file signal: some file registers auth-looking middleware via `.use(...)`. */
const OTHER_FILE_AUTH_USE_RE = /\.use\([^)]{0,240}?(?:auth|protect|jwt|passport|session|clerk|guard)/i;

/** Path segments that suppress every finding in this file (FP allowlist — PITFALLS.md Pitfall 1). */
const FP_ALLOWLIST_SEGMENTS = new Set(["__tests__", "fixtures", "mocks", "examples"]);

/** Comment fragment a developer adds to opt a route out of AUTH-01. */
const PUBLIC_COMMENT_MARKER = "// public";

/** True when `filePath` falls inside a test/fixture/mock/example directory, or is a test/spec/story file. */
function isAllowlistedPath(filePath: string): boolean {
  const segments = filePath.split("/");
  if (segments.some((segment) => FP_ALLOWLIST_SEGMENTS.has(segment))) {
    return true;
  }
  const basename = segments.at(-1) ?? "";
  return basename.includes(".test.") || basename.includes(".spec.") || basename.includes(".stories.");
}

/** Source text of `node`, sliced from the file by its byte offsets. */
function sourceOf(content: string, node: Node): string {
  return node.start === null || node.start === undefined || node.end === null || node.end === undefined
    ? ""
    : content.slice(node.start, node.end);
}

/** The static string value of a string literal or expression-free template literal. */
function staticString(node: Node | undefined): string | undefined {
  if (node?.type === "StringLiteral") {
    return node.value;
  }
  if (node?.type === "TemplateLiteral" && node.expressions.length === 0) {
    return node.quasis.at(0)?.value.cooked ?? undefined;
  }
  return undefined;
}

/** True for an inline function node. */
function isFunctionNode(node: Node | undefined): boolean {
  return node?.type === "ArrowFunctionExpression" || node?.type === "FunctionExpression";
}

/** True when a route path is public by nature, carries a `public` segment, or is the bare root. */
function isPublicPath(path: string): boolean {
  if (path === "/" || path === "*") {
    return true;
  }
  return path
    .split("/")
    .some((segment) => segment.toLowerCase() === "public" || PUBLIC_BY_NATURE_SEGMENTS.has(segment.toLowerCase()));
}

/** Reads an object-literal property by key name. */
function objectProperty(object: ObjectExpression, key: string): Node | undefined {
  for (const property of object.properties) {
    if (property.type !== "ObjectProperty") {
      continue;
    }
    const name = property.key.type === "Identifier" ? property.key.name : staticString(property.key);
    if (name === key) {
      return property.value;
    }
  }
  return undefined;
}

/** One route registration found in the file. */
interface RouteSite {
  method: string;
  path: string;
  line: number;
  /** Byte offset of the registration call — middleware registered before it covers it. */
  start: number;
  /** Source text of every middleware/hook/options argument plus the handler. */
  guardText: string;
  handler: Node;
}

/** An auth-looking `.use()` / `.addHook()` registration: covers routes after `start` under `prefix`. */
interface AuthMiddlewareSite {
  start: number;
  prefix: string;
}

/** Parses `app.<method>("/path", ...middleware, handler)`; undefined when the call is not a route registration. */
function routeFromMethodCall(call: CallExpression, content: string): RouteSite | undefined {
  const callee = call.callee;
  if (callee.type !== "MemberExpression" || callee.property.type !== "Identifier") {
    return undefined;
  }
  const method = callee.property.name;
  const path = staticString(call.arguments.at(0));
  const handler = call.arguments.at(-1);
  if (!ROUTE_METHODS.has(method) || path?.startsWith("/") !== true || call.arguments.length < 2 || handler === undefined) {
    return undefined;
  }
  const receiver = callee.object.type === "Identifier" ? callee.object.name : "";
  const handlerIsNamed = handler.type === "Identifier" || handler.type === "MemberExpression";
  if (!isFunctionNode(handler) && !(handlerIsNamed && SERVER_RECEIVER_RE.test(receiver))) {
    return undefined;
  }
  const middlewareText = call.arguments
    .slice(1, -1)
    .map((argument) => sourceOf(content, argument))
    .join(" ");
  return {
    method: method.toUpperCase(),
    path,
    line: call.loc?.start.line ?? 1,
    start: call.start ?? 0,
    guardText: middlewareText,
    handler,
  };
}

/** Parses Fastify's `fastify.route({ method, url, handler, preHandler })`. */
function routeFromFastifyRouteCall(call: CallExpression, content: string): RouteSite | undefined {
  const callee = call.callee;
  const options = call.arguments.at(0);
  if (
    callee.type !== "MemberExpression" ||
    callee.property.type !== "Identifier" ||
    callee.property.name !== "route" ||
    options?.type !== "ObjectExpression"
  ) {
    return undefined;
  }
  const path = staticString(objectProperty(options, "url"));
  const handler = objectProperty(options, "handler");
  if (path?.startsWith("/") !== true || handler === undefined) {
    return undefined;
  }
  const methodNode = objectProperty(options, "method");
  const method = (staticString(methodNode) ?? (methodNode === undefined ? "ALL" : sourceOf(content, methodNode))).toUpperCase();
  const guardText = ["preHandler", "onRequest", "preValidation"]
    .map((key) => objectProperty(options, key))
    .filter((node): node is Node => node !== undefined)
    .map((node) => sourceOf(content, node))
    .join(" ");
  return { method, path, line: call.loc?.start.line ?? 1, start: call.start ?? 0, guardText, handler };
}

/** Parses an auth-looking `.use(...)` / `.addHook(...)`; undefined for any other call. */
function authMiddlewareFromCall(call: CallExpression, content: string): AuthMiddlewareSite | undefined {
  const callee = call.callee;
  if (callee.type !== "MemberExpression" || callee.property.type !== "Identifier" || !MIDDLEWARE_METHODS.has(callee.property.name)) {
    return undefined;
  }
  const firstPath = staticString(call.arguments.at(0));
  const scoped = firstPath?.startsWith("/") === true;
  const middlewareText = call.arguments
    .slice(scoped ? 1 : 0)
    .map((argument) => sourceOf(content, argument))
    .join(" ");
  if (!AUTH_LIKE_TEXT_RE.test(middlewareText)) {
    return undefined;
  }
  const prefix = scoped ? (firstPath ?? "").replace(/\/?\*$/, "") : "";
  return { start: call.start ?? 0, prefix };
}

/** True when an auth middleware registered before `route` covers its path. */
function coveredByMiddleware(route: RouteSite, middleware: AuthMiddlewareSite[]): boolean {
  return middleware.some(
    (site) =>
      site.start < route.start &&
      (site.prefix === "" || route.path === site.prefix || route.path.startsWith(`${site.prefix}/`)),
  );
}

/** True when some other JS/TS file registers auth-looking middleware with `.use(...)`. */
function otherFileRegistersAuth(fileSet: ReadonlyMap<string, string>, filePath: string): boolean {
  for (const [path, content] of fileSet) {
    if (path !== filePath && /\.(?:[cm]?[jt]sx?)$/.test(path) && OTHER_FILE_AUTH_USE_RE.test(content)) {
      return true;
    }
  }
  return false;
}

/** True when a `// public` comment sits on the route's line or the line above. */
function hasPublicCommentNear(contentLines: string[], line: number): boolean {
  const sameLine = contentLines.at(line - 1) ?? "";
  const aboveLine = line >= 2 ? (contentLines.at(line - 2) ?? "") : "";
  return sameLine.includes(PUBLIC_COMMENT_MARKER) || aboveLine.includes(PUBLIC_COMMENT_MARKER);
}

export const serverRouteAuthDetector: Detector = {
  config: {
    name: "server-route-auth",
    category: "auth",
    requiresStack: ["express", "fastify", "hono", "koa"],
    globs: ["**/*.{ts,js,mjs,cjs}"],
  },

  // Not declared `async`: synchronous AST work wrapped in Promise.resolve().
  detect(ctx: DetectorContext): Promise<Finding[]> {
    try {
      const present = SERVER_FRAMEWORKS.filter(([hint]) => ctx.stackHints.frameworks.has(hint));
      if (present.length === 0 || isAllowlistedPath(ctx.filePath) || !isBabelFile(ctx.ast)) {
        return Promise.resolve([]);
      }
      const framework = present.length === 1 ? (present[0]?.[1] ?? "Server") : "Server";

      const routes: RouteSite[] = [];
      const middleware: AuthMiddlewareSite[] = [];
      const authCallOffsets: number[] = [];

      traverseAst(ctx.ast, {
        CallExpression(path) {
          const call = path.node;
          if (isAuthCall(call)) {
            authCallOffsets.push(call.start ?? -1);
          }
          const route = routeFromMethodCall(call, ctx.content) ?? routeFromFastifyRouteCall(call, ctx.content);
          if (route !== undefined) {
            routes.push(route);
            return;
          }
          const site = authMiddlewareFromCall(call, ctx.content);
          if (site !== undefined) {
            middleware.push(site);
          }
        },
      });

      if (routes.length === 0) {
        return Promise.resolve([]);
      }

      const contentLines = ctx.content.split("\n");
      const mountedBehindAuthElsewhere = otherFileRegistersAuth(ctx.fileSet, ctx.filePath);
      const findings: Finding[] = [];

      for (const route of routes) {
        const handlerText = sourceOf(ctx.content, route.handler);
        const handlerStart = route.handler.start ?? 0;
        const handlerEnd = route.handler.end ?? 0;
        const handlerCallsAuth = authCallOffsets.some((offset) => offset >= handlerStart && offset < handlerEnd);
        const protectedRoute =
          AUTH_LIKE_TEXT_RE.test(route.guardText) ||
          handlerCallsAuth ||
          IDENTITY_READ_RE.test(handlerText) ||
          NON_SESSION_AUTH_RE.test(handlerText) ||
          coveredByMiddleware(route, middleware) ||
          isPublicPath(route.path) ||
          hasPublicCommentNear(contentLines, route.line);
        if (protectedRoute) {
          continue;
        }

        const severity: Severity = mountedBehindAuthElsewhere ? "MEDIUM" : route.method === "GET" ? "HIGH" : "CRITICAL";
        const subject = `${framework} route ${route.method} ${route.path}`;
        findings.push({
          ruleId: "AUTH-01",
          category: "auth",
          detectorName: "server-route-auth",
          file: ctx.filePath,
          line: route.line,
          severity,
          confidence: mountedBehindAuthElsewhere ? "LOW" : "MEDIUM",
          message: mountedBehindAuthElsewhere
            ? `${subject} has no authentication check of its own; auth middleware is registered elsewhere — verify this router is mounted behind it.`
            : `${subject} has no authentication or authorization check.`,
          remediation:
            "Add an auth middleware to this route (e.g. app.post(path, requireAuth, handler) or a router-level router.use(requireAuth)) or check req.user / the session at the top of the handler and return 401 when it is missing; mark intentionally open routes with a // public comment.",
          matchedText: `${route.method} ${route.path}`,
        });
      }

      return Promise.resolve(findings);
    } catch {
      // No-throw contract (src/core/types.ts Detector.detect).
      return Promise.resolve([]);
    }
  },
};

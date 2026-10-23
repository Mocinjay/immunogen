/**
 * routeAuthDetector — CAT-3 AUTH-01 (unprotected Next.js server entry point)
 * detector, AST-based and stack-gated.
 *
 * AUTH-01 (FEATURES.md CAT-3): a server entry point with no
 * authentication/authorization check is the single most-reproduced AI-app
 * vulnerability class (CVE-2025-48757 / CVE-2025-29927). Three Next.js entry
 * point shapes are covered, all reachable by anyone on the internet:
 *   - App Router route handlers: `app/<path>/route.{ts,tsx,js,jsx}` exporting
 *     GET/POST/PUT/PATCH/DELETE.
 *   - Pages Router API routes: `pages/api/**` default-exported handlers.
 *   - Server Actions: every exported function of a `"use server"` module —
 *     each one is a public POST endpoint, whatever the UI that calls it.
 * A text regex cannot reliably tell an EXPORTED handler from an internal
 * helper of the same name, so this detector walks the pre-built `ctx.ast`
 * (ARCHITECTURE.md Pattern 1: parse once, share many) via @babel/traverse.
 *
 * Decision flow inside `detect()` (cheap gates first):
 *   1. STACK GATE — if `frameworks.has("nextjs")` is false, return [] (ENG-04).
 *   2. FP ALLOWLIST — test/fixture/mock/example paths return [] (PITFALLS.md
 *      Pitfall 1); a file that is none of the three entry-point shapes
 *      returns [].
 *   3. PUBLIC-PATH SUPPRESSION — a route whose path has a `public` segment,
 *      or is public by its nature (health checks, OG images, sitemaps, and
 *      sign-in/sign-up/OAuth-callback endpoints), returns [].
 *   4. AST GUARD — `if (!isBabelFile(ctx.ast)) return []` (PITFALLS.md
 *      Pitfall 3: a parse-failed file has no AST; emit nothing, never throw).
 *   5. WALK — collect file-scoped auth evidence and every exported handler,
 *      then emit one finding per handler with no auth evidence and no
 *      `// public` comment near it.
 *
 * Auth evidence (file-scoped) is any of: a recognized auth/session helper
 * call (`auth()`, `getServerSession()`, `currentUser()`, `requireUser()`,
 * `supabase.auth.getUser()`, `jwt.verify()`, ...), a webhook signature
 * check (`constructEvent`, svix `wh.verify`, `timingSafeEqual`), a shared
 * secret check (`CRON_SECRET`), or reading the `Authorization`/API-key
 * header. File-scoped is deliberately the LOWER false-positive choice: a
 * route file that calls an auth helper at all is overwhelmingly protecting
 * its handlers.
 *
 * Severity: a state-changing handler (POST/PUT/PATCH/DELETE, a Pages API
 * handler that serves every method, a Server Action) is CRITICAL; a
 * read-only GET is HIGH, since plenty of GETs are public by intent. When a
 * `middleware.ts` enforces auth (`auth.protect()`, `withAuth`,
 * `next-auth/middleware`, ...), every finding drops to MEDIUM/LOW with a
 * "verify the matcher covers this route" message — a middleware matcher
 * that skips `/api` is exactly the bug that still needs a human look.
 *
 * Confidence is MEDIUM, not HIGH, exactly per FEATURES.md CAT-3 AUTH-01 (FP
 * risk = MEDIUM: a genuinely public route is a real false-positive source).
 *
 * AST-only (ENG-05): reads `ctx.ast` and walks nodes. Never imports a
 * process/exec primitive, never evaluates/requires/spawns scanned source.
 *
 * No-throw contract (src/core/types.ts Detector.detect): the whole body runs
 * inside a try/catch returning `Promise.resolve([])` on any failure.
 */
import { isBabelFile, traverseAst } from "../ast/ast-utils.js";
import { isAuthCall, NON_SESSION_AUTH_RE, PUBLIC_BY_NATURE_SEGMENTS } from "./auth-evidence.js";

import type { Detector, DetectorContext, Finding, Severity } from "../../core/types.js";
import type { ExportDefaultDeclaration, ExportNamedDeclaration, File } from "@babel/types";

/** HTTP-method export names that mark a Next.js App Router route handler. */
const HTTP_METHOD_NAMES = new Set(["GET", "POST", "PUT", "PATCH", "DELETE"]);

/** Path segments that suppress every finding in this file (FP allowlist — PITFALLS.md Pitfall 1). */
const FP_ALLOWLIST_SEGMENTS = new Set(["__tests__", "fixtures", "mocks", "examples"]);

/** Route-path segment marking a deliberately public endpoint (FEATURES.md CAT-3 FP note). */
const PUBLIC_SEGMENT = "public";

/** Comment fragment a developer adds to opt a handler out of AUTH-01. */
const PUBLIC_COMMENT_MARKER = "// public";

/**
 * Text markers of a `middleware.ts` that enforces auth (not just reads it):
 * Clerk `auth.protect()`, NextAuth `withAuth` / `next-auth/middleware` /
 * `auth as middleware`, or a redirect/401 driven by a session lookup.
 */
const ENFORCING_MIDDLEWARE_RE =
  /auth\.protect\s*\(|\bwithAuth\b|next-auth\/middleware|auth\s+as\s+middleware|export\s+default\s+auth\b|(?:getUser|getSession|getToken)\s*\([\s\S]*?(?:redirect|status:\s*401)/;

/** Basenames of a Next.js middleware file (`proxy.ts` is its Next.js 16 name). */
const MIDDLEWARE_BASENAMES = new Set(["middleware.ts", "middleware.js", "proxy.ts", "proxy.js"]);

type EntryKind = "route" | "pages-api" | "server-action";

/**
 * True when `filePath` falls inside a test/fixture/mock/example directory,
 * or its basename marks it as a test or story file (`.test.` / `.stories.`).
 * Mirrors src/detectors/secrets/entropy-detector.ts `isAllowlistedPath`.
 */
function isAllowlistedPath(filePath: string): boolean {
  const segments = filePath.split("/");
  if (segments.some((segment) => FP_ALLOWLIST_SEGMENTS.has(segment))) {
    return true;
  }
  const basename = segments.at(-1) ?? "";
  return basename.includes(".test.") || basename.includes(".stories.");
}

/** True when `filePath`'s basename is a Next.js App Router route handler (`route.<ext>`) under an `app/` directory. */
function isRouteFile(filePath: string): boolean {
  const segments = filePath.split("/");
  const basename = segments.at(-1) ?? "";
  return /^route\.(?:ts|tsx|js|jsx)$/.test(basename) && segments.includes("app");
}

/** True when `filePath` is a Next.js Pages Router API route (`pages/api/...`). */
function isPagesApiFile(filePath: string): boolean {
  return /(?:^|\/)pages\/api\/.+\.(?:ts|tsx|js|jsx|mjs)$/.test(filePath);
}

/** True when the parsed module opens with a `"use server"` directive. */
function isServerActionModule(ast: File): boolean {
  return ast.program.directives.some((directive) => directive.value.value === "use server");
}

/** True when any path segment of `filePath` is `public` or a public-by-nature route name. */
function hasPublicPathSegment(filePath: string): boolean {
  return filePath
    .split("/")
    .some((segment) => segment === PUBLIC_SEGMENT || PUBLIC_BY_NATURE_SEGMENTS.has(segment.toLowerCase()));
}

/** True when the repo's Next.js middleware enforces authentication. */
function hasEnforcingMiddleware(fileSet: ReadonlyMap<string, string>): boolean {
  for (const [path, content] of fileSet) {
    const segments = path.split("/");
    const basename = segments.at(-1) ?? "";
    if (MIDDLEWARE_BASENAMES.has(basename) && ENFORCING_MIDDLEWARE_RE.test(content)) {
      return true;
    }
  }
  return false;
}

/**
 * Returns the exported name when `node` exports a handler this entry-point
 * kind serves: an HTTP-method-named function for a route file, or any
 * function for a Server Action module. Both `export async function X` and
 * `export const X = async () => ...` forms are recognized.
 */
function exportedHandlerName(node: ExportNamedDeclaration, kind: EntryKind): string | undefined {
  const accepts = (name: string): boolean => (kind === "server-action" ? true : HTTP_METHOD_NAMES.has(name));
  const declaration = node.declaration;
  if (declaration === null || declaration === undefined) {
    return undefined;
  }

  if (declaration.type === "FunctionDeclaration" && declaration.id !== null && declaration.id !== undefined) {
    const name = declaration.id.name;
    return accepts(name) ? name : undefined;
  }

  if (declaration.type === "VariableDeclaration") {
    for (const declarator of declaration.declarations) {
      if (declarator.id.type !== "Identifier") {
        continue;
      }
      const name = declarator.id.name;
      if (!accepts(name)) {
        continue;
      }
      const init = declarator.init;
      if (
        init !== null &&
        init !== undefined &&
        (init.type === "ArrowFunctionExpression" || init.type === "FunctionExpression")
      ) {
        return name;
      }
    }
  }

  return undefined;
}

/**
 * True when a Pages API `export default` is a handler that needs its own
 * auth check: a function, or a reference to one. A default export wrapped
 * in a call is left alone when the wrapper itself is auth
 * (`withApiAuthRequired(handler)`, `withAuth(handler)`).
 */
function isDefaultHandlerExport(node: ExportDefaultDeclaration): boolean {
  const declaration = node.declaration;
  if (
    declaration.type === "FunctionDeclaration" ||
    declaration.type === "ArrowFunctionExpression" ||
    declaration.type === "FunctionExpression" ||
    declaration.type === "Identifier"
  ) {
    return true;
  }
  if (declaration.type === "CallExpression") {
    const wrapperIsAuth =
      isAuthCall(declaration) || (declaration.callee.type === "Identifier" && /auth/i.test(declaration.callee.name));
    return !wrapperIsAuth;
  }
  return false;
}

/**
 * True when a `// public` endpoint comment sits on the handler's own line or
 * the line directly above it (the per-handler opt-out — FEATURES.md CAT-3
 * FP note).
 */
function hasPublicCommentNear(contentLines: string[], handlerLine: number): boolean {
  const sameLine = contentLines.at(handlerLine - 1) ?? "";
  const aboveLine = handlerLine >= 2 ? (contentLines.at(handlerLine - 2) ?? "") : "";
  return sameLine.includes(PUBLIC_COMMENT_MARKER) || aboveLine.includes(PUBLIC_COMMENT_MARKER);
}

interface HandlerSite {
  name: string;
  line: number;
}

/** Human description of one unprotected handler, for the finding message. */
function describeHandler(kind: EntryKind, name: string): string {
  if (kind === "server-action") {
    return `Server Action ${name} (a "use server" export — a public POST endpoint)`;
  }
  if (kind === "pages-api") {
    return "Pages Router API handler (serves every HTTP method)";
  }
  return `Exported Next.js route handler ${name}`;
}

/** Builds the AUTH-01 finding for one unprotected handler. */
function buildFinding(
  filePath: string,
  kind: EntryKind,
  site: HandlerSite,
  middlewareEnforcesAuth: boolean,
): Finding {
  const subject = describeHandler(kind, site.name);
  const severity: Severity = middlewareEnforcesAuth ? "MEDIUM" : site.name === "GET" ? "HIGH" : "CRITICAL";
  return {
    ruleId: "AUTH-01",
    category: "auth",
    detectorName: "route-auth",
    file: filePath,
    line: site.line,
    severity,
    confidence: middlewareEnforcesAuth ? "LOW" : "MEDIUM",
    message: middlewareEnforcesAuth
      ? `${subject} has no authentication check of its own; middleware enforces auth — verify its matcher covers this route.`
      : `${subject} has no authentication or authorization check.`,
    remediation:
      "Add a session/token check at the top of this handler (e.g. await auth(), await getServerSession(), or supabase.auth.getUser()) and return a 401 response when the request is unauthenticated, or annotate the handler with a // public endpoint comment if it is intentionally open.",
    matchedText: site.name,
  };
}

export const routeAuthDetector: Detector = {
  config: {
    name: "route-auth",
    category: "auth",
    requiresStack: ["nextjs"],
    globs: ["**/*.{ts,tsx,js,jsx,mjs}"],
  },

  // Not declared `async`: the body is synchronous AST work wrapped in
  // Promise.resolve(), matching the entropy-detector.ts precedent (async is
  // reserved for detectors that actually await a network/disk call).
  detect(ctx: DetectorContext): Promise<Finding[]> {
    try {
      // 1. STACK GATE — AUTH-01 only applies to Next.js apps (ENG-04). Also
      //    declared via config.requiresStack, but enforced in code because the
      //    registry does not yet gate on requiresStack (closed by 05-08).
      if (!ctx.stackHints.frameworks.has("nextjs")) {
        return Promise.resolve([]);
      }

      // 2. FP ALLOWLIST + entry-point guard (cheap text check before the AST).
      if (isAllowlistedPath(ctx.filePath)) {
        return Promise.resolve([]);
      }
      const routeKind: EntryKind | undefined = isRouteFile(ctx.filePath)
        ? "route"
        : isPagesApiFile(ctx.filePath)
          ? "pages-api"
          : undefined;
      if (routeKind === undefined && !ctx.content.includes("use server")) {
        return Promise.resolve([]);
      }

      // 3. PUBLIC-PATH SUPPRESSION — a `public` (or public-by-nature) route segment is open by design.
      if (hasPublicPathSegment(ctx.filePath)) {
        return Promise.resolve([]);
      }

      // 4. AST GUARD — no AST (parse-failed file) means no finding, no throw.
      if (!isBabelFile(ctx.ast)) {
        return Promise.resolve([]);
      }
      const kind: EntryKind | undefined =
        routeKind ?? (isServerActionModule(ctx.ast) ? "server-action" : undefined);
      if (kind === undefined) {
        return Promise.resolve([]);
      }

      // Webhook signatures, cron secrets, and API-key headers are auth too.
      if (NON_SESSION_AUTH_RE.test(ctx.content)) {
        return Promise.resolve([]);
      }

      // 5. WALK the File once: gather file-scoped auth-call presence and every
      //    exported handler site (name + line).
      let fileHasAuthCall = false;
      const handlerSites: HandlerSite[] = [];

      traverseAst(ctx.ast, {
        CallExpression(path) {
          if (isAuthCall(path.node)) {
            fileHasAuthCall = true;
          }
        },
        ExportNamedDeclaration(path) {
          if (kind === "pages-api") {
            return;
          }
          const name = exportedHandlerName(path.node, kind);
          if (name === undefined) {
            return;
          }
          const line = path.node.loc?.start.line ?? 1;
          handlerSites.push({ name, line });
        },
        ExportDefaultDeclaration(path) {
          if (kind !== "pages-api" || !isDefaultHandlerExport(path.node)) {
            return;
          }
          handlerSites.push({ name: "default", line: path.node.loc?.start.line ?? 1 });
        },
      });

      // A file-scoped auth call protects the file's handlers — suppress all.
      if (fileHasAuthCall) {
        return Promise.resolve([]);
      }

      const contentLines = ctx.content.split("\n");
      const middlewareEnforcesAuth = hasEnforcingMiddleware(ctx.fileSet);
      const findings = handlerSites
        // Per-handler `// public` opt-out (comment on or above the handler).
        .filter((site) => !hasPublicCommentNear(contentLines, site.line))
        .map((site) => buildFinding(ctx.filePath, kind, site, middlewareEnforcesAuth));

      return Promise.resolve(findings);
    } catch {
      // No-throw contract (src/core/types.ts Detector.detect).
      return Promise.resolve([]);
    }
  },
};

/**
 * routeAuthDetector — CAT-3 AUTH-01 (unprotected Next.js App Router route
 * handler) detector, AST-based and stack-gated.
 *
 * AUTH-01 (FEATURES.md CAT-3): an app/api route handler file (Next.js App
 * Router) that exports a GET/POST/PUT/PATCH/DELETE handler containing no
 * authentication/authorization check is the single most-reproduced AI-app
 * vulnerability class (CVE-2025-48757 / CVE-2025-29927). A text regex cannot
 * reliably tell an EXPORTED route handler from an internal helper of the same
 * name, so this detector walks the pre-built `ctx.ast` (ARCHITECTURE.md
 * Pattern 1: parse once, share many) via @babel/traverse instead.
 *
 * Decision flow inside `detect()` (cheap gates first):
 *   1. STACK GATE — if `frameworks.has("nextjs")` is false, return [] (ENG-04:
 *      a missing stack hint disables the whole framework-specific rule).
 *   2. FP ALLOWLIST — test/fixture/mock/example paths return [] (PITFALLS.md
 *      Pitfall 1), and a non-`route.*` filename returns [] defensively (the
 *      registry already pre-filters on globs, but the detector double-checks).
 *   3. PUBLIC-PATH SUPPRESSION — a route whose path has a `public` segment is
 *      a legitimately open endpoint (FEATURES.md CAT-3 FP note), return [].
 *   4. AST GUARD — `if (!isBabelFile(ctx.ast)) return []` (PITFALLS.md Pitfall
 *      3: a parse-failed file has no AST; emit nothing, never throw).
 *   5. WALK — collect file-scoped auth-call presence and every exported
 *      HTTP-method handler, then emit one CRITICAL/MEDIUM finding per handler
 *      that has no auth call and no `// public` comment near it.
 *
 * Confidence is MEDIUM, not HIGH, exactly per FEATURES.md CAT-3 AUTH-01 (FP
 * risk = MEDIUM: a genuinely public route is a real false-positive source).
 *
 * Auth-call presence is computed file-scoped (any matching call anywhere in
 * the File), not proven to be lexically inside the specific handler — this is
 * deliberately the LOWER false-positive choice: a route file that imports and
 * calls an auth helper at all is overwhelmingly protecting its handlers, and
 * insisting the call sit inside each handler body would re-flag the common
 * middleware/wrapper patterns AUTH-01 is not meant to catch.
 *
 * AST-only (ENG-05): reads `ctx.ast` and walks nodes. Never imports a
 * process/exec primitive, never evaluates/requires/spawns scanned source.
 *
 * No-throw contract (src/core/types.ts Detector.detect): the whole body runs
 * inside a try/catch returning `Promise.resolve([])` on any failure.
 */
import { isBabelFile, traverseAst } from "../ast/ast-utils.js";

import type { Detector, DetectorContext, Finding } from "../../core/types.js";
import type { CallExpression, ExportNamedDeclaration } from "@babel/types";

/** HTTP-method export names that mark a Next.js App Router route handler. */
const HTTP_METHOD_NAMES = new Set(["GET", "POST", "PUT", "PATCH", "DELETE"]);

/** Bare-identifier auth helpers whose presence (called) suppresses AUTH-01. */
const AUTH_CALL_IDENTIFIERS = new Set(["getServerSession", "auth", "verifyToken", "getUserFromRequest"]);

/** Member-call auth helpers (`object.property(...)`) that suppress AUTH-01. */
const AUTH_MEMBER_METHODS = new Set(["getUser", "getSession"]);

/** Path segments that suppress every finding in this file (FP allowlist — PITFALLS.md Pitfall 1). */
const FP_ALLOWLIST_SEGMENTS = new Set(["__tests__", "fixtures", "mocks", "examples"]);

/** Route-path segment marking a deliberately public endpoint (FEATURES.md CAT-3 FP note). */
const PUBLIC_SEGMENT = "public";

/** Comment fragment a developer adds to opt a handler out of AUTH-01. */
const PUBLIC_COMMENT_MARKER = "// public";

/**
 * True when `filePath` falls inside a test/fixture/mock/example directory, or
 * its basename marks it as a test/story file. Mirrors entropy-detector.ts's
 * `isAllowlistedPath` style (segment split, no micromatch).
 */
function isAllowlistedPath(filePath: string): boolean {
  const segments = filePath.split("/");
  if (segments.some((segment) => FP_ALLOWLIST_SEGMENTS.has(segment))) {
    return true;
  }
  const basename = segments.at(-1) ?? "";
  return basename.includes(".test.") || basename.includes(".stories.");
}

/** True when `filePath`'s basename is a Next.js App Router route handler (`route.<ext>`). */
function isRouteFile(filePath: string): boolean {
  const basename = filePath.split("/").at(-1) ?? "";
  return (
    basename === "route.ts" || basename === "route.tsx" || basename === "route.js" || basename === "route.jsx"
  );
}

/** True when any path segment of `filePath` is exactly `public`. */
function hasPublicPathSegment(filePath: string): boolean {
  return filePath.split("/").some((segment) => segment === PUBLIC_SEGMENT);
}

/**
 * Returns the exported HTTP-method handler name declared by `node`, or
 * undefined. Handles both `export async function GET(...)` (a function
 * declaration) and `export const GET = (...) => {...}` / `export const GET =
 * async function (...) {...}` (a variable declaration with a function-valued
 * initializer). Returns the method NAME (e.g. "GET") so the caller can also
 * recover the `.loc` line for the Finding.
 */
function exportedHandlerName(node: ExportNamedDeclaration): string | undefined {
  const declaration = node.declaration;
  if (declaration === null || declaration === undefined) {
    return undefined;
  }

  if (declaration.type === "FunctionDeclaration" && declaration.id !== null && declaration.id !== undefined) {
    const name = declaration.id.name;
    return HTTP_METHOD_NAMES.has(name) ? name : undefined;
  }

  if (declaration.type === "VariableDeclaration") {
    for (const declarator of declaration.declarations) {
      if (declarator.id.type !== "Identifier") {
        continue;
      }
      const name = declarator.id.name;
      if (!HTTP_METHOD_NAMES.has(name)) {
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

/** True when `call` is a recognized auth helper call (bare identifier OR member method). */
function isAuthCall(call: CallExpression): boolean {
  const callee = call.callee;
  if (callee.type === "Identifier") {
    return AUTH_CALL_IDENTIFIERS.has(callee.name);
  }
  if (callee.type === "MemberExpression" && callee.property.type === "Identifier") {
    // Matches the `.auth.getUser()` / `.auth.getSession()` shape (e.g.
    // supabase.auth.getUser) by the terminal method name — file-scoped
    // presence is sufficient and lower-FP than pinning the receiver chain.
    return AUTH_MEMBER_METHODS.has(callee.property.name);
  }
  return false;
}

/**
 * True when a `// public` opt-out comment sits on or just above the handler
 * declared at 1-indexed `handlerLine`. Scans `contentLines` for the handler's
 * own line and the line immediately above it (a leading annotation), using
 * `.at()` rather than bracket indexing to avoid a dynamic-index access
 * pattern (entropy-detector.ts precedent).
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

export const routeAuthDetector: Detector = {
  config: {
    name: "route-auth",
    category: "auth",
    requiresStack: ["nextjs"],
    globs: ["**/app/**/route.ts", "**/app/**/route.tsx", "**/app/**/route.js", "**/app/**/route.jsx"],
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

      // 2. FP ALLOWLIST + route-filename guard.
      if (isAllowlistedPath(ctx.filePath) || !isRouteFile(ctx.filePath)) {
        return Promise.resolve([]);
      }

      // 3. PUBLIC-PATH SUPPRESSION — a `public` route segment is open by design.
      if (hasPublicPathSegment(ctx.filePath)) {
        return Promise.resolve([]);
      }

      // 4. AST GUARD — no AST (parse-failed file) means no finding, no throw.
      if (!isBabelFile(ctx.ast)) {
        return Promise.resolve([]);
      }

      // 5. WALK the File once: gather file-scoped auth-call presence and every
      //    exported HTTP-method handler site (name + line).
      let fileHasAuthCall = false;
      const handlerSites: HandlerSite[] = [];

      traverseAst(ctx.ast, {
        CallExpression(path) {
          if (isAuthCall(path.node)) {
            fileHasAuthCall = true;
          }
        },
        ExportNamedDeclaration(path) {
          const name = exportedHandlerName(path.node);
          if (name === undefined) {
            return;
          }
          const line = path.node.loc?.start.line ?? 1;
          handlerSites.push({ name, line });
        },
      });

      // A file-scoped auth call protects the route's handlers — suppress all.
      if (fileHasAuthCall) {
        return Promise.resolve([]);
      }

      const contentLines = ctx.content.split("\n");
      const findings: Finding[] = [];

      for (const site of handlerSites) {
        // Per-handler `// public` opt-out (comment on or above the handler).
        if (hasPublicCommentNear(contentLines, site.line)) {
          continue;
        }
        findings.push({
          ruleId: "AUTH-01",
          category: "auth",
          detectorName: "route-auth",
          file: ctx.filePath,
          line: site.line,
          severity: "CRITICAL",
          confidence: "MEDIUM",
          message: `Exported Next.js route handler ${site.name} has no authentication or authorization check.`,
          remediation:
            "Add a session/token check at the top of this handler (e.g. await getServerSession() or supabase.auth.getUser()) and return a 401 response when the request is unauthenticated, or annotate the handler with a // public endpoint comment if it is intentionally open.",
          matchedText: site.name,
        });
      }

      return Promise.resolve(findings);
    } catch {
      // No-throw contract (src/core/types.ts Detector.detect).
      return Promise.resolve([]);
    }
  },
};

/**
 * pyGoRouteAuthDetector — CAT-3 AUTH-01 for Python (FastAPI, Flask) and Go
 * (net/http, Gin, Echo, Chi, Fiber) routes registered with no
 * authentication or authorization check. The Next.js and Node-server
 * shapes are covered by route-auth-detector.ts and
 * server-route-auth-detector.ts; this is the same rule for the two other
 * languages AI tools most often generate backends in.
 *
 * Python routes are decorated functions: `@app.post("/x")`,
 * `@router.get("/x")`, `@bp.route("/x", methods=["POST"])`. A route is
 * protected when another decorator on it looks like auth
 * (`@login_required`, `@jwt_required()`, `@token_required`, ...), its
 * decorator or signature declares an auth dependency
 * (`Depends(get_current_user)`, `dependencies=[Depends(verify_token)]`,
 * `Security(...)`), its body reads the authenticated identity
 * (`current_user`, `g.user`, `request.state.user`, `get_jwt_identity()`,
 * `session[...]`) or checks a webhook signature / API-key header, its router
 * was created with auth dependencies (`APIRouter(dependencies=[...])`), or
 * the file registers an auth `before_request` hook.
 *
 * Go routes are registrations: `r.POST("/x", h)` (Gin, Echo),
 * `r.Post("/x", h)` (Chi, Fiber), `mux.HandleFunc("POST /x", h)` /
 * `http.HandleFunc("/x", h)` (net/http). A route is protected when a
 * middleware argument or wrapping call looks like auth, its router variable
 * is a group created with or given auth middleware (`admin :=
 * r.Group("/admin", AuthRequired())`, `admin.Use(...)`, Chi `r.With(auth)`),
 * an auth `.Use(...)` precedes it in the file, or its handler — inline, or a
 * named function found anywhere in the repo's Go files — reads the
 * authenticated identity (`c.Get("user")`, `r.Context().Value(...)`,
 * `c.Locals("user")`, verified claims) or checks a signature/API key.
 *
 * Shared with the JS rules: public-by-nature paths and `# public` /
 * `// public` comments are exempt; state-changing methods are CRITICAL,
 * GET is HIGH, and a Go `HandleFunc` with no method (it serves every
 * method) is HIGH; auth middleware registered in ANOTHER file drops
 * findings to MEDIUM/LOW with a verify note. Confidence MEDIUM.
 *
 * Text-only (ENG-05): never evaluates scanned source.
 *
 * No-throw contract (src/core/types.ts Detector.detect): the whole body runs
 * inside a try/catch returning `[]` on any failure.
 */
import { PUBLIC_BY_NATURE_SEGMENTS } from "./auth-evidence.js";

import type { Detector, DetectorContext, Finding, Severity } from "../../core/types.js";
import { isTestOrFixturePath } from "../shared/test-paths.js";

/** Text that looks like an auth decorator, dependency, middleware, or guard. */
const AUTH_LIKE_TEXT_RE =
  /auth|login_required|jwt|token|session|current_user|permission|role|admin|protect|guard|verify|api_?key|signed_?in|requires?_user/i;

/** Python handler text that reads the authenticated identity or verifies a caller. */
const PY_IDENTITY_RE =
  /\bcurrent_user\b|\bg\.user\b|\brequest\.(?:user|state\.user|auth)\b|\bsession\s*(?:\[|\.get\()|get_jwt_identity\(|verify_jwt_in_request\(|get_current_user\(|verify_(?:id_)?token\(|\.auth\.get_user\(|construct_event\(|compare_digest\(|headers\.get\(\s*["'](?:authorization|x-api-key)["']/i;

/** Go handler text that reads the authenticated identity or verifies a caller. */
const GO_IDENTITY_RE =
  /\.(?:Get|MustGet|Locals)\(\s*"(?:user|userID|user_id|claims|session|auth)"|\.Context\(\)\.Value\(|\bctx\.Value\(|\bclaims\b|VerifyIDToken\(|jwt\.Parse|\.ConstructEvent\(|hmac\.Equal\(|Header\.Get\(\s*"(?:Authorization|X-API-Key)"\)/;

/** Python route decorator: `@<receiver>.<method>("/path"...`. */
const PY_ROUTE_DECORATOR_RE = /^\s*@(\w+)\.(get|post|put|patch|delete|route|api_route)\(\s*["'](\/[^"']*)["']/;

/** Go route registration: `<receiver>.<Method>("<path>", <args>`. */
const GO_ROUTE_RE =
  /\b(\w+)\.(GET|POST|PUT|PATCH|DELETE|Any|Get|Post|Put|Patch|Delete|All|HandleFunc|Handle)\(\s*"([^"]*)"\s*,\s*(.*)$/;

/** Go router group or `.Use(` registration: captures the variable and the arguments. */
const GO_GROUP_RE = /\b(\w+)\s*:?=\s*\w+\.(?:Group|Route)\(\s*"[^"]*"\s*,?\s*(.*)$/;
const GO_USE_RE = /\b(\w+)\.(?:Use|With)\(\s*(.*)$/;

/** True when a route path is public by nature, carries a `public` segment, or is the bare root. */
function isPublicPath(path: string): boolean {
  if (path === "/" || path === "") {
    return true;
  }
  return path
    .split("/")
    .some((segment) => segment.toLowerCase() === "public" || PUBLIC_BY_NATURE_SEGMENTS.has(segment.toLowerCase()));
}

/** True when a `public` marker comment sits on line `index` or the line above. */
function hasPublicComment(lines: string[], index: number): boolean {
  return [lines.at(index), index >= 1 ? lines.at(index - 1) : undefined].some(
    (line) => line !== undefined && /(?:#|\/\/)\s*public\b/.test(line),
  );
}

/** Indentation width of a line. */
function indentOf(line: string): number {
  return line.length - line.trimStart().length;
}

/** One unprotected route. */
interface RouteHit {
  framework: string;
  method: string;
  path: string;
  line: number;
}

/** HTTP methods named in a Python `methods=[...]` argument, or the decorator's own method. */
function pythonMethods(method: string, decoratorText: string): string[] {
  if (method !== "route" && method !== "api_route") {
    return [method.toUpperCase()];
  }
  const listed = decoratorText.match(/methods\s*=\s*[[(]([^\])]*)[\])]/)?.[1];
  const methods = [...(listed ?? "").matchAll(/["'](\w+)["']/g)].map((match) => (match[1] ?? "").toUpperCase());
  return methods.length > 0 ? methods : ["GET"];
}

/** True when a Python `def` signature line closes the parameter list: `...) :` or `...) -> T:`. */
function isSignatureEnd(line: string): boolean {
  const trimmed = line.trimEnd();
  return trimmed.endsWith(":") && trimmed.includes(")");
}

/** Python router variables created with auth dependencies, and whether the file has an auth before_request hook. */
function pythonFileGuards(lines: string[]): { guardedReceivers: Set<string>; beforeRequestAuth: boolean } {
  const guardedReceivers = new Set<string>();
  let beforeRequestAuth = false;
  for (const [index, line] of lines.entries()) {
    const router = line.match(/^\s*(\w+)\s*=\s*(?:APIRouter|FastAPI|Blueprint)\((.*)$/);
    if (router !== null && /dependencies\s*=/.test(router[2] ?? "") && AUTH_LIKE_TEXT_RE.test(router[2] ?? "")) {
      guardedReceivers.add(router[1] ?? "");
    }
    if (/^\s*@\w+\.before(?:_app)?_request\b/.test(line)) {
      const body = lines.slice(index + 1, index + 15).join("\n");
      if (AUTH_LIKE_TEXT_RE.test(body)) {
        beforeRequestAuth = true;
      }
    }
  }
  return { guardedReceivers, beforeRequestAuth };
}

/** Unprotected Python routes in one file. */
function pythonRoutes(lines: string[], framework: string): RouteHit[] {
  const hits: RouteHit[] = [];
  const { guardedReceivers, beforeRequestAuth } = pythonFileGuards(lines);
  if (beforeRequestAuth) {
    return hits;
  }

  for (const [index, line] of lines.entries()) {
    const route = line.match(PY_ROUTE_DECORATOR_RE);
    if (route === null) {
      continue;
    }
    const [, receiver = "", method = "", path = ""] = route;

    // Collect the whole decorator stack and the def signature around this decorator.
    let start = index;
    while (start > 0 && /^\s*@/.test(lines.at(start - 1) ?? "")) {
      start -= 1;
    }
    let defIndex = index + 1;
    while (defIndex < lines.length && !/^def\s/.test((lines.at(defIndex) ?? "").trimStart().replace(/^async\s+/, ""))) {
      defIndex += 1;
    }
    if (defIndex >= lines.length) {
      continue;
    }
    let signatureEnd = defIndex;
    // The signature ends on the first line that closes the parameter list and ends with ":".
    while (signatureEnd < lines.length - 1 && !isSignatureEnd(lines.at(signatureEnd) ?? "")) {
      signatureEnd += 1;
    }
    const decorators = lines.slice(start, defIndex).join("\n");
    const signature = lines.slice(defIndex, signatureEnd + 1).join("\n");
    const otherDecorators = decorators.replace(line, "");
    const defIndent = indentOf(lines.at(defIndex) ?? "");
    let bodyEnd = signatureEnd + 1;
    while (
      bodyEnd < lines.length &&
      ((lines.at(bodyEnd) ?? "").trim() === "" || indentOf(lines.at(bodyEnd) ?? "") > defIndent)
    ) {
      bodyEnd += 1;
    }
    const body = lines.slice(signatureEnd + 1, bodyEnd).join("\n");

    const routeArgs = decorators.slice(decorators.indexOf(line) + line.indexOf(path) + path.length);
    const protectedRoute =
      guardedReceivers.has(receiver) ||
      AUTH_LIKE_TEXT_RE.test(otherDecorators) ||
      (/dependencies\s*=/.test(routeArgs) && AUTH_LIKE_TEXT_RE.test(routeArgs)) ||
      (/\b(?:Depends|Security)\(/.test(signature) && AUTH_LIKE_TEXT_RE.test(signature)) ||
      PY_IDENTITY_RE.test(body) ||
      isPublicPath(path) ||
      hasPublicComment(lines, start);
    if (protectedRoute) {
      continue;
    }
    for (const routeMethod of pythonMethods(method, decorators)) {
      hits.push({ framework, method: routeMethod, path, line: index + 1 });
    }
  }
  return hits;
}

/** Splits a Go argument list on top-level commas (ignoring commas nested in parens/braces or strings). */
function splitTopLevelArgs(text: string): string[] {
  const args: string[] = [];
  let depth = 0;
  let current = "";
  let inString = false;
  for (const char of text) {
    if (char === '"') {
      inString = !inString;
    } else if (!inString && (char === "(" || char === "{" || char === "[")) {
      depth += 1;
    } else if (!inString && (char === ")" || char === "}" || char === "]")) {
      depth -= 1;
      if (depth < 0) {
        break;
      }
    } else if (!inString && char === "," && depth === 0) {
      args.push(current.trim());
      current = "";
      continue;
    }
    current += char;
  }
  if (current.trim() !== "") {
    args.push(current.trim());
  }
  return args;
}

/** Body text of a Go function literal starting on `lines[index]` (brace-balanced, capped). */
function goInlineBody(lines: string[], index: number): string {
  let depth = 0;
  const body: string[] = [];
  for (const line of lines.slice(index, index + 200)) {
    body.push(line);
    depth += (line.match(/\{/g) ?? []).length - (line.match(/\}/g) ?? []).length;
    if (depth <= 0 && body.length > 1) {
      break;
    }
  }
  return body.join("\n");
}

/** Body text of a named Go function/method (`createOrder` or `h.CreateOrder`) found in any Go file. */
function goNamedHandlerBody(name: string, fileSet: ReadonlyMap<string, string>): string | undefined {
  const bare = name.split(".").at(-1) ?? name;
  if (!/^\w+$/.test(bare)) {
    return undefined;
  }
  // eslint-disable-next-line security/detect-non-literal-regexp -- `bare` is restricted to \w+ just above
  const declaration = new RegExp(`\\nfunc\\s+(?:\\([^)]*\\)\\s*)?${bare}\\s*\\(`);
  for (const [path, content] of fileSet) {
    if (!path.endsWith(".go")) {
      continue;
    }
    const match = `\n${content}`.match(declaration);
    if (match?.index !== undefined) {
      const start = match.index;
      const next = `\n${content}`.indexOf("\nfunc ", start + 1);
      return `\n${content}`.slice(start, next === -1 ? undefined : next);
    }
  }
  return undefined;
}

/** Display name for the Go web framework in use. */
function goFrameworkName(frameworks: ReadonlySet<string>, method: string): string {
  if (method === "HandleFunc" || method === "Handle") {
    return "net/http";
  }
  for (const [hint, name] of [
    ["gin", "Gin"],
    ["echo", "Echo"],
    ["chi", "Chi"],
    ["fiber", "Fiber"],
  ] as const) {
    if (frameworks.has(hint)) {
      return name;
    }
  }
  return "Go";
}

/** Unprotected Go routes in one file. */
function goRoutes(lines: string[], ctx: DetectorContext): RouteHit[] {
  const hits: RouteHit[] = [];
  const guardedReceivers = new Set<string>();
  let fileWideAuthFrom = Number.POSITIVE_INFINITY;

  for (const [index, line] of lines.entries()) {
    if (/^\s*\/\//.test(line)) {
      continue;
    }
    const group = line.match(GO_GROUP_RE);
    if (group !== null && AUTH_LIKE_TEXT_RE.test(group[2] ?? "")) {
      guardedReceivers.add(group[1] ?? "");
    }
    const use = line.match(GO_USE_RE);
    if (use !== null && AUTH_LIKE_TEXT_RE.test(use[2] ?? "")) {
      guardedReceivers.add(use[1] ?? "");
      if (/^(?:r|router|e|app|mux|engine|api|g)$/.test(use[1] ?? "") && !line.includes(".With(")) {
        fileWideAuthFrom = Math.min(fileWideAuthFrom, index);
      }
    }

    const route = line.match(GO_ROUTE_RE);
    if (route === null) {
      continue;
    }
    const [, receiver = "", rawMethod = "", rawPath = "", rest = ""] = route;
    const methodPrefix = rawPath.match(/^([A-Z]+)\s+(\/.*)$/);
    const path = methodPrefix?.[2] ?? rawPath;
    if (!path.startsWith("/")) {
      continue;
    }
    const method =
      methodPrefix?.[1] ?? (rawMethod === "HandleFunc" || rawMethod === "Handle" || rawMethod === "Any" || rawMethod === "All"
        ? "ANY"
        : rawMethod.toUpperCase());

    const args = splitTopLevelArgs(rest);
    const handlerArg = args.at(-1) ?? "";
    const middlewareText = args.slice(0, -1).join(" ");
    const wrapsHandler = /^\w[\w.]*\(/.test(handlerArg) && !handlerArg.startsWith("func(");
    const handlerBody = handlerArg.startsWith("func(")
      ? goInlineBody(lines, index)
      : goNamedHandlerBody(handlerArg.replace(/^http\.HandlerFunc\(|\)$/g, ""), ctx.fileSet);

    const protectedRoute =
      guardedReceivers.has(receiver) ||
      index > fileWideAuthFrom ||
      AUTH_LIKE_TEXT_RE.test(middlewareText) ||
      (wrapsHandler && AUTH_LIKE_TEXT_RE.test(handlerArg.slice(0, handlerArg.indexOf("(")))) ||
      (handlerBody !== undefined && GO_IDENTITY_RE.test(handlerBody)) ||
      isPublicPath(path) ||
      hasPublicComment(lines, index);
    if (!protectedRoute) {
      hits.push({ framework: goFrameworkName(ctx.stackHints.frameworks, rawMethod), method, path, line: index + 1 });
    }
  }
  return hits;
}

/** True when another Python / Go file registers auth-looking middleware or hooks. */
function otherFileRegistersAuth(fileSet: ReadonlyMap<string, string>, filePath: string, language: "py" | "go"): boolean {
  const pattern =
    language === "py"
      ? /before(?:_app)?_request[\s\S]{0,400}?(?:auth|login|jwt|token|session)|include_router\([^)]*dependencies\s*=[^)]*(?:auth|user|token)/i
      : /\.Use\([^)\n]*(?:auth|jwt|session|token|protect|guard)/i;
  for (const [path, content] of fileSet) {
    if (path !== filePath && path.endsWith(`.${language}`) && pattern.test(content)) {
      return true;
    }
  }
  return false;
}

export const pyGoRouteAuthDetector: Detector = {
  config: {
    name: "py-go-route-auth",
    category: "auth",
    requiresStack: ["fastapi", "flask", "go"],
    globs: ["**/*.{py,go}"],
  },

  // Not declared `async`: synchronous text work wrapped in Promise.resolve().
  detect(ctx: DetectorContext): Promise<Finding[]> {
    try {
      const frameworks = ctx.stackHints.frameworks;
      const language = ctx.filePath.endsWith(".go") ? "go" : "py";
      const pythonFramework = frameworks.has("fastapi") ? "FastAPI" : frameworks.has("flask") ? "Flask" : undefined;
      if (isTestOrFixturePath(ctx.filePath) || (language === "py" ? pythonFramework === undefined : !frameworks.has("go"))) {
        return Promise.resolve([]);
      }

      const lines = ctx.content.split("\n");
      const hits = language === "py" ? pythonRoutes(lines, pythonFramework ?? "Python") : goRoutes(lines, ctx);
      if (hits.length === 0) {
        return Promise.resolve([]);
      }
      const mountedBehindAuthElsewhere = otherFileRegistersAuth(ctx.fileSet, ctx.filePath, language);

      const findings: Finding[] = hits.map((hit) => {
        const severity: Severity = mountedBehindAuthElsewhere
          ? "MEDIUM"
          : hit.method === "GET" || hit.method === "ANY"
            ? "HIGH"
            : "CRITICAL";
        const subject = `${hit.framework} route ${hit.method} ${hit.path}`;
        return {
          ruleId: "AUTH-01",
          category: "auth",
          detectorName: "py-go-route-auth",
          file: ctx.filePath,
          line: hit.line,
          severity,
          confidence: mountedBehindAuthElsewhere ? "LOW" : "MEDIUM",
          message: mountedBehindAuthElsewhere
            ? `${subject} has no authentication check of its own; auth middleware is registered elsewhere — verify it covers this route.`
            : `${subject} has no authentication or authorization check.`,
          remediation:
            language === "py"
              ? "Require an authenticated user on this route — FastAPI: add user = Depends(get_current_user) (or dependencies=[Depends(...)] on the router); Flask: add @login_required / @jwt_required() — and mark intentionally open routes with a # public comment."
              : "Wrap this route in auth middleware (e.g. a router group with r.Group(\"/api\", AuthRequired()) or chi's r.With(auth)) or check the authenticated user at the top of the handler and return 401; mark intentionally open routes with a // public comment.",
          matchedText: `${hit.method} ${hit.path}`,
        };
      });
      return Promise.resolve(findings);
    } catch {
      // No-throw contract (src/core/types.ts Detector.detect).
      return Promise.resolve([]);
    }
  },
};

/**
 * dangerousCodeDetector — AST-based detector for three server-code mistakes
 * coding agents ship when they reach for the quickest working snippet:
 *
 *   INJECT-02 (HIGH): SQL built by string interpolation or concatenation and
 *   handed to a raw-query API — Prisma `$queryRawUnsafe`/`$executeRawUnsafe`,
 *   or `.query()` / `.execute()` / `.raw()` / `.unsafe()` called with a
 *   template literal or `+` concatenation whose text starts like a SQL
 *   statement. Tagged templates (`sql\`...\``, Prisma `$queryRaw\`...\``)
 *   parameterize their values and are never flagged.
 *
 *   INJECT-03 (HIGH): dynamic code or shell execution — `eval(x)`,
 *   `new Function(x)`, `vm.runIn*Context(x)` with a non-literal argument,
 *   or `exec`/`execSync` with an interpolated/concatenated command string.
 *
 *   AUTH-06 (HIGH): `jwt.decode()` (jsonwebtoken) in a file that never
 *   verifies a token — `decode` only base64-decodes the payload, so anyone
 *   can mint a token claiming to be any user.
 *
 *   INJECT-04 (HIGH): server-side request forgery — `fetch` / `axios` /
 *   `got` / `ky` / `http(s).get` / `undici` called with a URL whose scheme
 *   or host comes from the request (request-input.ts). A fixed origin with
 *   a request-controlled path is not flagged. Skipped in client
 *   components and in files that validate targets against an allowlist.
 *
 * All three are MEDIUM confidence: the interpolated value may be a trusted
 * constant, which static analysis cannot always prove.
 *
 * AST-only (ENG-05): reads `ctx.ast`; never evaluates scanned source. The
 * names `eval`/`exec`/`Function` below are compared as strings on parsed
 * nodes — this module never calls them.
 *
 * No-throw contract (src/core/types.ts Detector.detect): the whole body runs
 * inside a try/catch returning `[]` on any failure.
 */
import { isBabelFile, traverseAst } from "../ast/ast-utils.js";
import { collectRequestTaintedNames, isRequestControlled } from "./request-input.js";

import type { Category, Detector, DetectorContext, Finding } from "../../core/types.js";
import type { CallExpression, Expression, NewExpression, Node } from "@babel/types";

/** Path segments that suppress every finding in this file (FP allowlist — PITFALLS.md Pitfall 1). */
const FP_ALLOWLIST_SEGMENTS = new Set(["__tests__", "fixtures", "mocks", "examples"]);

/** Prisma's explicitly-unsafe raw query APIs: any non-literal SQL string is injectable. */
const RAW_UNSAFE_METHODS = new Set(["$queryRawUnsafe", "$executeRawUnsafe", "queryRawUnsafe", "executeRawUnsafe"]);

/** Generic query APIs that are injectable when handed a SQL string built by interpolation. */
const QUERY_METHODS = new Set(["query", "execute", "raw", "unsafe", "run", "all", "get", "prepare"]);

/** Static text that opens a SQL statement. */
const SQL_START_RE = /^\s*(?:select|insert|update|delete|with|replace|merge|upsert|create|drop|alter)\b/i;

/** Shell-execution function names (child_process). */
const SHELL_EXEC_NAMES = new Set(["exec", "execSync"]);

/** `vm` module methods that compile and run a code string. */
const VM_RUN_METHODS = new Set(["runInNewContext", "runInThisContext", "runInContext"]);

/** Receivers whose `.decode()` is jsonwebtoken's unverified decode. */
const JWT_RECEIVERS = new Set(["jwt", "jsonwebtoken"]);

/** A token verification anywhere in the file (jsonwebtoken, jose, or a project helper). */
const TOKEN_VERIFY_RE = /\b(?:jwt|jsonwebtoken)\s*\.\s*verify\s*\(|\bjwtVerify\s*\(|\bverify(?:Token|Jwt|IdToken)\s*\(/;

/** Outbound HTTP clients called as a bare function: `fetch(url)`, `got(url)`, `axios(url)`. */
const HTTP_CLIENT_FUNCTIONS = new Set(["fetch", "$fetch", "ofetch", "got", "ky", "axios", "needle", "request", "superagent"]);

/** Outbound HTTP client receivers whose `.get/.post/.request(...)` takes the URL first. */
const HTTP_CLIENT_RECEIVERS = new Set(["axios", "got", "ky", "http", "https", "undici", "superagent", "needle", "ofetch"]);

/** HTTP client methods that take the target URL as their first argument. */
const HTTP_CLIENT_METHODS = new Set(["get", "post", "put", "patch", "delete", "head", "request", "fetch", "stream"]);

/** Evidence that the file validates outbound targets (allowlist / hostname check) — suppresses INJECT-04. */
const URL_ALLOWLIST_RE =
  /allowed(?:Hosts|Domains|Origins|Urls)|ALLOWED_(?:HOSTS|DOMAINS|ORIGINS|URLS)|isAllowed(?:Url|Host)|isSafeUrl|validateUrl|\.hostname\s*(?:===|!==)|ssrf/i;

/** True for client-side code, where a request to a user-chosen URL runs in the user's own browser, not on the server. */
function isClientCode(filePath: string, content: string): boolean {
  if (/^\s*["']use client["']/m.test(content)) {
    return true;
  }
  return filePath.split("/").some((segment) => segment === "components" || segment === "hooks");
}

/** The URL argument of an outbound HTTP call (first argument, or the `url` property of an options object), when the call is one. */
function outboundUrlArgument(call: CallExpression): Node | undefined {
  const callee = call.callee;
  const isClientFunction = callee.type === "Identifier" && HTTP_CLIENT_FUNCTIONS.has(callee.name);
  const isClientMethod =
    callee.type === "MemberExpression" &&
    callee.object.type === "Identifier" &&
    HTTP_CLIENT_RECEIVERS.has(callee.object.name) &&
    callee.property.type === "Identifier" &&
    HTTP_CLIENT_METHODS.has(callee.property.name);
  if (!isClientFunction && !isClientMethod) {
    return undefined;
  }
  const first = call.arguments.at(0);
  if (first?.type === "ObjectExpression") {
    for (const property of first.properties) {
      if (property.type === "ObjectProperty" && property.key.type === "Identifier" && property.key.name === "url") {
        return property.value;
      }
    }
    return undefined;
  }
  return first;
}

/** True when `filePath` falls inside a test/fixture/mock/example directory, or is a test/story file. */
function isAllowlistedPath(filePath: string): boolean {
  const segments = filePath.split("/");
  if (segments.some((segment) => FP_ALLOWLIST_SEGMENTS.has(segment))) {
    return true;
  }
  const basename = segments.at(-1) ?? "";
  return basename.includes(".test.") || basename.includes(".spec.") || basename.includes(".stories.");
}

/** The called function's own name: `foo` for `foo()`, `bar` for `x.y.bar()`. */
function calleeName(call: CallExpression | NewExpression): string | undefined {
  const callee = call.callee;
  if (callee.type === "Identifier") {
    return callee.name;
  }
  if (callee.type === "MemberExpression" && callee.property.type === "Identifier") {
    return callee.property.name;
  }
  return undefined;
}

/** The receiver identifier of a member call (`jwt` for `jwt.decode()`), if it is a plain identifier. */
function receiverName(call: CallExpression): string | undefined {
  const callee = call.callee;
  if (callee.type === "MemberExpression" && callee.object.type === "Identifier") {
    return callee.object.name;
  }
  return undefined;
}

/** True when `node` is a string assembled at runtime: a template literal with `${}` parts or a `+` concatenation. */
function isDynamicString(node: Node | undefined): boolean {
  if (node === undefined) {
    return false;
  }
  if (node.type === "TemplateLiteral") {
    return node.expressions.length > 0;
  }
  return node.type === "BinaryExpression" && node.operator === "+";
}

/** The leading static text of a dynamic string (first template quasi, or left-most string literal of a concatenation). */
function leadingText(node: Node): string {
  if (node.type === "TemplateLiteral") {
    return node.quasis.at(0)?.value.cooked ?? "";
  }
  if (node.type === "BinaryExpression") {
    return leadingText(node.left);
  }
  if (node.type === "StringLiteral") {
    return node.value;
  }
  return "";
}

/** True when `node` is not a compile-time constant string (so its runtime value may be attacker-controlled). */
function isNonLiteral(node: Node | undefined): boolean {
  if (node === undefined) {
    return false;
  }
  if (node.type === "StringLiteral" || node.type === "NumericLiteral") {
    return false;
  }
  return !(node.type === "TemplateLiteral" && node.expressions.length === 0);
}

interface Site {
  ruleId: "INJECT-02" | "INJECT-03" | "AUTH-06" | "INJECT-04";
  line: number;
  matchedText: string;
}

/** Message, remediation, and category per ruleId. */
const RULE_COPY: Record<Site["ruleId"], { category: Category; message: string; remediation: string }> = {
  "INJECT-02": {
    category: "injection",
    message: "SQL query built with string interpolation/concatenation passed to a raw query API (possible SQL injection).",
    remediation:
      "Pass values as bound parameters instead of splicing them into the SQL text — e.g. Prisma's tagged $queryRaw`... ${value}`, a sql`` tagged template, or query('... where id = $1', [id]).",
  },
  "INJECT-03": {
    category: "injection",
    message: "Dynamic code or shell execution with a non-literal input (eval / new Function / vm / exec) — possible remote code execution.",
    remediation:
      "Remove the dynamic evaluation. Parse data with JSON.parse, map user choices to a fixed allowlist of functions, and run subprocesses with execFile/spawn and an argument array instead of a shell string.",
  },
  "AUTH-06": {
    category: "auth",
    message: "JWT payload read with jwt.decode() and never verified in this file — anyone can forge a token claiming to be any user.",
    remediation:
      "Use jwt.verify(token, secret) (or jose's jwtVerify) before trusting any claim; jwt.decode() does not check the signature.",
  },
  "INJECT-04": {
    category: "injection",
    message:
      "Server-side request to a URL taken from the request (SSRF) — an attacker can make your server call internal services (cloud metadata at 169.254.169.254, localhost admin ports) and read the response.",
    remediation:
      "Never fetch a user-supplied URL directly: parse it with new URL(), allow only an explicit list of hosts (and https), reject private/link-local addresses after DNS resolution, and disable automatic redirects.",
  },
};

export const dangerousCodeDetector: Detector = {
  config: {
    name: "dangerous-code",
    category: "injection",
    globs: ["**/*.{ts,tsx,js,jsx,mjs,cjs}"],
  },

  // Not declared `async`: synchronous AST work wrapped in Promise.resolve().
  detect(ctx: DetectorContext): Promise<Finding[]> {
    try {
      if (isAllowlistedPath(ctx.filePath) || !isBabelFile(ctx.ast)) {
        return Promise.resolve([]);
      }

      const sites: Site[] = [];
      const fileVerifiesTokens = TOKEN_VERIFY_RE.test(ctx.content);
      const checksSsrf = !isClientCode(ctx.filePath, ctx.content) && !URL_ALLOWLIST_RE.test(ctx.content);
      const tainted = collectRequestTaintedNames(ctx.ast, ctx.content);

      const checkCall = (call: CallExpression | NewExpression): void => {
        const name = calleeName(call);
        if (name === undefined) {
          return;
        }
        const line = call.loc?.start.line ?? 1;
        const firstArg = call.arguments.at(0) as Expression | undefined;
        const lastArg = call.arguments.at(-1) as Expression | undefined;

        if (RAW_UNSAFE_METHODS.has(name) && isNonLiteral(firstArg) && isDynamicString(firstArg)) {
          sites.push({ ruleId: "INJECT-02", line, matchedText: name });
        } else if (
          call.type === "CallExpression" &&
          QUERY_METHODS.has(name) &&
          firstArg !== undefined &&
          isDynamicString(firstArg) &&
          SQL_START_RE.test(leadingText(firstArg))
        ) {
          sites.push({ ruleId: "INJECT-02", line, matchedText: name });
        } else if (call.type === "CallExpression" && call.callee.type === "Identifier" && name === "eval" && isNonLiteral(firstArg)) {
          sites.push({ ruleId: "INJECT-03", line, matchedText: "eval" });
        } else if (call.type === "NewExpression" && name === "Function" && isNonLiteral(lastArg)) {
          sites.push({ ruleId: "INJECT-03", line, matchedText: "new Function" });
        } else if (VM_RUN_METHODS.has(name) && isNonLiteral(firstArg)) {
          sites.push({ ruleId: "INJECT-03", line, matchedText: name });
        } else if (SHELL_EXEC_NAMES.has(name) && isDynamicString(firstArg)) {
          sites.push({ ruleId: "INJECT-03", line, matchedText: name });
        } else if (
          call.type === "CallExpression" &&
          name === "decode" &&
          JWT_RECEIVERS.has(receiverName(call) ?? "") &&
          !fileVerifiesTokens
        ) {
          sites.push({ ruleId: "AUTH-06", line, matchedText: "jwt.decode" });
        } else if (
          checksSsrf &&
          call.type === "CallExpression" &&
          isRequestControlled(outboundUrlArgument(call), tainted, ctx.content, "url")
        ) {
          sites.push({ ruleId: "INJECT-04", line, matchedText: name });
        }
      };

      traverseAst(ctx.ast, {
        CallExpression(path) {
          checkCall(path.node);
        },
        NewExpression(path) {
          checkCall(path.node);
        },
      });

      const findings: Finding[] = sites.map((site) => ({
        ruleId: site.ruleId,
        category: RULE_COPY[site.ruleId].category,
        detectorName: "dangerous-code",
        file: ctx.filePath,
        line: site.line,
        severity: "HIGH",
        confidence: "MEDIUM",
        message: RULE_COPY[site.ruleId].message,
        remediation: RULE_COPY[site.ruleId].remediation,
        matchedText: site.matchedText,
      }));

      return Promise.resolve(findings);
    } catch {
      // No-throw contract (src/core/types.ts Detector.detect).
      return Promise.resolve([]);
    }
  },
};

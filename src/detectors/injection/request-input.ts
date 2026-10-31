/**
 * request-input — a deliberately small, file-scoped "does this value come
 * from the HTTP request?" check shared by the SSRF (INJECT-04) and open
 * redirect (REDIRECT-01) rules in dangerous-code-detector.ts.
 *
 * Not a full taint analysis: a value is request-controlled when its source
 * text reads request input directly (`req.query.url`, `searchParams.get("next")`,
 * `await req.json()`, `formData.get(...)`, Hono `c.req.query(...)`, Koa
 * `ctx.query`, `router.query`, `location.search`, ...), or it is an
 * identifier (or a property of one) that some declaration / assignment in
 * the same file initialized from such a read — including destructuring
 * (`const { url } = await req.json()`). This catches the shape AI-generated
 * handlers actually take, where the request value travels through one or
 * two local variables before reaching the sink, without the false
 * positives of guessing across files.
 *
 * AST-only (ENG-05): reads `ctx.ast` and slices `ctx.content` by node
 * offsets; never evaluates scanned source.
 */
import { traverseAst } from "../ast/ast-utils.js";

import type { File, Node } from "@babel/types";

/** Source text that reads HTTP request input (server frameworks and the browser URL). */
export const REQUEST_SOURCE_RE =
  /\b(?:req|request)\.(?:query|body|params|url|nextUrl)\b|\b(?:req|request)\.(?:json|formData|text)\(\)|\bsearchParams\.get\(|\bformData\.get\(|\bc\.req\.(?:query|param|json|parseBody|header)\(|\bctx\.(?:query|params|request\.body)\b|\buseSearchParams\(\)|\brouter\.query\b|\b(?:window\.)?location\.(?:search|hash)\b|\bnew\s+URLSearchParams\(/;

/** Source text of `node`, sliced from the file by its byte offsets. */
function sourceOf(content: string, node: Node): string {
  return node.start === null || node.start === undefined || node.end === null || node.end === undefined
    ? ""
    : content.slice(node.start, node.end);
}

/** Every local name bound to a pattern (`a`, `{ a, b: c }`, `[a, ...rest]`). */
function boundNames(pattern: Node): string[] {
  switch (pattern.type) {
    case "Identifier":
      return [pattern.name];
    case "ObjectPattern":
      return pattern.properties.flatMap((property) =>
        property.type === "RestElement" ? boundNames(property.argument) : boundNames(property.value),
      );
    case "ArrayPattern":
      return pattern.elements.flatMap((element) => (element === null ? [] : boundNames(element)));
    case "AssignmentPattern":
      return boundNames(pattern.left);
    case "RestElement":
      return boundNames(pattern.argument);
    default:
      return [];
  }
}

/**
 * Names in the file initialized (or assigned) from request input, iterated
 * to a fixed point so `const body = await req.json(); const url = body.url;`
 * marks both `body` and `url`.
 */
export function collectRequestTaintedNames(ast: File, content: string): Set<string> {
  const bindings: Array<{ names: string[]; init: Node }> = [];
  traverseAst(ast, {
    VariableDeclarator(path) {
      const init = path.node.init;
      if (init !== null && init !== undefined) {
        bindings.push({ names: boundNames(path.node.id), init });
      }
    },
    AssignmentExpression(path) {
      if (path.node.operator === "=") {
        bindings.push({ names: boundNames(path.node.left), init: path.node.right });
      }
    },
  });

  const tainted = new Set<string>();
  let changed = true;
  while (changed) {
    changed = false;
    for (const binding of bindings) {
      if (binding.names.every((name) => tainted.has(name))) {
        continue;
      }
      if (isRequestControlled(binding.init, tainted, content, "value")) {
        for (const name of binding.names) {
          if (!tainted.has(name)) {
            tainted.add(name);
            changed = true;
          }
        }
      }
    }
  }
  return tainted;
}

/**
 * How a string argument is used: `"value"` (any part request-controlled),
 * `"url"` (the attacker must control the scheme/host — a fixed
 * `https://api.example.com/${id}` prefix is NOT controlled), or
 * `"redirect"` (the attacker must control where the target starts — a
 * fixed `/dashboard?x=${y}` prefix is NOT controlled).
 */
export type InputUse = "value" | "url" | "redirect";

/** True when `node` evaluates to a request-controlled value for the given use. */
export function isRequestControlled(node: Node | null | undefined, tainted: ReadonlySet<string>, content: string, use: InputUse): boolean {
  if (node === null || node === undefined) {
    return false;
  }
  switch (node.type) {
    case "Identifier":
      return tainted.has(node.name);
    case "AwaitExpression":
      return isRequestControlled(node.argument, tainted, content, use);
    case "TSNonNullExpression":
    case "TSAsExpression":
    case "TSSatisfiesExpression":
    case "ParenthesizedExpression":
      return isRequestControlled(node.expression, tainted, content, use);
    case "MemberExpression":
    case "OptionalMemberExpression":
      return isRequestControlled(node.object, tainted, content, use) || REQUEST_SOURCE_RE.test(sourceOf(content, node));
    case "CallExpression":
    case "OptionalCallExpression":
      // `String(x)`, `decodeURIComponent(x)`, `x.toString()`, `x.trim()` pass the value through.
      return (
        REQUEST_SOURCE_RE.test(sourceOf(content, node)) ||
        node.arguments.some((argument) => isRequestControlled(argument, tainted, content, use)) ||
        (node.callee.type === "MemberExpression" && isRequestControlled(node.callee.object, tainted, content, use))
      );
    case "NewExpression":
      // `new URL(x)` / `new URL(x, base)` — the first argument decides the target.
      return isRequestControlled(node.arguments.at(0), tainted, content, use);
    case "LogicalExpression":
    case "ConditionalExpression":
      return node.type === "LogicalExpression"
        ? isRequestControlled(node.left, tainted, content, use) || isRequestControlled(node.right, tainted, content, use)
        : isRequestControlled(node.consequent, tainted, content, use) || isRequestControlled(node.alternate, tainted, content, use);
    case "TemplateLiteral": {
      const leading = node.quasis.at(0)?.value.cooked ?? "";
      if (use === "url" && /^[a-z][\w+.-]*:\/\/[^/$]+/i.test(leading)) {
        return false;
      }
      if (use === "redirect" && leading !== "" && !/^[a-z][\w+.-]*:\/\/$/i.test(leading)) {
        return false;
      }
      const controlling = use === "value" ? node.expressions : node.expressions.slice(0, 1);
      return controlling.some((expression) => isRequestControlled(expression, tainted, content, use));
    }
    case "BinaryExpression": {
      if (node.operator !== "+") {
        return false;
      }
      if (use !== "value" && node.left.type === "StringLiteral" && node.left.value !== "") {
        return use === "url" ? !/^[a-z][\w+.-]*:\/\/[^/]+/i.test(node.left.value) && isRequestControlled(node.right, tainted, content, use) : false;
      }
      return isRequestControlled(node.left, tainted, content, use) || (use === "value" && isRequestControlled(node.right, tainted, content, use));
    }
    default:
      return REQUEST_SOURCE_RE.test(sourceOf(content, node));
  }
}

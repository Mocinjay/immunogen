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

/**
 * Parameter names of the functions a `"use server"` module exports — every
 * one is a public endpoint whose arguments arrive from the client, whatever
 * their TypeScript types say. Empty for any other module.
 */
export function serverActionParamNames(ast: File): string[] {
  if (!ast.program.directives.some((directive) => directive.value.value === "use server")) {
    return [];
  }
  const names: string[] = [];
  traverseAst(ast, {
    ExportNamedDeclaration(path) {
      const declaration = path.node.declaration;
      const functions =
        declaration?.type === "FunctionDeclaration"
          ? [declaration]
          : declaration?.type === "VariableDeclaration"
            ? declaration.declarations.flatMap((declarator) =>
                declarator.init?.type === "ArrowFunctionExpression" || declarator.init?.type === "FunctionExpression" ? [declarator.init] : [],
              )
            : [];
      for (const fn of functions) {
        for (const param of fn.params) {
          names.push(...boundNames(param));
        }
      }
    },
  });
  return names;
}

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

/** Array methods whose callback receives the receiver's elements (`items.map((item) => ...)`). */
const ELEMENT_CALLBACK_METHODS = new Set(["map", "forEach", "filter", "flatMap", "some", "every", "find", "findLast", "reduce", "reduceRight"]);

/** Compound assignments that carry the right-hand value into the target (`total += item.price`). */
const ACCUMULATING_OPERATORS = new Set(["=", "+=", "-=", "*=", "/="]);

/** Options for `collectRequestTaintedNames`. */
export interface TaintOptions {
  /**
   * `"value"` (default) is the permissive check the SSRF / redirect rules
   * use. `"data"` is the strict check for business-data rules: a call's
   * result is request data only when the call reads the request itself or
   * passes a value straight through (`Number(x)`, `Math.round(x)`,
   * `body.items.map(...)`), never because a request value was one of its
   * arguments (`prisma.product.findUnique({ where: { id: body.id } })`
   * returns trusted data). `"data"` also follows `for...of` loops, array
   * callbacks, and `+=` accumulation.
   */
  use?: "value" | "data";
  /** Names that hold request input from the start (e.g. a route handler's `params` argument). */
  seeds?: Iterable<string>;
}

/**
 * Names in the file initialized (or assigned) from request input, iterated
 * to a fixed point so `const body = await req.json(); const url = body.url;`
 * marks both `body` and `url`.
 */
export function collectRequestTaintedNames(ast: File, content: string, options: TaintOptions = {}): Set<string> {
  const use = options.use ?? "value";
  const bindings: Array<{ names: string[]; init: Node }> = [];
  traverseAst(ast, {
    VariableDeclarator(path) {
      const init = path.node.init;
      if (init !== null && init !== undefined) {
        bindings.push({ names: boundNames(path.node.id), init });
      }
    },
    AssignmentExpression(path) {
      if (path.node.operator === "=" || (use === "data" && ACCUMULATING_OPERATORS.has(path.node.operator))) {
        bindings.push({ names: boundNames(path.node.left), init: path.node.right });
      }
    },
    ForOfStatement(path) {
      if (use !== "data") {
        return;
      }
      const left = path.node.left;
      const pattern = left.type === "VariableDeclaration" ? left.declarations.at(0)?.id : left;
      if (pattern !== undefined) {
        bindings.push({ names: boundNames(pattern), init: path.node.right });
      }
    },
    CallExpression(path) {
      const callee = path.node.callee;
      if (use !== "data" || callee.type !== "MemberExpression" || callee.property.type !== "Identifier") {
        return;
      }
      const method = callee.property.name;
      const callback = path.node.arguments.at(0);
      if (!ELEMENT_CALLBACK_METHODS.has(method) || (callback?.type !== "ArrowFunctionExpression" && callback?.type !== "FunctionExpression")) {
        return;
      }
      const element = callback.params.at(method.startsWith("reduce") ? 1 : 0);
      if (element !== undefined) {
        bindings.push({ names: boundNames(element), init: callee.object });
      }
    },
  });

  const tainted = new Set<string>(options.seeds ?? []);
  let changed = true;
  while (changed) {
    changed = false;
    for (const binding of bindings) {
      if (binding.names.every((name) => tainted.has(name))) {
        continue;
      }
      if (isRequestControlled(binding.init, tainted, content, use)) {
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
 * fixed `/dashboard?x=${y}` prefix is NOT controlled), or `"data"` (the
 * strict business-data check described on `TaintOptions.use`).
 */
export type InputUse = "value" | "url" | "redirect" | "data";

/** Global functions that pass their argument's value through (`Number(body.qty)`). */
const PASS_THROUGH_FUNCTIONS = new Set(["Number", "parseInt", "parseFloat", "String", "Boolean", "BigInt", "decodeURIComponent", "decodeURI"]);

/** Built-in namespaces whose static methods pass their arguments' values through (`Math.round(x)`, `Object.fromEntries(fd)`). */
const PASS_THROUGH_NAMESPACES = new Set(["Math", "JSON", "Number", "String", "Object", "Array"]);

/** Constructors that wrap a value without changing who controls it (`new Decimal(body.price)`). */
const PASS_THROUGH_CONSTRUCTORS = new Set(["Number", "String", "Decimal", "Big", "BigNumber", "URLSearchParams", "URL"]);

/**
 * Dotted access-path text of a member chain (`req.body.price`,
 * `request.nextUrl.searchParams.get`), `()` for a zero-argument call in
 * the chain (`req.json()`), or undefined for any other shape. Lets the
 * strict check match REQUEST_SOURCE_RE against the access path alone, so
 * a request read buried in a call's arguments never counts.
 */
export function accessPath(node: Node): string | undefined {
  switch (node.type) {
    case "Identifier":
      return node.name;
    case "ThisExpression":
      return "this";
    case "MemberExpression":
    case "OptionalMemberExpression": {
      const object = accessPath(node.object);
      if (object === undefined) {
        return undefined;
      }
      if (!node.computed && node.property.type === "Identifier") {
        return `${object}.${node.property.name}`;
      }
      return node.property.type === "StringLiteral" ? `${object}.${node.property.value}` : undefined;
    }
    case "CallExpression":
    case "OptionalCallExpression": {
      const callee = accessPath(node.callee);
      return callee === undefined || node.arguments.length > 0 ? undefined : `${callee}()`;
    }
    case "AwaitExpression":
      return accessPath(node.argument);
    default:
      return undefined;
  }
}

/** The strict ("data") request-controlled check — see `TaintOptions.use`. */
function isRequestData(node: Node, tainted: ReadonlySet<string>, content: string): boolean {
  const recurse = (child: Node | null | undefined): boolean => isRequestControlled(child, tainted, content, "data");
  switch (node.type) {
    case "Identifier":
      return tainted.has(node.name);
    case "AwaitExpression":
      return recurse(node.argument);
    case "TSNonNullExpression":
    case "TSAsExpression":
    case "TSSatisfiesExpression":
    case "ParenthesizedExpression":
      return recurse(node.expression);
    case "UnaryExpression":
      return (node.operator === "-" || node.operator === "+") && recurse(node.argument);
    case "MemberExpression":
    case "OptionalMemberExpression":
      return recurse(node.object) || REQUEST_SOURCE_RE.test(accessPath(node) ?? "");
    case "CallExpression":
    case "OptionalCallExpression": {
      const callee = node.callee;
      const calleePath = accessPath(callee);
      if (calleePath !== undefined && REQUEST_SOURCE_RE.test(`${calleePath}()`)) {
        return true;
      }
      if (callee.type === "Identifier") {
        return PASS_THROUGH_FUNCTIONS.has(callee.name) && node.arguments.some((argument) => recurse(argument));
      }
      if (callee.type === "MemberExpression" || callee.type === "OptionalMemberExpression") {
        if (callee.object.type === "Identifier" && PASS_THROUGH_NAMESPACES.has(callee.object.name)) {
          return node.arguments.some((argument) => recurse(argument));
        }
        // A method of request data (`body.items.map(...)`, `price.toFixed(2)`) is request data.
        return recurse(callee.object);
      }
      return false;
    }
    case "NewExpression":
      return (
        node.callee.type === "Identifier" &&
        PASS_THROUGH_CONSTRUCTORS.has(node.callee.name) &&
        node.arguments.some((argument) => recurse(argument))
      );
    case "LogicalExpression":
      return recurse(node.left) || recurse(node.right);
    case "ConditionalExpression":
      return recurse(node.consequent) || recurse(node.alternate);
    case "BinaryExpression":
      return ["+", "-", "*", "/", "%", "**"].includes(node.operator) && (recurse(node.left) || recurse(node.right));
    case "TemplateLiteral":
      return node.expressions.some((expression) => recurse(expression));
    case "ArrayExpression":
      return node.elements.some((element) => element !== null && recurse(element.type === "SpreadElement" ? element.argument : element));
    case "ObjectExpression":
      return node.properties.some((property) => property.type === "SpreadElement" && recurse(property.argument));
    default:
      return false;
  }
}

/** True when `node` evaluates to a request-controlled value for the given use. */
export function isRequestControlled(node: Node | null | undefined, tainted: ReadonlySet<string>, content: string, use: InputUse): boolean {
  if (node === null || node === undefined) {
    return false;
  }
  if (use === "data") {
    return isRequestData(node, tainted, content);
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

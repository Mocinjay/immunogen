/**
 * xssDetector — CAT-6 INJECT-01 (dangerouslySetInnerHTML with a non-literal
 * value and no DOMPurify sanitizer in the same file) detector, AST-based.
 *
 * INJECT-01: the canonical React XSS sink is a
 * dangerouslySetInnerHTML attribute whose __html receives a VARIABLE (an
 * identifier, member access, call result, or a template literal carrying
 * expressions) when the file performs no DOMPurify.sanitize() anywhere. A
 * string literal in __html is author-controlled, not user-controlled, and is
 * not flagged. This needs AST analysis: a text regex cannot reliably tell a
 * literal __html from a variable one, nor see whether a sanitizer is present
 * elsewhere in the file.
 *
 * Decision flow inside detect() (cheap gates first):
 *   1. FP ALLOWLIST — test/fixture/mock/example paths return [].
 *   2. AST GUARD — if (!isBabelFile(ctx.ast)) return [] (a parse-failed
 *      file has no AST; emit nothing, never throw).
 *   3. SANITIZER PASS — walk the File once to compute a file-scoped boolean:
 *      does it contain a DOMPurify.sanitize(...) member call, or a bare
 *      sanitize(...) call? If so the file is treated as sanitized and emits
 *      nothing.
 *   4. SINK PASS — find every dangerouslySetInnerHTML JSX attribute carrying a
 *      __html property; flag the ones whose __html value is non-literal.
 *
 * Beyond React, the same rule covers the other places a stored or
 * reflected `<script>` / `<img onerror>` in a username ends up as markup:
 *   - DOM sinks: `el.innerHTML = ` / `outerHTML = ` a template literal,
 *     concatenation, or property read (`user.name`), `insertAdjacentHTML`,
 *     and `document.write(ln)` with such a value;
 *   - Vue `v-html="..."` and Svelte `{@html ...}` with a non-literal value
 *     (text-matched in `.vue` / `.svelte` files);
 *   - server-rendered HTML: `res.send` / `res.write` / `res.end` / `c.html` /
 *     `reply.send` / `new Response` / `ctx.body =` with an HTML template
 *     literal that interpolates request input (reflected XSS).
 * A sanitizer / escaper anywhere in the file (DOMPurify, sanitize-html,
 * escapeHtml, lodash escape, he.encode, xss / filterXSS) suppresses the file.
 *
 * Confidence is MEDIUM, not HIGH: sanitization may legitimately happen in a
 * caller, so the finding's remediation says to verify it.
 *
 * AST-only (ENG-05): reads ctx.ast and walks nodes. Never imports a
 * process/exec primitive, never evaluates/requires/spawns scanned source.
 *
 * No-throw contract (src/core/types.ts Detector.detect): the whole body runs
 * inside a try/catch returning Promise.resolve([]) on any failure.
 */
import { isBabelFile, traverseAst } from "../ast/ast-utils.js";
import { collectRequestTaintedNames, isRequestControlled } from "./request-input.js";

import type { Detector, DetectorContext, Finding } from "../../core/types.js";
import type { CallExpression, JSXAttribute, Node, ObjectProperty } from "@babel/types";
import { isTestOrFixturePath } from "../shared/test-paths.js";

/** The React XSS-sink attribute name. */
const SINK_ATTRIBUTE = "dangerouslySetInnerHTML";

/** The HTML-payload property inside the sink's object literal. */
const HTML_PROPERTY = "__html";

/**
 * Sanitizer / HTML-escaper function names: DOMPurify `sanitize`,
 * sanitize-html `sanitizeHtml`, `escapeHtml` / `escapeHTML`, lodash
 * `escape`, `he.encode` / `he.escape`, js-xss `xss` / `filterXSS`.
 */
const SANITIZER_NAMES = new Set(["sanitize", "sanitizeHtml", "sanitizeHTML", "escapeHtml", "escapeHTML", "escape", "encode", "encodeHTML", "encodeHtml", "xss", "filterXSS"]);

/**
 * True when `call` is a sanitizer call: either a member call whose method is
 * a sanitizer name (matches DOMPurify.sanitize, purify.sanitize, he.encode,
 * etc. by terminal method name — file-scoped presence is sufficient), or a
 * bare sanitizer call (covers an imported `{ sanitize }`).
 */
function isSanitizerCall(call: CallExpression): boolean {
  const callee = call.callee;
  if (callee.type === "MemberExpression" && callee.property.type === "Identifier") {
    return SANITIZER_NAMES.has(callee.property.name);
  }
  if (callee.type === "Identifier") {
    return SANITIZER_NAMES.has(callee.name);
  }
  return false;
}

/** Text-level sanitizer evidence, for `.vue` / `.svelte` files that are not parsed. */
const SANITIZER_TEXT_RE = /\b(?:DOMPurify|sanitizeHtml|sanitize|escapeHtml|escapeHTML|filterXSS)\b/;

/** Vue `v-html="expr"` whose expression is not a quoted string literal. */
const VUE_V_HTML_RE = /\bv-html\s*=\s*"(?!\s*'[^']*'\s*")([^"]+)"/g;

/** Svelte `{@html expr}` whose expression is not a string literal. */
const SVELTE_HTML_RE = /\{@html\s+(?!["'`][^"'`]*["'`]\s*\})([^}]+)\}/g;

/** Member-call sinks that send an HTML body (Express / Hono / Fastify / Node http). */
const HTML_RESPONSE_METHODS = new Set(["send", "write", "end", "html"]);
const HTML_RESPONSE_RECEIVER_RE = /^(?:res|response|reply|c|ctx)$/;

/** A template literal / concatenation whose static text contains an HTML tag. */
function looksLikeHtml(node: Node): boolean {
  if (node.type === "TemplateLiteral") {
    return node.quasis.some((quasi) => /<[a-z!/]/i.test(quasi.value.cooked ?? ""));
  }
  if (node.type === "BinaryExpression" && node.operator === "+") {
    return looksLikeHtml(node.left) || looksLikeHtml(node.right);
  }
  return node.type === "StringLiteral" && /<[a-z!/]/i.test(node.value);
}

/**
 * True for a DOM-sink value built from data: a template literal with
 * `${}`, a `+` concatenation with a non-literal part, or a property read
 * (`user.name`). Bare identifiers and call results are left alone — they
 * are as often developer-built markup as user data.
 */
function isDataBuiltHtml(node: Node): boolean {
  if (node.type === "TemplateLiteral") {
    return node.expressions.length > 0;
  }
  if (node.type === "BinaryExpression" && node.operator === "+") {
    return !(node.left.type === "StringLiteral" && node.right.type === "StringLiteral");
  }
  return node.type === "MemberExpression" || node.type === "OptionalMemberExpression";
}

/** 1-indexed line of a character offset. */
function lineAt(content: string, offset: number): number {
  return content.slice(0, offset).split("\n").length;
}

/** INJECT-01 for a Vue / Svelte template (text-matched). */
function templateFindings(ctx: DetectorContext): Finding[] {
  if (SANITIZER_TEXT_RE.test(ctx.content)) {
    return [];
  }
  const isVue = ctx.filePath.endsWith(".vue");
  const pattern = isVue ? VUE_V_HTML_RE : SVELTE_HTML_RE;
  const sink = isVue ? "v-html" : "{@html}";
  return [...ctx.content.matchAll(pattern)].map((match) => ({
    ruleId: "INJECT-01",
    category: "injection",
    detectorName: "xss",
    file: ctx.filePath,
    line: lineAt(ctx.content, match.index),
    severity: "HIGH",
    confidence: "MEDIUM",
    message: `${sink} renders a non-literal value as raw HTML without sanitization (possible XSS) — a username like <img src=x onerror=...> runs as script.`,
    remediation: `Render the value as text ({{ value }} / {value}) instead of ${sink}, or sanitize it with DOMPurify.sanitize(value) first.`,
    matchedText: sink,
  }));
}

/**
 * True when `prop` is the __html object property whose value is a LITERAL
 * (a plain string literal, or a template literal with no `${...}`
 * expressions). A literal payload is author-controlled, not user-controlled,
 * and must NOT be flagged.
 */
function isLiteralHtmlProperty(prop: ObjectProperty): boolean {
  const value = prop.value;
  if (value.type === "StringLiteral") {
    return true;
  }
  if (value.type === "TemplateLiteral") {
    return value.expressions.length === 0;
  }
  return false;
}

/** The 1-indexed start line of `prop` (the __html value), falling back to the attribute line. */
function htmlPropertyLine(prop: ObjectProperty, attribute: JSXAttribute): number {
  return prop.loc?.start.line ?? attribute.loc?.start.line ?? 1;
}

/**
 * Returns the __html ObjectProperty of a dangerouslySetInnerHTML attribute, or
 * undefined when the attribute is not the sink, not an object-literal
 * expression container, or has no __html key. Pure shape inspection.
 */
function htmlPropertyOf(attribute: JSXAttribute): ObjectProperty | undefined {
  if (attribute.name.type !== "JSXIdentifier" || attribute.name.name !== SINK_ATTRIBUTE) {
    return undefined;
  }
  const value = attribute.value;
  if (value === null || value === undefined || value.type !== "JSXExpressionContainer") {
    return undefined;
  }
  const expression = value.expression;
  if (expression.type !== "ObjectExpression") {
    return undefined;
  }
  for (const member of expression.properties) {
    if (member.type !== "ObjectProperty") {
      continue;
    }
    const key = member.key;
    const keyName = key.type === "Identifier" ? key.name : key.type === "StringLiteral" ? key.value : undefined;
    if (keyName === HTML_PROPERTY) {
      return member;
    }
  }
  return undefined;
}

interface SinkSite {
  line: number;
  kind?: "dom" | "server";
  sink?: string;
}

/** Message / remediation per non-React sink kind. */
const SINK_COPY = {
  dom: {
    message: (sink: string): string =>
      `${sink} receives HTML built from data without sanitization (possible XSS) — a username like <img src=x onerror=...> runs as script.`,
    remediation:
      "Set text with textContent (or build elements with createElement), or sanitize the HTML with DOMPurify.sanitize(value) before assigning it.",
  },
  server: {
    message: (sink: string): string =>
      `HTML response built from request input without escaping (${sink}) — reflected XSS: <script> in a query parameter or form field runs in the visitor's browser.`,
    remediation:
      "Escape every interpolated value (e.g. escape-html, he.encode) or render through a template engine / JSX that escapes by default; never splice request input into HTML strings.",
  },
} as const;

export const xssDetector: Detector = {
  config: {
    name: "xss",
    category: "injection",
    // JSX lives in tsx/jsx; ts/js/mjs/cjs included for React.createElement and
    // transpiled forms that still carry the attribute.
    globs: ["**/*.{tsx,jsx,ts,js,mjs,cjs,mts,cts,vue,svelte}"],
    usesAst: true,
  },

  // Not declared `async`: synchronous AST work wrapped in Promise.resolve()
  // (entropy-detector.ts precedent; async is reserved for awaiting detectors).
  detect(ctx: DetectorContext): Promise<Finding[]> {
    try {
      // 1. FP ALLOWLIST — never self-flag test/fixture/mock/example sources.
      if (isTestOrFixturePath(ctx.filePath)) {
        return Promise.resolve([]);
      }

      // Vue / Svelte templates are not parsed — text-match their raw-HTML directives.
      if (/\.(?:vue|svelte)$/.test(ctx.filePath)) {
        return Promise.resolve(templateFindings(ctx));
      }

      // 2. AST GUARD — no AST (parse-failed file) means no finding, no throw.
      if (!isBabelFile(ctx.ast)) {
        return Promise.resolve([]);
      }
      const content = ctx.content;
      const tainted = collectRequestTaintedNames(ctx.ast, content);
      const isServerHtml = (node: Node | undefined): boolean =>
        node !== undefined && looksLikeHtml(node) && isRequestControlled(node, tainted, content, "value");

      // 3 + 4. Single walk: compute file-scoped sanitizer presence AND collect
      //         every non-literal dangerouslySetInnerHTML sink site.
      let fileHasSanitizer = false;
      const sinkSites: SinkSite[] = [];

      traverseAst(ctx.ast, {
        CallExpression(path) {
          const call = path.node;
          if (isSanitizerCall(call)) {
            fileHasSanitizer = true;
          }
          const callee = call.callee;
          if (callee.type !== "MemberExpression" || callee.property.type !== "Identifier") {
            return;
          }
          const method = callee.property.name;
          const receiver = content.slice(callee.object.start ?? 0, callee.object.end ?? 0);
          const line = call.loc?.start.line ?? 1;
          // DOM: el.insertAdjacentHTML(pos, html) / document.write(html)
          const domValue =
            method === "insertAdjacentHTML" ? call.arguments.at(1) : (method === "write" || method === "writeln") && receiver === "document" ? call.arguments.at(0) : undefined;
          if (domValue !== undefined && domValue.type !== "SpreadElement" && isDataBuiltHtml(domValue)) {
            sinkSites.push({ line, kind: "dom", sink: method === "insertAdjacentHTML" ? "insertAdjacentHTML" : `document.${method}` });
            return;
          }
          // Server: res.send(`<h1>${req.query.name}</h1>`) / c.html(...)
          if (HTML_RESPONSE_METHODS.has(method) && HTML_RESPONSE_RECEIVER_RE.test(receiver) && isServerHtml(call.arguments.at(0))) {
            sinkSites.push({ line, kind: "server", sink: `${receiver}.${method}` });
          }
        },
        NewExpression(path) {
          // new Response(`<p>${q}</p>`, { headers: { "content-type": "text/html" } })
          const call = path.node;
          if (call.callee.type === "Identifier" && /^(?:Response|NextResponse)$/.test(call.callee.name) && isServerHtml(call.arguments.at(0))) {
            sinkSites.push({ line: call.loc?.start.line ?? 1, kind: "server", sink: `new ${call.callee.name}` });
          }
        },
        AssignmentExpression(path) {
          const { left, right } = path.node;
          if (left.type !== "MemberExpression" || left.property.type !== "Identifier") {
            return;
          }
          const line = path.node.loc?.start.line ?? 1;
          const property = left.property.name;
          // DOM: el.innerHTML = `<b>${user.name}</b>`
          if (property === "innerHTML" || property === "outerHTML") {
            // `+=` appends markup too, so any non-literal appended value counts.
            if (isDataBuiltHtml(right) || (path.node.operator === "+=" && right.type !== "StringLiteral")) {
              sinkSites.push({ line, kind: "dom", sink: property });
            }
            return;
          }
          // Koa: ctx.body = `<h1>${ctx.query.q}</h1>`
          if (property === "body" && content.slice(left.object.start ?? 0, left.object.end ?? 0) === "ctx" && isServerHtml(right)) {
            sinkSites.push({ line, kind: "server", sink: "ctx.body" });
          }
        },
        JSXAttribute(path) {
          const htmlProp = htmlPropertyOf(path.node);
          if (htmlProp === undefined) {
            return;
          }
          if (isLiteralHtmlProperty(htmlProp)) {
            // Literal __html is author-controlled — not an XSS sink.
            return;
          }
          sinkSites.push({ line: htmlPropertyLine(htmlProp, path.node) });
        },
      });

      // A same-file sanitizer is treated as covering the file's sinks
      //.
      if (fileHasSanitizer) {
        return Promise.resolve([]);
      }

      const findings: Finding[] = sinkSites.map((site) => ({
        ruleId: "INJECT-01",
        category: "injection",
        detectorName: "xss",
        file: ctx.filePath,
        line: site.line,
        severity: "HIGH",
        confidence: "MEDIUM",
        message:
          site.kind === undefined
            ? "dangerouslySetInnerHTML receives a non-literal value without sanitization (possible XSS)."
            : SINK_COPY[site.kind].message(site.sink ?? ""),
        remediation:
          site.kind === undefined
            ? "Sanitize the HTML with DOMPurify.sanitize(value) before passing it to dangerouslySetInnerHTML, or confirm the value is already sanitized in the caller and is never user-controlled."
            : SINK_COPY[site.kind].remediation,
        matchedText: site.sink ?? SINK_ATTRIBUTE,
      }));

      return Promise.resolve(findings);
    } catch {
      // No-throw contract (src/core/types.ts Detector.detect).
      return Promise.resolve([]);
    }
  },
};

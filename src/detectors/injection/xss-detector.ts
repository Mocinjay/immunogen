/**
 * xssDetector — CAT-6 INJECT-01 (dangerouslySetInnerHTML with a non-literal
 * value and no DOMPurify sanitizer in the same file) detector, AST-based.
 *
 * INJECT-01 (FEATURES.md CAT-6): the canonical React XSS sink is a
 * dangerouslySetInnerHTML attribute whose __html receives a VARIABLE (an
 * identifier, member access, call result, or a template literal carrying
 * expressions) when the file performs no DOMPurify.sanitize() anywhere. A
 * string literal in __html is author-controlled, not user-controlled, and is
 * not flagged. This needs AST analysis: a text regex cannot reliably tell a
 * literal __html from a variable one, nor see whether a sanitizer is present
 * elsewhere in the file.
 *
 * Decision flow inside detect() (cheap gates first):
 *   1. FP ALLOWLIST — test/fixture/mock/example paths return [] (PITFALLS.md
 *      Pitfall 1).
 *   2. AST GUARD — if (!isBabelFile(ctx.ast)) return [] (PITFALLS.md Pitfall 3:
 *      a parse-failed file has no AST; emit nothing, never throw).
 *   3. SANITIZER PASS — walk the File once to compute a file-scoped boolean:
 *      does it contain a DOMPurify.sanitize(...) member call, or a bare
 *      sanitize(...) call? If so the file is treated as sanitized and emits
 *      nothing (FEATURES.md: "no DOMPurify.sanitize in the same file").
 *   4. SINK PASS — find every dangerouslySetInnerHTML JSX attribute carrying a
 *      __html property; flag the ones whose __html value is non-literal.
 *
 * Confidence is MEDIUM, not HIGH, per FEATURES.md CAT-6 INJECT-01 (FP risk =
 * LOW-MEDIUM: sanitization may legitimately happen in a caller; the finding's
 * remediation says to verify it).
 *
 * AST-only (ENG-05): reads ctx.ast and walks nodes. Never imports a
 * process/exec primitive, never evaluates/requires/spawns scanned source.
 *
 * No-throw contract (src/core/types.ts Detector.detect): the whole body runs
 * inside a try/catch returning Promise.resolve([]) on any failure.
 */
import { isBabelFile, traverseAst } from "../ast/ast-utils.js";

import type { Detector, DetectorContext, Finding } from "../../core/types.js";
import type { CallExpression, JSXAttribute, ObjectProperty } from "@babel/types";

/** The React XSS-sink attribute name. */
const SINK_ATTRIBUTE = "dangerouslySetInnerHTML";

/** The HTML-payload property inside the sink's object literal. */
const HTML_PROPERTY = "__html";

/** Sanitizer method name (the `.sanitize` of `DOMPurify.sanitize`). */
const SANITIZE_METHOD = "sanitize";

/** Path segments that suppress every finding in this file (FP allowlist — PITFALLS.md Pitfall 1). */
const FP_ALLOWLIST_SEGMENTS = new Set(["__tests__", "fixtures", "mocks", "examples"]);

/**
 * True when `filePath` falls inside a test/fixture/mock/example directory, or
 * its basename marks it as a test/story file. Mirrors entropy-detector.ts's
 * `isAllowlistedPath` style.
 */
function isAllowlistedPath(filePath: string): boolean {
  const segments = filePath.split("/");
  if (segments.some((segment) => FP_ALLOWLIST_SEGMENTS.has(segment))) {
    return true;
  }
  const basename = segments.at(-1) ?? "";
  return basename.includes(".test.") || basename.includes(".stories.");
}

/**
 * True when `call` is a sanitizer call: either a member call whose method is
 * `sanitize` (matches DOMPurify.sanitize, purify.sanitize, etc. by terminal
 * method name — file-scoped presence is sufficient per FEATURES.md), or a
 * bare `sanitize(...)` call (covers an imported `{ sanitize }`).
 */
function isSanitizerCall(call: CallExpression): boolean {
  const callee = call.callee;
  if (callee.type === "MemberExpression" && callee.property.type === "Identifier") {
    return callee.property.name === SANITIZE_METHOD;
  }
  if (callee.type === "Identifier") {
    return callee.name === SANITIZE_METHOD;
  }
  return false;
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
}

export const xssDetector: Detector = {
  config: {
    name: "xss",
    category: "injection",
    // JSX lives in tsx/jsx; ts/js/mjs/cjs included for React.createElement and
    // transpiled forms that still carry the attribute.
    globs: ["**/*.{tsx,jsx,ts,js,mjs,cjs}"],
  },

  // Not declared `async`: synchronous AST work wrapped in Promise.resolve()
  // (entropy-detector.ts precedent; async is reserved for awaiting detectors).
  detect(ctx: DetectorContext): Promise<Finding[]> {
    try {
      // 1. FP ALLOWLIST — never self-flag test/fixture/mock/example sources.
      if (isAllowlistedPath(ctx.filePath)) {
        return Promise.resolve([]);
      }

      // 2. AST GUARD — no AST (parse-failed file) means no finding, no throw.
      if (!isBabelFile(ctx.ast)) {
        return Promise.resolve([]);
      }

      // 3 + 4. Single walk: compute file-scoped sanitizer presence AND collect
      //         every non-literal dangerouslySetInnerHTML sink site.
      let fileHasSanitizer = false;
      const sinkSites: SinkSite[] = [];

      traverseAst(ctx.ast, {
        CallExpression(path) {
          if (isSanitizerCall(path.node)) {
            fileHasSanitizer = true;
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
      // (FEATURES.md "no DOMPurify.sanitize in the same file").
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
        message: "dangerouslySetInnerHTML receives a non-literal value without sanitization (possible XSS).",
        remediation:
          "Sanitize the HTML with DOMPurify.sanitize(value) before passing it to dangerouslySetInnerHTML, or confirm the value is already sanitized in the caller and is never user-controlled.",
        matchedText: SINK_ATTRIBUTE,
      }));

      return Promise.resolve(findings);
    } catch {
      // No-throw contract (src/core/types.ts Detector.detect).
      return Promise.resolve([]);
    }
  },
};

/**
 * insecureRandomDetector — AUTH-11: login codes, reset tokens, and other
 * secrets generated with `Math.random()`.
 *
 * `Math.random()` is a fast, non-cryptographic PRNG: V8's xorshift128+
 * state can be recovered from a handful of outputs, after which every
 * future "random" one-time code, password-reset token, or invite link is
 * predictable. AI-generated auth code reaches for it constantly
 * (`Math.floor(100000 + Math.random() * 900000)`), usually alongside a
 * verify endpoint with no attempt limit (RATE-01) — together they make
 * "guess the login code" trivial.
 *
 * A `Math.random()` call is reported when the value it feeds is named like
 * a secret: the nearest enclosing variable, assignment target, object key,
 * or function name matches otp / code / pin / token / secret / password /
 * nonce / salt / verification / reset / invite / magic / api key / session.
 * Names that are codes but not secrets (`colorCode`, `zipCode`,
 * `statusCode`, `keyCode`, ...) and seed / script / story files are
 * skipped.
 *
 * MEDIUM/MEDIUM. AST-only (ENG-05); no-throw contract.
 */
import { isBabelFile, traverseAst } from "../ast/ast-utils.js";
import { isTestOrFixturePath } from "../shared/test-paths.js";

import type { NodePath } from "../ast/ast-utils.js";
import type { Detector, DetectorContext, Finding } from "../../core/types.js";
import type { CallExpression, Node } from "@babel/types";

/** Names of values that must be unguessable. */
const SECRET_NAME_RE =
  /otp|passcode|(?:^|_)pin(?:code|_code|Number)?$|^pin(?:Code|Number)?$|token|secret|password|passwd|nonce|salt$|^salt|verif|invite|magic_?link|api_?key|session_?id|2fa|mfa|code$|^code$/i;

/** "Code" names that are not secrets. */
const NON_SECRET_CODE_RE = /(?:color|colour|zip|postal|country|currency|error|status|hex|area|language|lang|locale|font|key|char|exit|http|response|qr|bar|short|room|product|sku|class|discount|coupon|promo|referral|item|order|tracking)_?code/i;

/** Directories / files of throwaway or demo code. */
const NON_PRODUCTION_PATH_RE = /(?:^|\/)(?:scripts?|seeds?|seeders|storybook|stories|demo|demos|playground|e2e|cypress|playwright)\//i;

/** True when `call` is `Math.random()`. */
function isMathRandom(call: CallExpression): boolean {
  const callee = call.callee;
  return (
    callee.type === "MemberExpression" &&
    callee.object.type === "Identifier" &&
    callee.object.name === "Math" &&
    callee.property.type === "Identifier" &&
    callee.property.name === "random"
  );
}

/** Name text of a pattern / key / member target, when it has one. */
function nameOf(node: Node | null | undefined, content: string): string | undefined {
  if (node === null || node === undefined) {
    return undefined;
  }
  if (node.type === "Identifier") {
    return node.name;
  }
  if (node.type === "StringLiteral") {
    return node.value;
  }
  if (node.type === "MemberExpression" && !node.computed && node.property.type === "Identifier") {
    return node.property.name;
  }
  return content.slice(node.start ?? 0, node.end ?? 0) || undefined;
}

/** The name of the value a `Math.random()` call feeds: nearest declarator, assignment, object key, or enclosing function. */
function consumerName(path: NodePath<CallExpression>, content: string): string | undefined {
  let current: NodePath | null = path.parentPath;
  while (current !== null) {
    const node = current.node;
    switch (node.type) {
      case "VariableDeclarator":
        return nameOf(node.id, content);
      case "AssignmentExpression":
        return nameOf(node.left, content);
      case "ObjectProperty":
        return nameOf(node.key, content);
      case "ClassProperty":
        return nameOf(node.key, content);
      case "ReturnStatement":
      case "ArrowFunctionExpression": {
        // `function generateOtp() { return ... }` / `const makeCode = () => ...`
        const fn = node.type === "ArrowFunctionExpression" ? current : current.getFunctionParent();
        if (fn === null) {
          return undefined;
        }
        const fnNode = fn.node;
        if ((fnNode.type === "FunctionDeclaration" || fnNode.type === "FunctionExpression") && fnNode.id) {
          return fnNode.id.name;
        }
        if (fnNode.type === "ClassMethod" || fnNode.type === "ObjectMethod") {
          return nameOf(fnNode.key, content);
        }
        const parent = fn.parentPath?.node;
        return parent?.type === "VariableDeclarator" ? nameOf(parent.id, content) : undefined;
      }
      case "FunctionDeclaration":
      case "FunctionExpression":
      case "ClassMethod":
      case "ObjectMethod":
      case "Program":
        return undefined;
      default:
        current = current.parentPath;
    }
  }
  return undefined;
}

export const insecureRandomDetector: Detector = {
  config: {
    name: "insecure-random",
    category: "auth",
    globs: ["**/*.{ts,tsx,js,jsx,mjs,cjs,mts,cts}"],
    usesAst: true,
  },

  detect(ctx: DetectorContext): Promise<Finding[]> {
    try {
      if (
        isTestOrFixturePath(ctx.filePath) ||
        NON_PRODUCTION_PATH_RE.test(ctx.filePath) ||
        /seed/i.test(ctx.filePath.split("/").at(-1) ?? "") ||
        !ctx.content.includes("Math.random") ||
        !isBabelFile(ctx.ast)
      ) {
        return Promise.resolve([]);
      }
      const findings: Finding[] = [];
      const seenLines = new Set<number>();
      traverseAst(ctx.ast, {
        CallExpression(path) {
          if (!isMathRandom(path.node)) {
            return;
          }
          const name = consumerName(path, ctx.content);
          const line = path.node.loc?.start.line ?? 1;
          if (name === undefined || !SECRET_NAME_RE.test(name) || NON_SECRET_CODE_RE.test(name) || seenLines.has(line)) {
            return;
          }
          seenLines.add(line);
          findings.push({
            ruleId: "AUTH-11",
            category: "auth",
            detectorName: "insecure-random",
            file: ctx.filePath,
            line,
            severity: "MEDIUM",
            confidence: "MEDIUM",
            message: `${name} is generated with Math.random(), which is not cryptographically secure — its output can be predicted, so login codes, reset tokens, and invite links built on it can be guessed.`,
            remediation:
              'Use crypto.randomInt(100000, 1000000) for numeric codes and crypto.randomBytes(32).toString("hex") (or crypto.getRandomValues in the browser) for tokens; store only a hash, expire codes within minutes, and cap verification attempts.',
            matchedText: name,
          });
        },
      });
      return Promise.resolve(findings);
    } catch {
      return Promise.resolve([]);
    }
  },
};

/**
 * massAssignmentDetector — AUTH-10: mass assignment / privilege fields set
 * from the request. "Make myself admin at signup": a sign-up or profile
 * update that writes the request body straight into the user record lets a
 * client add `"role": "admin"` (or `isAdmin`, `credits`, `plan`) to the JSON
 * and have it saved.
 *
 * Two shapes, both in server entry files (JS/TS, AST):
 *   1. Wholesale body: a database write whose payload IS the request body —
 *      `prisma.user.create({ data: body })`, `{ data: { ...body } }`,
 *      `User.create(req.body)`, `new User(req.body)`,
 *      `Model.findByIdAndUpdate(id, req.body)`, `db.insert(users).values(body)`,
 *      `supabase.from("profiles").update(body)`, `Object.assign(user, req.body)`,
 *      or a Server Action's object argument passed through as `data`
 *      (TypeScript types are not enforced at runtime). Destructuring a few
 *      fields out (`const { password, ...rest } = body`) still leaves
 *      `rest` wholesale; parsing with a schema (`schema.parse(body)`) does not.
 *   2. Privilege field from the request: `role: body.role`,
 *      `isAdmin: req.body.isAdmin ?? false`, `plan: input.plan`, ... inside a
 *      write payload, including Supabase `auth.signUp({ options: { data } })`
 *      user metadata.
 * Admin endpoints (a role check in the file) manage other users' roles by
 * design and are skipped.
 *
 * Severity: a privilege field is HIGH/MEDIUM; a wholesale write is
 * HIGH/MEDIUM into a user / profile / account record (or in a sign-up
 * route), MEDIUM/MEDIUM into anything else (where it can still set
 * `status`, `total`, `ownerId`, ...).
 *
 * AST-only (ENG-05): never evaluates scanned source.
 * No-throw contract: returns `[]` on any failure.
 */
import { isBabelFile, traverseAst } from "../ast/ast-utils.js";
import { accessPath, collectRequestTaintedNames, isRequestControlled } from "../injection/request-input.js";
import { isTestOrFixturePath } from "../shared/test-paths.js";
import { isServerEntryFile } from "../shared/server-entry.js";
import { FILTER_THEN_UPDATE, isDbReceiver, receiverText, WRITE_METHODS } from "../shared/db-writes.js";
import { ROLE_GUARD_RE } from "./auth-evidence.js";

import type { Detector, DetectorContext, Finding } from "../../core/types.js";
import type { CallExpression, File, NewExpression, Node } from "@babel/types";

/** Record keys that grant privilege, entitlement, or trust. */
const PRIVILEGE_KEYS = new Set([
  "role",
  "roles",
  "isAdmin",
  "is_admin",
  "admin",
  "isSuperuser",
  "is_superuser",
  "isStaff",
  "is_staff",
  "permissions",
  "scopes",
  "accessLevel",
  "access_level",
  "userType",
  "user_type",
  "accountType",
  "account_type",
  "plan",
  "tier",
  "subscriptionStatus",
  "subscription_status",
  "isPro",
  "is_pro",
  "isPremium",
  "is_premium",
  "credits",
  "balance",
  "isVerified",
  "is_verified",
  "verified",
  "emailVerified",
  "email_verified",
  "approved",
  "isApproved",
  "is_approved",
]);

/** Models / tables / routes that hold user identity and privilege. */
const USER_RECORD_RE = /user|profile|account|member|customer|admin|signup|sign-up|sign_up|register/i;

/** Text of a node. */
function sourceOf(content: string, node: Node): string {
  return content.slice(node.start ?? 0, node.end ?? 0);
}

/** The text name of a property key. */
function keyName(node: Node): string | undefined {
  if (node.type === "Identifier") {
    return node.name;
  }
  return node.type === "StringLiteral" ? node.value : undefined;
}

/** Unwraps `await`, TS assertions, and parentheses. */
function unwrap(node: Node): Node {
  let current = node;
  for (;;) {
    if (current.type === "AwaitExpression") {
      current = current.argument;
    } else if (
      current.type === "TSAsExpression" ||
      current.type === "TSSatisfiesExpression" ||
      current.type === "TSNonNullExpression" ||
      current.type === "ParenthesizedExpression"
    ) {
      current = current.expression;
    } else {
      return current;
    }
  }
}

/** Access paths that are the whole request body (not one field of it). */
const WHOLE_BODY_PATH_RE = /^(?:req|request|ctx\.request|ctx)\.body$|^(?:req|request|c\.req)\.(?:json|parseBody)\(\)$|^(?:req|request)\.query$/;

/** True when `node` is the whole request body, a wholesale-bound name, or an object spreading one. */
function isWholesale(node: Node | null | undefined, wholesale: ReadonlySet<string>): boolean {
  if (node === null || node === undefined) {
    return false;
  }
  const inner = unwrap(node);
  if (inner.type === "Identifier") {
    return wholesale.has(inner.name);
  }
  if (WHOLE_BODY_PATH_RE.test(accessPath(inner) ?? "")) {
    return true;
  }
  if (inner.type === "ObjectExpression") {
    return inner.properties.some((property) => property.type === "SpreadElement" && isWholesale(property.argument, wholesale));
  }
  if (inner.type === "CallExpression" && inner.callee.type === "MemberExpression") {
    const calleePath = accessPath(inner.callee);
    // Object.fromEntries(formData) / Object.fromEntries(await req.formData()) / Object.assign({}, body)
    if (calleePath === "Object.fromEntries") {
      const argument = inner.arguments.at(0);
      const argumentText = argument === undefined ? "" : (accessPath(unwrap(argument)) ?? "");
      return /formData/i.test(argumentText) || isWholesale(argument, wholesale);
    }
    if (calleePath === "Object.assign") {
      return inner.arguments.some((argument) => isWholesale(argument, wholesale));
    }
  }
  return false;
}

/**
 * Names bound to the whole request body: `const body = await req.json()`,
 * `const data = req.body`, `const { password, ...rest } = body`, and the
 * object parameters of exported Server Actions (client-supplied at runtime).
 */
function collectWholesaleNames(ast: File, isServerAction: boolean): Set<string> {
  const wholesale = new Set<string>();
  const bindings: Array<{ name: string; init: Node; rest: boolean }> = [];
  traverseAst(ast, {
    VariableDeclarator(path) {
      const { id, init } = path.node;
      if (init === null || init === undefined) {
        return;
      }
      if (id.type === "Identifier") {
        bindings.push({ name: id.name, init, rest: false });
      } else if (id.type === "ObjectPattern") {
        for (const property of id.properties) {
          if (property.type === "RestElement" && property.argument.type === "Identifier") {
            bindings.push({ name: property.argument.name, init, rest: true });
          }
        }
      }
    },
    ExportNamedDeclaration(path) {
      const declaration = path.node.declaration;
      if (!isServerAction || declaration?.type !== "FunctionDeclaration") {
        return;
      }
      for (const param of declaration.params) {
        // A FormData parameter is handled via Object.fromEntries(formData); primitives (ids) are not payloads.
        const annotation = param.type === "Identifier" ? param.typeAnnotation : undefined;
        const typeText = annotation?.type === "TSTypeAnnotation" ? annotation.typeAnnotation.type : undefined;
        if (param.type === "Identifier" && typeText !== "TSStringKeyword" && typeText !== "TSNumberKeyword" && typeText !== "TSBooleanKeyword") {
          if (!/FormData/.test(JSON.stringify(annotation ?? {}))) {
            wholesale.add(param.name);
          }
        }
      }
    },
  });
  let changed = true;
  while (changed) {
    changed = false;
    for (const binding of bindings) {
      if (!wholesale.has(binding.name) && isWholesale(binding.init, wholesale)) {
        wholesale.add(binding.name);
        changed = true;
      }
    }
  }
  return wholesale;
}

/** The write payload(s) of `call` — the values a client could smuggle fields into. */
function writePayloads(call: CallExpression, content: string): Node[] {
  const callee = call.callee;
  if (callee.type !== "MemberExpression" || callee.property.type !== "Identifier") {
    return [];
  }
  const method = callee.property.name;
  if (!WRITE_METHODS.has(method) || !isDbReceiver(receiverText(call, content))) {
    return [];
  }
  if (method === "set" && call.arguments.length !== 1) {
    return [];
  }
  const first = call.arguments.at(0);
  if (first?.type === "ObjectExpression") {
    const optionKeys = ["data", "create", "update"];
    const options = first.properties.filter(
      (property): property is typeof property & { type: "ObjectProperty" } =>
        property.type === "ObjectProperty" && optionKeys.includes(keyName(property.key) ?? ""),
    );
    if (options.length > 0) {
      return options.map((property) => property.value);
    }
  }
  if (FILTER_THEN_UPDATE.has(method)) {
    const second = call.arguments.at(1);
    return second === undefined ? [] : [second];
  }
  return first === undefined ? [] : [first];
}

/** Privilege keys set from request data anywhere in a payload object (one level of nesting covers `options.data`). */
function privilegeKeysFromRequest(payload: Node, isTainted: (node: Node) => boolean, depth = 0): string[] {
  const inner = unwrap(payload);
  if (inner.type !== "ObjectExpression" || depth > 2) {
    return [];
  }
  const keys: string[] = [];
  for (const property of inner.properties) {
    if (property.type !== "ObjectProperty") {
      continue;
    }
    const key = keyName(property.key) ?? "";
    if (PRIVILEGE_KEYS.has(key) && isTainted(property.value)) {
      keys.push(key);
    } else {
      keys.push(...privilegeKeysFromRequest(property.value, isTainted, depth + 1));
    }
  }
  return keys;
}

/** Display name of the written record: the Prisma model, Mongoose model, Supabase table, or Drizzle table. */
function recordName(call: CallExpression | NewExpression, content: string): string {
  if (call.type === "NewExpression") {
    return call.callee.type === "Identifier" ? call.callee.name : "record";
  }
  const receiver = receiverText(call, content);
  const table = receiver.match(/from\(\s*["'`]([\w-]+)["'`]\s*\)|(?:insert|update)\(\s*(\w+)\s*\)/);
  if (table !== null) {
    return table[1] ?? table[2] ?? "record";
  }
  return receiver.split(".").at(-1) ?? "record";
}

export const massAssignmentDetector: Detector = {
  config: {
    name: "mass-assignment",
    category: "auth",
    globs: ["**/*.{ts,tsx,js,jsx,mjs,cjs,mts,cts}"],
    usesAst: true,
  },

  detect(ctx: DetectorContext): Promise<Finding[]> {
    try {
      if (
        isTestOrFixturePath(ctx.filePath) ||
        !isBabelFile(ctx.ast) ||
        !isServerEntryFile(ctx.filePath, ctx.content) ||
        ROLE_GUARD_RE.test(ctx.content)
      ) {
        return Promise.resolve([]);
      }
      const ast = ctx.ast;
      const isServerAction = /^\s*["']use server["']/m.test(ctx.content);
      const wholesale = collectWholesaleNames(ast, isServerAction);
      const tainted = collectRequestTaintedNames(ast, ctx.content, { use: "data", seeds: wholesale });
      const isTainted = (node: Node): boolean => isRequestControlled(node, tainted, ctx.content, "data");
      const userRoute = USER_RECORD_RE.test(ctx.filePath);

      const findings: Finding[] = [];
      const report = (node: Node, record: string, message: string, severity: "HIGH" | "MEDIUM"): void => {
        findings.push({
          ruleId: "AUTH-10",
          category: "auth",
          detectorName: "mass-assignment",
          file: ctx.filePath,
          line: node.loc?.start.line ?? 1,
          severity,
          confidence: "MEDIUM",
          message,
          remediation:
            "Copy only the fields a user may set — e.g. data: { name: body.name, bio: body.bio }, or parse the body with a strict schema (z.object({ ... }).strict()) — and set role, plan, credits and verification flags only from server-side logic.",
          matchedText: record,
        });
      };
      const checkWrite = (call: CallExpression | NewExpression, payloads: Node[]): void => {
        const record = recordName(call, ctx.content);
        const privileged = payloads.flatMap((payload) => privilegeKeysFromRequest(payload, isTainted));
        if (privileged.length > 0) {
          report(
            call,
            record,
            `${privileged.join(", ")} is taken from the request when writing ${record} — anyone can make themselves an admin (or grant themselves a plan, credits, or a verified flag) by sending it.`,
            "HIGH",
          );
          return;
        }
        if (payloads.some((payload) => isWholesale(payload, wholesale))) {
          report(
            call,
            record,
            `The request body is written straight into ${record} (mass assignment) — a client that adds "role": "admin" (or isAdmin, credits, ownerId, status) to the JSON gets it saved.`,
            userRoute || USER_RECORD_RE.test(record) ? "HIGH" : "MEDIUM",
          );
        }
      };

      traverseAst(ast, {
        CallExpression(path) {
          const call = path.node;
          if (call.callee.type === "MemberExpression" && accessPath(call.callee) === "Object.assign") {
            // Object.assign(user, req.body) — mutating a loaded record with the whole body.
            const [target, ...sources] = call.arguments;
            if (target !== undefined && target.type !== "ObjectExpression" && sources.some((source) => isWholesale(source, wholesale))) {
              report(call, sourceOf(ctx.content, target), `The request body is merged into ${sourceOf(ctx.content, target)} with Object.assign (mass assignment) — a client can overwrite any field, including role or ownership.`, "HIGH");
            }
            return;
          }
          const payloads = writePayloads(call, ctx.content);
          if (payloads.length > 0) {
            checkWrite(call, payloads);
          }
        },
        NewExpression(path) {
          // Mongoose `new User(req.body)`.
          const call = path.node;
          if (call.callee.type === "Identifier" && /^[A-Z]/.test(call.callee.name) && !["URL", "URLSearchParams", "Response", "Request", "Error", "Date", "Map", "Set", "FormData", "Headers"].includes(call.callee.name)) {
            const first = call.arguments.at(0);
            if (first !== undefined) {
              checkWrite(call, [first]);
            }
          }
        },
      });
      return Promise.resolve(findings);
    } catch {
      return Promise.resolve([]);
    }
  },
};

/**
 * idorDetector — AUTH-08: insecure direct object reference. A signed-in
 * handler loads, updates, or deletes a record by an id taken straight from
 * the request (`/account?id=1043`, `/api/orders/[id]`) without scoping the
 * query to the caller — so changing the id in the URL returns (or edits)
 * another user's data. Authentication alone does not stop this: the caller
 * IS logged in, just not as the record's owner.
 *
 * Recognized lookups (JS/TS, AST):
 *   - Prisma / Sequelize `where` filters: `prisma.order.findUnique({ where: { id } })`,
 *     `findFirst`, `update`, `delete`, `upsert`, `Order.findOne({ where })`,
 *     `Order.destroy({ where })`, `Order.update(values, { where })`.
 *   - Mongoose: `Order.findById(id)`, `findByIdAndUpdate/Delete/Remove`,
 *     `findOne({ _id: id })`, `updateOne`, `deleteOne`, `findOneAndUpdate`, ...
 *   - Sequelize `findByPk(id)`.
 *   - Drizzle: `.where(eq(orders.id, id))` and the query API's
 *     `findFirst({ where: eq(orders.id, id) })`.
 * Supabase and Firebase lookups are left to the RLS / rules detectors: their
 * row-level policies are where ownership is enforced.
 *
 * A lookup is scoped (no finding) when its filter also matches an owner
 * column (`userId`, `ownerId`, `authorId`, `tenantId`, `user: { ... }`,
 * an `AND`/`OR` group), or when the file compares the fetched record's
 * owner to the caller (`order.userId !== session.user.id`) or calls an
 * object-level authorization helper. Admin handlers (a role check in the
 * file) may legitimately reach any record and are skipped.
 *
 * The rule only runs in server entry files that authenticate the caller
 * (an auth helper call or `req.user`): an unauthenticated handler is
 * AUTH-01's finding, and webhook / cron / API-key handlers are
 * server-to-server.
 *
 * Severity: an update/delete is HIGH/MEDIUM; a read of a record that
 * typically holds personal data (orders, invoices, accounts, messages,
 * documents, ...) is HIGH/LOW. Reads of other models (a product catalog,
 * public posts) are not reported.
 *
 * AST-only (ENG-05): reads `ctx.ast`; never evaluates scanned source.
 * No-throw contract: the whole body runs inside a try/catch returning `[]`.
 */
import { isBabelFile, traverseAst } from "../ast/ast-utils.js";
import { collectRequestTaintedNames, isRequestControlled } from "../injection/request-input.js";
import { isTestOrFixturePath } from "../shared/test-paths.js";
import { isClientModule, isServerEntryFile } from "../shared/server-entry.js";
import {
  isAuthCall,
  NON_SESSION_AUTH_RE,
  OWNERSHIP_CHECK_RE,
  OWNERSHIP_KEY_RE,
  ROLE_CHECK_RE,
  USER_IDENTITY_READ_RE,
} from "./auth-evidence.js";

import type { Detector, DetectorContext, Finding } from "../../core/types.js";
import type { CallExpression, Expression, File, Node, ObjectExpression } from "@babel/types";

/** Methods taking a single id argument. */
const ID_ARGUMENT_READS = new Set(["findById", "findByPk"]);
const ID_ARGUMENT_WRITES = new Set(["findByIdAndUpdate", "findByIdAndDelete", "findByIdAndRemove"]);

/** Methods taking a filter object (Prisma/Sequelize `{ where }`, or a Mongoose filter). */
const FILTER_READS = new Set(["findUnique", "findUniqueOrThrow", "findFirst", "findFirstOrThrow", "findOne"]);
const FILTER_WRITES = new Set([
  "update",
  "delete",
  "upsert",
  "destroy",
  "deleteOne",
  "updateOne",
  "findOneAndUpdate",
  "findOneAndDelete",
  "findOneAndRemove",
  "findOneAndReplace",
]);

/** Methods whose filter is a bare Mongoose filter object (no `where` key). */
const MONGOOSE_FILTER_METHODS = new Set([
  "findOne",
  "deleteOne",
  "updateOne",
  "findOneAndUpdate",
  "findOneAndDelete",
  "findOneAndRemove",
  "findOneAndReplace",
]);

/** Filter keys that identify one record. */
const ID_KEY_RE = /^(?:id|_id|uuid|slug|[a-z][A-Za-z]*Id|[a-z]+_id)$/;

/** Logical filter groups whose contents this rule does not try to reason about. */
const LOGICAL_KEYS = new Set(["AND", "OR", "NOT", "$and", "$or", "$nor"]);

/** Models that typically hold one user's personal data (reads of anything else are not reported). */
const PERSONAL_MODEL_RE =
  /order|invoice|payment|transaction|account|user|profile|customer|member|message|conversation|chat|thread|inbox|document|file|upload|attachment|note|address|card|wallet|subscription|billing|booking|reservation|appointment|ticket|report|application|submission|receipt|statement|patient|medical|record|journal|contact|cart|checkout|secret|credential|session|project|workspace/i;

/** Route handler names whose second parameter carries the dynamic route segments. */
const HTTP_METHOD_NAMES = new Set(["GET", "POST", "PUT", "PATCH", "DELETE", "loader", "action", "load"]);

interface Lookup {
  model: string;
  write: boolean;
  line: number;
}

/** The text name of a property key (`id`, `"user_id"`). */
function keyName(node: Node): string | undefined {
  if (node.type === "Identifier") {
    return node.name;
  }
  return node.type === "StringLiteral" ? node.value : undefined;
}

/** The value of `key` in an object literal. */
function propertyValue(object: ObjectExpression, key: string): Node | undefined {
  for (const property of object.properties) {
    if (property.type === "ObjectProperty" && keyName(property.key) === key) {
      return property.value;
    }
  }
  return undefined;
}

/**
 * Names that hold dynamic route segments: `params` itself, and the second
 * parameter of exported route handlers (`GET(req, context)` -> `context`),
 * or the destructured names of a `({ params })` argument.
 */
function routeParamSeeds(ast: File): string[] {
  const seeds = new Set(["params", "searchParams"]);
  const addPattern = (param: Node | undefined): void => {
    if (param?.type === "Identifier") {
      seeds.add(param.name);
    } else if (param?.type === "ObjectPattern") {
      for (const property of param.properties) {
        const key = property.type === "ObjectProperty" ? keyName(property.key) : undefined;
        if (property.type === "ObjectProperty" && property.value.type === "Identifier" && (key === "params" || key === "searchParams")) {
          seeds.add(property.value.name);
        }
      }
    }
  };
  traverseAst(ast, {
    ExportDefaultDeclaration(path) {
      // A Next.js page / layout: `export default async function Page({ params, searchParams })`.
      const declaration = path.node.declaration;
      if (
        declaration.type === "FunctionDeclaration" ||
        declaration.type === "ArrowFunctionExpression" ||
        declaration.type === "FunctionExpression"
      ) {
        addPattern(declaration.params.at(0));
      }
    },
    ExportNamedDeclaration(path) {
      const declaration = path.node.declaration;
      if (declaration?.type === "FunctionDeclaration" && HTTP_METHOD_NAMES.has(declaration.id?.name ?? "")) {
        addPattern(declaration.params.at(declaration.params.length > 1 ? 1 : 0));
      }
      if (declaration?.type === "VariableDeclaration") {
        for (const declarator of declaration.declarations) {
          const init = declarator.init;
          if (
            declarator.id.type === "Identifier" &&
            HTTP_METHOD_NAMES.has(declarator.id.name) &&
            (init?.type === "ArrowFunctionExpression" || init?.type === "FunctionExpression")
          ) {
            addPattern(init.params.at(init.params.length > 1 ? 1 : 0));
          }
        }
      }
    },
  });
  return [...seeds];
}

/** Receiver model name of a data-access call: `order` for `prisma.order.findUnique`, `Order` for `Order.findById`. */
function modelName(call: CallExpression): string | undefined {
  const callee = call.callee;
  if (callee.type !== "MemberExpression") {
    return undefined;
  }
  const receiver = callee.object;
  if (receiver.type === "Identifier") {
    return receiver.name;
  }
  if (receiver.type === "MemberExpression" && receiver.property.type === "Identifier") {
    return receiver.property.name;
  }
  return undefined;
}

/**
 * For a Drizzle condition (`eq(orders.id, id)`, `and(eq(...), eq(...))`,
 * or the query API's `(o, { eq }) => eq(o.id, id)`), the table name and
 * whether the condition matches an id from the request without an owner
 * column. Undefined when the condition is not one of those shapes.
 */
function drizzleCondition(
  condition: Node | undefined,
  isTainted: (node: Node | undefined) => boolean,
): { table: string; unscoped: boolean } | undefined {
  let node = condition;
  if (node?.type === "ArrowFunctionExpression" && node.body.type !== "BlockStatement") {
    node = node.body;
  }
  if (node?.type !== "CallExpression" || node.callee.type !== "Identifier") {
    return undefined;
  }
  const comparisons = node.callee.name === "and" ? node.arguments : node.callee.name === "eq" ? [node] : [];
  let table: string | undefined;
  let idFromRequest = false;
  let ownerScoped = false;
  for (const comparison of comparisons) {
    if (comparison.type !== "CallExpression" || comparison.callee.type !== "Identifier" || comparison.callee.name !== "eq") {
      continue;
    }
    const column = comparison.arguments.at(0);
    if (column?.type !== "MemberExpression" || column.property.type !== "Identifier") {
      continue;
    }
    const columnName = column.property.name;
    const value = comparison.arguments.at(1);
    if (OWNERSHIP_KEY_RE.test(columnName)) {
      ownerScoped = true;
    } else if (ID_KEY_RE.test(columnName) && isTainted(value)) {
      idFromRequest = true;
      table = column.object.type === "Identifier" ? column.object.name : table;
    } else if (ID_KEY_RE.test(columnName) && value !== undefined && !isLiteralValue(value)) {
      ownerScoped = true;
    }
  }
  return table === undefined ? undefined : { table, unscoped: idFromRequest && !ownerScoped };
}

/** True when a Drizzle builder chain under `node` contains an `update(...)` / `delete(...)` call. */
function chainWrites(node: Node): boolean {
  let current: Node = node;
  while (current.type === "CallExpression" || current.type === "MemberExpression") {
    if (
      current.type === "CallExpression" &&
      current.callee.type === "MemberExpression" &&
      current.callee.property.type === "Identifier" &&
      (current.callee.property.name === "update" || current.callee.property.name === "delete")
    ) {
      return true;
    }
    current = current.type === "CallExpression" ? current.callee : current.object;
  }
  return false;
}

/** True for a literal filter value (`status: "active"`), which narrows a query but never scopes it to an owner. */
function isLiteralValue(node: Node): boolean {
  return ["StringLiteral", "NumericLiteral", "BooleanLiteral", "NullLiteral"].includes(node.type) || (node.type === "TemplateLiteral" && node.expressions.length === 0);
}

/**
 * True when an object filter matches an id from the request and nothing
 * that scopes it: no owner key, no logical group or spread, and no second
 * id key bound to a server-side value (`cartId: cart.id` — a parent the
 * handler already resolved for this user).
 */
function isUnscopedIdFilter(filter: ObjectExpression, isTainted: (node: Node | undefined) => boolean): boolean {
  let idFromRequest = false;
  for (const property of filter.properties) {
    if (property.type !== "ObjectProperty") {
      // A spread (`...ownerFilter`) may carry the owner scope.
      return false;
    }
    const key = keyName(property.key);
    if (key === undefined || LOGICAL_KEYS.has(key) || OWNERSHIP_KEY_RE.test(key)) {
      return false;
    }
    if (ID_KEY_RE.test(key)) {
      if (isTainted(property.value)) {
        idFromRequest = true;
      } else if (!isLiteralValue(property.value)) {
        return false;
      }
    }
  }
  return idFromRequest;
}

/** The unscoped by-id lookup `call` performs, if any. */
function unscopedLookup(call: CallExpression, isTainted: (node: Node | undefined) => boolean): Lookup | undefined {
  const callee = call.callee;
  if (callee.type !== "MemberExpression" || callee.property.type !== "Identifier") {
    return undefined;
  }
  const method = callee.property.name;
  const line = call.loc?.start.line ?? 1;
  const first = call.arguments.at(0) as Expression | undefined;

  if (ID_ARGUMENT_READS.has(method) || ID_ARGUMENT_WRITES.has(method)) {
    const model = modelName(call);
    return model !== undefined && isTainted(first) ? { model, write: ID_ARGUMENT_WRITES.has(method), line } : undefined;
  }

  if (method === "where") {
    const condition = drizzleCondition(first, isTainted);
    return condition?.unscoped === true ? { model: condition.table, write: chainWrites(callee.object), line } : undefined;
  }

  if (!FILTER_READS.has(method) && !FILTER_WRITES.has(method)) {
    return undefined;
  }
  const model = modelName(call);
  if (model === undefined) {
    return undefined;
  }
  const write = FILTER_WRITES.has(method);
  // Sequelize `Model.update(values, { where })` carries the filter second.
  const options = [first, call.arguments.at(1)].find(
    (argument): argument is ObjectExpression => argument?.type === "ObjectExpression" && propertyValue(argument, "where") !== undefined,
  );
  const where = options === undefined ? undefined : propertyValue(options, "where");
  if (where?.type === "ObjectExpression") {
    return isUnscopedIdFilter(where, isTainted) ? { model, write, line } : undefined;
  }
  if (where !== undefined) {
    const condition = drizzleCondition(where, isTainted);
    return condition?.unscoped === true ? { model: condition.table, write, line } : undefined;
  }
  if (MONGOOSE_FILTER_METHODS.has(method) && first?.type === "ObjectExpression") {
    return isUnscopedIdFilter(first, isTainted) ? { model, write, line } : undefined;
  }
  return undefined;
}

export const idorDetector: Detector = {
  config: {
    name: "idor",
    category: "auth",
    globs: ["**/*.{ts,tsx,js,jsx,mjs,cjs,mts,cts}"],
    usesAst: true,
  },

  detect(ctx: DetectorContext): Promise<Finding[]> {
    try {
      if (
        isTestOrFixturePath(ctx.filePath) ||
        !isBabelFile(ctx.ast) ||
        isClientModule(ctx.content) ||
        !isServerEntryFile(ctx.filePath, ctx.content) ||
        NON_SESSION_AUTH_RE.test(ctx.content) ||
        ROLE_CHECK_RE.test(ctx.content) ||
        OWNERSHIP_CHECK_RE.test(ctx.content)
      ) {
        return Promise.resolve([]);
      }
      const ast = ctx.ast;

      let authenticated = USER_IDENTITY_READ_RE.test(ctx.content);
      traverseAst(ast, {
        CallExpression(path) {
          authenticated ||= isAuthCall(path.node);
        },
      });
      if (!authenticated) {
        return Promise.resolve([]);
      }

      const tainted = collectRequestTaintedNames(ast, ctx.content, { use: "data", seeds: routeParamSeeds(ast) });
      const isTainted = (node: Node | undefined): boolean => isRequestControlled(node, tainted, ctx.content, "data");

      const findings: Finding[] = [];
      traverseAst(ast, {
        CallExpression(path) {
          const lookup = unscopedLookup(path.node, isTainted);
          if (lookup === undefined || (!lookup.write && !PERSONAL_MODEL_RE.test(lookup.model))) {
            return;
          }
          findings.push({
            ruleId: "AUTH-08",
            category: "auth",
            detectorName: "idor",
            file: ctx.filePath,
            line: lookup.line,
            severity: "HIGH",
            confidence: lookup.write ? "MEDIUM" : "LOW",
            message: lookup.write
              ? `${lookup.model} record is updated or deleted by an id from the request without checking it belongs to the signed-in user (IDOR) — changing the id lets one user modify another user's data.`
              : `${lookup.model} record is fetched by an id from the request without checking it belongs to the signed-in user (IDOR) — changing the id in the URL returns someone else's data.`,
            remediation:
              "Scope the query to the caller — e.g. where: { id, userId: session.user.id } (findFirst), or load the record and return 404 unless record.userId === session.user.id. Never trust an id from the URL or body on its own.",
            matchedText: lookup.model,
          });
        },
      });
      return Promise.resolve(findings);
    } catch {
      return Promise.resolve([]);
    }
  },
};

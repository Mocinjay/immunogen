/**
 * db-writes — "is this call a database write, and what does it write?"
 * shared by the mass-assignment (AUTH-10) and commerce-logic (PAY-03..06)
 * rules. Recognizes ORM / query-builder write methods (Prisma, Drizzle,
 * Mongoose, Sequelize, Supabase, Firestore, Knex) by method name, and
 * rules out receivers whose `create` / `update` / `set` is something else
 * (a hash, an HTTP response, an SDK call, browser state).
 *
 * Text / AST only (ENG-05): never evaluates scanned source.
 */
import type { CallExpression } from "@babel/types";

/** Write methods whose payload is their first argument (or a Prisma-style `{ data }` option). */
export const WRITE_METHODS = new Set([
  "create",
  "createMany",
  "update",
  "updateMany",
  "upsert",
  "insert",
  "insertOne",
  "insertMany",
  "values",
  "set",
  "build",
  "bulkCreate",
  "signUp",
  "findByIdAndUpdate",
  "findOneAndUpdate",
  "updateOne",
  "replaceOne",
]);

/** Mongoose methods taking `(filter, update)`: the payload is the second argument. */
export const FILTER_THEN_UPDATE = new Set(["findByIdAndUpdate", "findOneAndUpdate", "updateOne", "replaceOne"]);

/** Receiver text naming an SDK, hash, or built-in whose `create` / `update` / `set` is not a database write. */
const NON_DB_RECEIVER_TEXT_RE =
  /\b(?:stripe|openai|anthropic|groq|mistral|gemini|genai|resend|sendgrid|mailgun|twilio|postmark|pusher|s3|redis|kv|axios|ky|got|logger|console|analytics|posthog|sentry|crypto|createHash|createHmac|createCipher\w*|Object|Reflect|JSON|Math)\b/;

/** Last receiver segment (call arguments stripped) that is not a database: hashes, HTTP responses, browser / client state. */
const NON_DB_RECEIVER_SEGMENT_RE = /^(?:hash|hmac|cipher|digest|res|response|reply|headers|cookies?|searchParams|url|params|cache|map|state|store|history|router|form|bucket|storage|ai)$/i;

/** True when a member call's receiver is a database / ORM object rather than an SDK, hash, or response. */
export function isDbReceiver(receiver: string): boolean {
  if (NON_DB_RECEIVER_TEXT_RE.test(receiver)) {
    return false;
  }
  let stripped = receiver;
  for (let previous = ""; previous !== stripped; ) {
    previous = stripped;
    stripped = stripped.replace(/\([^()]*\)/g, "");
  }
  const last = stripped.split(".").at(-1) ?? stripped;
  return !NON_DB_RECEIVER_SEGMENT_RE.test(last.trim());
}

/** The receiver text of a member call (`prisma.user`, `User`, `supabase.from("profiles")`). */
export function receiverText(call: CallExpression, content: string): string {
  return call.callee.type === "MemberExpression" ? content.slice(call.callee.object.start ?? 0, call.callee.object.end ?? 0) : "";
}

/** True when `call` is a database write (`prisma.order.create(...)`, `db.insert(t).values(...)`, `Order.updateOne(...)`). */
export function isDbWriteCall(call: CallExpression, content: string): boolean {
  const callee = call.callee;
  if (callee.type !== "MemberExpression" || callee.property.type !== "Identifier" || !WRITE_METHODS.has(callee.property.name)) {
    return false;
  }
  if (callee.property.name === "set" && call.arguments.length !== 1) {
    return false;
  }
  return isDbReceiver(receiverText(call, content));
}

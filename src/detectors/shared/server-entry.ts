/**
 * server-entry — "does this file handle HTTP requests on the server?"
 * shared by the business-logic rules (IDOR, mass assignment, payment
 * logic, uploads), which only matter where a request reaches the server.
 *
 * A file counts when it is a framework entry point (Next.js route handler,
 * Pages API route, Server Action module, SvelteKit `+server` / `+page.server`
 * module, Nuxt/Nitro `server/api` or `server/routes` file, Remix/React Router
 * route module exporting an `action`/`loader`), registers routes on a
 * server/router object (`app.post("/x", ...)`), or defines an Express-style
 * controller (`(req, res) => ...`).
 *
 * Next.js App Router server component pages (`page.tsx` without
 * `"use client"`) count too: they run on the server for every request,
 * with the URL's `params` and `searchParams`.
 *
 * Text-only (ENG-05): never evaluates scanned source.
 */

/** The shape of server entry point a file is, when it is one. */
export type ServerEntryKind =
  | "next-route"
  | "pages-api"
  | "server-action"
  | "server-page"
  | "framework-route"
  | "server-routes"
  | "controller";

/** Route registration on a server/router object (`app.post("/x", ...)`, `router.get('/a', h)`); `api.get(...)` is usually an HTTP client, so it is excluded. */
const ROUTE_REGISTRATION_RE =
  /\b(?:app|server|fastify|hono|router|routes|r|\w+Router|\w+Routes)\.(?:get|post|put|patch|delete|all|route)\(\s*["'`]\/[^"'`]*["'`]\s*,/;

/** An Express/Koa-style handler signature: `(req, res)` / `(req: Request, res: Response)` / `async (ctx) =>` with ctx.request. */
const CONTROLLER_SIGNATURE_RE = /\(\s*req\b[^,()]{0,60},\s*res\b|\bctx\.request\.body\b/;

/** Remix / React Router route module exports. */
const ROUTE_MODULE_EXPORT_RE = /export\s+(?:async\s+function|function|const)\s+(?:action|loader)\b/;

/** Which kind of server entry point `filePath` is, or undefined when it is not one. */
export function serverEntryKind(filePath: string, content: string): ServerEntryKind | undefined {
  const segments = filePath.split("/");
  const basename = segments.at(-1) ?? "";
  if (/^route\.(?:ts|tsx|js|jsx|mjs)$/.test(basename) && segments.includes("app")) {
    return "next-route";
  }
  if (/(?:^|\/)pages\/api\/.+\.(?:ts|tsx|js|jsx|mjs)$/.test(filePath)) {
    return "pages-api";
  }
  if (/^\s*["']use server["']/m.test(content)) {
    return "server-action";
  }
  if (/^page\.(?:ts|tsx|js|jsx)$/.test(basename) && segments.includes("app") && !isClientModule(content)) {
    // A Next.js server component page runs on every request with the URL's params and searchParams.
    return "server-page";
  }
  if (
    /^\+(?:server|page\.server|layout\.server)\.(?:ts|js)$/.test(basename) ||
    /(?:^|\/)server\/(?:api|routes)\//.test(filePath) ||
    (segments.includes("routes") && ROUTE_MODULE_EXPORT_RE.test(content))
  ) {
    return "framework-route";
  }
  if (ROUTE_REGISTRATION_RE.test(content)) {
    return "server-routes";
  }
  if (CONTROLLER_SIGNATURE_RE.test(content)) {
    return "controller";
  }
  return undefined;
}

/** True when `filePath` handles HTTP requests on the server (see `serverEntryKind`). */
export function isServerEntryFile(filePath: string, content: string): boolean {
  return serverEntryKind(filePath, content) !== undefined;
}

/** True for a client component / browser module (`"use client"`), where business rules cannot be enforced. */
export function isClientModule(content: string): boolean {
  return /^\s*["']use client["']/m.test(content);
}

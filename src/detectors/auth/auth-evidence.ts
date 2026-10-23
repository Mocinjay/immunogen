/**
 * auth-evidence — shared recognition of "this server code checks who is
 * calling" for the AUTH-01 detectors (Next.js entry points in
 * route-auth-detector.ts, Express/Fastify/Hono/Koa routes in
 * server-route-auth-detector.ts).
 *
 * Evidence comes in three shapes: a call to a recognized auth/session
 * helper (`isAuthCall`, AST-level), a non-session check matched as text
 * (`NON_SESSION_AUTH_RE`: webhook signatures, shared secrets, API-key
 * headers), and route paths that are public by their nature
 * (`PUBLIC_BY_NATURE_SEGMENTS`).
 *
 * AST-only / text-only (ENG-05): never evaluates scanned source.
 */
import type { CallExpression } from "@babel/types";

/** Bare-identifier auth/session helpers whose presence (called) is auth evidence. */
export const AUTH_CALL_IDENTIFIERS = new Set([
  "auth",
  "authenticate",
  "authorize",
  "currentUser",
  "getAuth",
  "getAuthSession",
  "getAuthUser",
  "getAuthenticatedUser",
  "getCurrentUser",
  "getKindeServerSession",
  "getLoggedInUser",
  "getServerAuthSession",
  "getServerSession",
  "getSession",
  "getToken",
  "getUserFromRequest",
  "getUserFromToken",
  "isAuthenticated",
  "jwtVerify",
  "validateRequest",
  "verifyIdToken",
  "verifyJwt",
  "verifyToken",
]);

/**
 * Project-specific auth helper names: `requireUser`, `requireAuth`,
 * `ensureAuthenticated`, `checkAdmin`, `verifySession`, `assertRole`,
 * `withAuth`, ... — a guard verb followed by an auth noun.
 */
export const AUTH_HELPER_NAME_RE = /^(?:require|ensure|check|verify|validate|assert|with|protect)\w*?(?:Auth|Authenticated|Session|User|Admin|Role|Permission|LoggedIn|SignedIn)s?$/;

/** Member-call auth helpers (`object.property(...)`) that are auth evidence. */
const AUTH_MEMBER_METHODS = new Set([
  "getUser",
  "getSession",
  "getClaims",
  "protect",
  "verifyIdToken",
  "verifySessionCookie",
  "getServerSession",
]);

/** Receivers whose `.verify(...)` is a token check (`jwt.verify`, `jsonwebtoken.verify`). */
const JWT_RECEIVERS = new Set(["jwt", "jsonwebtoken", "jose"]);

/**
 * Non-session auth evidence, matched as text: webhook signature verification
 * (Stripe `constructEvent`, svix/Clerk/Resend `Webhook(...).verify`, GitHub
 * `x-hub-signature`, constant-time HMAC comparison), a shared-secret cron
 * check (`CRON_SECRET`), or reading the Authorization / API-key header.
 */
export const NON_SESSION_AUTH_RE =
  /constructEvent|new\s+Webhook\s*\(|verifySignature|verifyWebhook|validateWebhook|timingSafeEqual|x-hub-signature|svix-signature|CRON_SECRET|headers\.get\(\s*['"`](?:authorization|x-api-key)['"`]\s*\)|headers\[\s*['"`](?:authorization|x-api-key)['"`]\s*\]|headers\.(?:authorization|\[?['"`]x-api-key)/i;

/**
 * Route-path segments that are public by their nature: health/uptime
 * probes, Open Graph / icon / sitemap / robots / manifest generators, and
 * the sign-in, sign-up, and OAuth-callback endpoints that by definition run
 * before a session exists.
 */
export const PUBLIC_BY_NATURE_SEGMENTS = new Set([
  "health",
  "healthz",
  "healthcheck",
  "ping",
  "og",
  "opengraph-image",
  "twitter-image",
  "icon",
  "apple-icon",
  "sitemap.xml",
  "robots.txt",
  "manifest.json",
  "manifest.webmanifest",
  "[...nextauth]",
  "[...all]",
  "login",
  "logout",
  "signin",
  "sign-in",
  "signup",
  "sign-up",
  "register",
  "callback",
  "oauth",
]);

/** True when `call` is a recognized auth helper call (bare identifier OR member method). */
export function isAuthCall(call: CallExpression): boolean {
  const callee = call.callee;
  if (callee.type === "Identifier") {
    return AUTH_CALL_IDENTIFIERS.has(callee.name) || AUTH_HELPER_NAME_RE.test(callee.name);
  }
  if (callee.type === "MemberExpression" && callee.property.type === "Identifier") {
    const method = callee.property.name;
    // Matches the `.auth.getUser()` / `.auth.getSession()` shape (e.g.
    // supabase.auth.getUser) by the terminal method name — file-scoped
    // presence is sufficient and lower-FP than pinning the receiver chain.
    if (AUTH_MEMBER_METHODS.has(method) || AUTH_HELPER_NAME_RE.test(method)) {
      return true;
    }
    return method === "verify" && callee.object.type === "Identifier" && JWT_RECEIVERS.has(callee.object.name);
  }
  return false;
}

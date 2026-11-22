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
 * the sign-in, sign-up, OAuth-callback, one-time-code, and password-reset
 * endpoints that by definition run before a session exists (RATE-01 covers
 * their abuse instead).
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
  // One-time-code / recovery steps also run before a session exists.
  "verify-code",
  "verify-otp",
  "otp",
  "magic-link",
  "verify-email",
  "forgot-password",
  "reset-password",
  "password-reset",
  "two-factor",
  "2fa",
  "mfa",
]);

/**
 * Handler text that reads the identity an auth middleware attached to the
 * request (`req.user`, `req.session`, Koa `ctx.state.user`, Hono
 * `c.get("jwtPayload")`).
 */
export const USER_IDENTITY_READ_RE =
  /\b(?:req|request)\.(?:user|session|auth|isAuthenticated)\b|\bctx\.state\.(?:user|auth)\b|\bc\.get\(\s*['"`](?:user|session|auth|jwtPayload)['"`]\s*\)|\bc\.var\.(?:user|session|auth)\b/;

/**
 * Authorization by role, not just authentication: a role comparison
 * (`user.role === "admin"`, `role !== 'admin'`), a role/permission helper
 * (`requireAdmin()`, `hasRole()`, `checkPermission()`, `isAdmin`), an
 * admin allowlist (`ADMIN_EMAILS.includes(...)`), or provider role claims
 * (Clerk `sessionClaims.metadata.role`, `has({ role })`).
 */
export const ROLE_CHECK_RE =
  /\broles?\b\s*(?:===|!==|==|!=)|(?:===|!==|==|!=)\s*["'`](?:admin|super_?admin|owner|staff|moderator)["'`]|\broles?\??\.(?:includes|has|some|indexOf)\(|\bis_?(?:admin|Admin|super_?admin|SuperAdmin|superuser|Superuser|staff|Staff)\b|\b(?:has|check|require|ensure|assert|verify|with|is)(?:Role|Roles|Permission|Permissions|Admin|AdminRole|AdminUser|Scope|Scopes)\b|\badmin_?only\b|\badminOnly\b|\bpermissions?\??\.(?:includes|has|some)\(|\bcan\(|\bability\.|\bADMIN_(?:EMAILS?|IDS?|USERS?|LIST)\b|\badmin(?:Emails|Ids|Users|List)\??\.(?:includes|has|some)\(|\bsessionClaims[?.\w]{0,24}\.role\b|\bpublicMetadata\??\.role\b|\bhas\(\s*\{\s*(?:role|permission)\b/;

/**
 * A role GUARD — stricter than ROLE_CHECK_RE, which also accepts a mere
 * mention such as an `isAdmin` field: a role comparison, a role/permission
 * helper call (`requireAdmin()`, `hasRole(...)`), a negated or tested
 * admin flag (`if (!user.isAdmin)`), or an admin allowlist. Used where the
 * privileged field itself would otherwise count as its own guard.
 */
export const ROLE_GUARD_RE =
  /\broles?\b\s*(?:===|!==|==|!=)|(?:===|!==|==|!=)\s*["'`](?:admin|super_?admin|owner|staff|moderator)["'`]|\broles?\??\.(?:includes|has|some|indexOf)\(|\b(?:has|check|require|ensure|assert|verify|with|is)(?:Role|Roles|Permission|Permissions|Admin|AdminRole|AdminUser|Scope|Scopes)\s*\(|!\s*[\w.?]*\bis_?(?:admin|Admin|superuser|Superuser|staff|Staff)\b|\bif\s*\(\s*[\w.?]*\bis_?(?:admin|Admin|superuser|Superuser|staff|Staff)\s*\)|\badmin_?[oO]nly\b|\bpermissions?\??\.(?:includes|has|some)\(|\bcan\(|\bability\.|\bADMIN_(?:EMAILS?|IDS?|USERS?|LIST)\b|\bsessionClaims[?.\w]{0,24}\.role\b|\bhas\(\s*\{\s*(?:role|permission)\b/;

/**
 * Record keys / columns that scope a query to its owner (`userId`,
 * `owner_id`, `authorId`, `tenantId`, ...). A lookup that filters on one of
 * these is not an insecure direct object reference.
 */
export const OWNERSHIP_KEY_RE =
  /^(?:user|owner|author|creator|created_?by|account|tenant|org|organization|team|workspace|customer|member|profile|buyer|seller|uploader|sender|recipient|patient|student|company)_?(?:id|Id|ID|uid|Uid)?$|^(?:createdBy|created_by|userEmail|user_email|ownerEmail|owner_email|email)$/;

/**
 * Text evidence that a handler compares a fetched record's owner with the
 * caller (`if (order.userId !== session.user.id)`), or calls an
 * object-level authorization helper (`assertOwner`, `canAccess`, CASL
 * `ability.can`, a policy object).
 */
export const OWNERSHIP_CHECK_RE =
  /\.\s*(?:user|owner|author|creator|account|tenant|org|organization|team|workspace|customer|member|profile)_?(?:id|Id|ID)\s*(?:!==|===|!=|==)|(?:!==|===|!=|==)\s*[\w.?!]*\.(?:user|owner|author|creator|account|tenant|org|team|workspace|customer|member)_?(?:id|Id|ID)\b|\.createdBy\s*(?:!==|===)|\b(?:assert|check|ensure|verify|require)\w*(?:Owner|Ownership|Access|Permission|Member|Membership)\w*\s*\(|\bcan(?:Access|Edit|View|Read|Update|Delete|Manage|Modify)\w*\s*\(|\bisOwner\b|\bability\.|\bpolicy\.|\bauthorize\w*\s*\(/;

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

/** Barrel re-export of routeAuthDetector (CAT-3 AUTH-01 unprotected Next.js route handler). */
export { routeAuthDetector } from "./route-auth-detector.js";
/** Barrel re-export of serverRouteAuthDetector (AUTH-01 for Express / Fastify / Hono / Koa routes). */
export { serverRouteAuthDetector } from "./server-route-auth-detector.js";
/** Barrel re-export of pyGoRouteAuthDetector (AUTH-01 for FastAPI / Flask / Go routes). */
export { pyGoRouteAuthDetector } from "./py-go-route-auth-detector.js";
/** Barrel re-export of idorDetector (AUTH-08 by-id record access not scoped to the signed-in user). */
export { idorDetector } from "./idor-detector.js";
/** Barrel re-export of adminAccessDetector (AUTH-09 admin area without an admin role check). */
export { adminAccessDetector } from "./admin-access-detector.js";
/** Barrel re-export of massAssignmentDetector (AUTH-10 request body / privilege fields written to records). */
export { massAssignmentDetector } from "./mass-assignment-detector.js";
/** Barrel re-export of insecureRandomDetector (AUTH-11 secrets and login codes from Math.random). */
export { insecureRandomDetector } from "./insecure-random-detector.js";

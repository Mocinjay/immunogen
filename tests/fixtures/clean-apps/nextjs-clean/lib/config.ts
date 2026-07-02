/**
 * Phase 5 clean fixture — safe config module exercising the
 * FP-prone-but-safe patterns that must NOT fire on any detector.
 */

// BUNDLE-01 must NOT fire: Stripe's own documented public-key naming
// convention (PUBLISHABLE) is explicitly excluded by the client-exposure
// detector's keyword filter.
export const stripePublishableKey = process.env.NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY;

// BUNDLE-01 must NOT fire: a public, non-secret API base URL behind the
// public prefix is the intended use of NEXT_PUBLIC_.
export const apiUrl = process.env.NEXT_PUBLIC_API_URL;

// CORS-01 must NOT fire: a specific allowlisted origin, not a wildcard.
export const corsHeaders = {
  "Access-Control-Allow-Origin": "https://app.example.com",
  "Access-Control-Allow-Credentials": "true",
};

// CONFIG-01 must NOT fire: a single named property read, never the whole
// process.env object.
export function logStartupConfig(): void {
  // eslint-disable-next-line no-console -- safe single-property diagnostic log, not a whole-env dump (CONFIG-01 clean case)
  console.log("starting up, nodeEnv =", process.env.NODE_ENV);
}

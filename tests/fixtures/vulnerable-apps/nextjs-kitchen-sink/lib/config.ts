/**
 * Phase 5 vulnerable kitchen-sink fixture — intentionally insecure config
 * module. Every secret below is fake/synthetic; this file exists only to be
 * scanned by tests/integration/phase5-coverage.test.ts, never to run.
 */

// SEC-01: hardcoded Stripe live secret key.
export const stripeSecretKey = "sk_live_4eC39HqLyjWDarjtT1zdp7dc";

// BUNDLE-01: a secret-named env var behind the NEXT_PUBLIC_ prefix gets
// inlined into the browser bundle.
export const exposedStripeSecret = process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY;

// SEC-06: high-entropy literal anchored to a "secret" keyword on the same line.
export const internalApiSecret = "aB3xQ9zK2mN7pL5wR8tY4vU6sD1fG0hJ2kM8nQ4rZ7c";

// SEC-04 (signal a): a Supabase service_role JWT whose decoded payload
// carries role:service_role.
export const supabaseServiceRoleJwt =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIiwiaXNzIjoic3VwYWJhc2UiLCJpYXQiOjE3MDAwMDAwMDB9.fakeSignatureNotARealSecretXXXXXXXXXXXXXX";

// SEC-04 (signal b): a bare reference to the env-var name itself.
export const serviceRoleEnvName = process.env.SUPABASE_SERVICE_ROLE_KEY;

// CONFIG-01: the whole environment object dumped to the logs.
export function logStartupConfig(): void {
  console.log(process.env);
}

// CORS-01: wildcard origin combined with allow-credentials true — forbidden
// by the CORS spec, enables cross-origin credential theft.
export const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Credentials": "true",
};

/**
 * FIXTURE FILE — used by src/scan.test.ts to prove the end-to-end secrets
 * pipeline (ingest -> detectors -> scoring -> CLI). The value below is a
 * FABRICATED test string in the shape of a Stripe live secret key
 * (`sk_live_` + token chars matching the SEC-01 provider regex from
 * src/detectors/secrets/entropy-detector.ts) — it is NOT a real credential
 * and was never issued by Stripe or any other provider.
 */
export const stripeSecretKey =
  "sk_live_FAKE0000000000000000000000TESTONLY";

export function getPaymentConfig() {
  return { stripeSecretKey };
}

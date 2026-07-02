/**
 * stripeDetector — CAT-4 (Payment) detector, PAY-01.
 *
 * Stripe's own docs mandate that every webhook handler verify the request
 * signature via `stripe.webhooks.constructEvent` (or its async sibling
 * `constructEventAsync`) before trusting the event body — without it, any
 * caller can POST a forged event and trigger payment-fraud-adjacent logic
 * (granting entitlements, marking orders paid, etc.). PAY-01 fires when a
 * file BOTH (a) sits on a webhook/stripe route path AND (b) imports the
 * `stripe` module AND (c) never references `constructEvent` anywhere in its
 * content. All three signals must hold — per
 * .planning/research/FEATURES.md CAT-4's False Positive Management Strategy
 * ("Require constructEvent absence + webhook path match together; not just
 * one signal"), a stripe import alone (e.g. in a checkout/lib file) or a
 * webhook-shaped path with no stripe import at all must never fire.
 *
 * STACK GATE (ctx.stackHints.hasStripe, src/core/ingest/stack-detector.ts):
 * checked FIRST, before any other logic — a repo with no `stripe` dependency
 * never runs the path/import/constructEvent scan at all. This mirrors
 * ARCHITECTURE.md's stack-detection rationale: framework-specific detectors
 * must never activate on a stack that doesn't use that framework. The gate
 * lives inside detect() itself (not the registry) per this plan's contract.
 *
 * FP allowlist (.planning/research/PITFALLS.md Pitfall 1): `detect()` also
 * opens with the same path-segment check against `__tests__`, `fixtures`,
 * `mocks`, `examples`, plus a `.test.`/`.stories.` basename check, mirroring
 * src/detectors/secrets/entropy-detector.ts's `isAllowlistedPath` — a
 * deliberately-vulnerable fixture file must never self-flag.
 *
 * ENG-05 (text-only invariant): this module reads `ctx.content` as a plain
 * string. It never reads `ctx.ast`, never imports a parser, and never
 * evaluates, requires, or spawns a subprocess from scanned content.
 *
 * No-throw contract (src/core/types.ts `Detector.detect`): the entire body
 * of `detect()` runs inside a try/catch returning `[]` on any failure, so a
 * malformed/empty `ctx.content` can never propagate a rejection.
 */
import type { Detector, DetectorContext, Finding } from "../../core/types.js";

/** Path segments that suppress every finding in this file (FP allowlist — PITFALLS.md Pitfall 1). */
const FP_ALLOWLIST_SEGMENTS = new Set(["__tests__", "fixtures", "mocks", "examples"]);

/**
 * True when `filePath` falls inside a test/fixture/mock/example directory,
 * or its basename marks it as a test or story file (`.test.` / `.stories.`).
 * Mirrors src/detectors/secrets/entropy-detector.ts `isAllowlistedPath`.
 */
function isAllowlistedPath(filePath: string): boolean {
  const segments = filePath.split("/");
  if (segments.some((segment) => FP_ALLOWLIST_SEGMENTS.has(segment))) {
    return true;
  }
  const basename = segments.at(-1) ?? "";
  return basename.includes(".test.") || basename.includes(".stories.");
}

/**
 * True when `filePath` (lowercased) looks like a Stripe webhook route:
 * either a path segment literally named `webhook` or `webhooks`, or any
 * path under an `api`/`app` route tree containing the literal `stripe`
 * (covers both `app/**\/webhook/**` App Router handlers and
 * `pages/api/**stripe**` Pages Router handlers, plus a bare
 * `/api/stripe` or `/api/webhook` Express-style route file). This is
 * signal (a) of the required two-signal (path-match + missing-verify)
 * co-occurrence — a stripe import on a non-route file like `lib/checkout.ts`
 * must never match here.
 */
function isWebhookOrStripeRoute(filePath: string): boolean {
  const lower = filePath.toLowerCase();
  const segments = lower.split("/");
  const hasWebhookSegment = segments.some((segment) => segment === "webhook" || segment === "webhooks");
  if (hasWebhookSegment) {
    return true;
  }
  // Any segment containing "stripe" under an api/app-rooted path covers
  // pages/api/stripe.ts, app/api/stripe/route.ts, and api/stripe.ts alike.
  const hasApiOrAppSegment = segments.some((segment) => segment === "api" || segment === "app");
  const hasStripeSegment = segments.some((segment) => segment.includes("stripe"));
  return hasApiOrAppSegment && hasStripeSegment;
}

/**
 * Matches an import or require of the `stripe` module, ES or CJS style. NO
 * global flag — this pattern is only ever used with `.test()` for a one-shot
 * per-line presence check, never `matchAll`. A global-flagged regex used
 * with `.test()` is stateful (`lastIndex` persists on the shared
 * module-level instance across calls), which silently skips matches on
 * later calls; omitting `g` keeps every `.test()` call independent (same
 * gotcha documented on src/detectors/cors-headers/cors-detector.ts's
 * WILDCARD_ORIGIN_RE).
 */
const STRIPE_IMPORT_RE = /(?:import\s+.*from\s+["']stripe["']|require\(\s*["']stripe["']\s*\))/;

/** Matches `constructEvent` or `constructEventAsync` anywhere in content — presence means signature verification IS performed. */
const CONSTRUCT_EVENT_RE = /constructEvent(?:Async)?/;

export const stripeDetector: Detector = {
  config: {
    name: "stripe-webhook",
    category: "payment",
    globs: ["**/*.{ts,tsx,js,jsx,mjs,cjs}"],
    requiresStack: ["stripe"],
    requiresNetwork: false,
  },

  // Not declared `async` — no network/disk wait in this text-only detector;
  // the body is plain synchronous work wrapped in `Promise.resolve()`.
  detect(ctx: DetectorContext): Promise<Finding[]> {
    try {
      // STACK GATE FIRST (per this plan's contract): a repo with no stripe
      // dependency never runs the rest of the scan. requiresStack on
      // config is declarative metadata for the registry; this in-code gate
      // is the actual enforcement until the registry wiring plan (05-08).
      if (!ctx.stackHints.hasStripe) {
        return Promise.resolve([]);
      }

      // FP allowlist (PITFALLS.md Pitfall 1): suppress every finding for
      // test/fixture/mock/example/story paths.
      if (isAllowlistedPath(ctx.filePath)) {
        return Promise.resolve([]);
      }

      // PATH MATCH (signal a): only webhook/stripe route files are eligible.
      // Both signals (path-match AND missing-constructEvent) are required —
      // a stripe import on a non-route file must never fire (FP mitigation
      // per FEATURES.md CAT-4).
      if (!isWebhookOrStripeRoute(ctx.filePath)) {
        return Promise.resolve([]);
      }

      // IMPORT SIGNAL: confirm the file actually imports/requires stripe.
      // Capture the first match's line for the Finding's reported line.
      const lines = ctx.content.split("\n");
      let stripeImportLine: number | undefined;
      for (const [index, line] of lines.entries()) {
        if (STRIPE_IMPORT_RE.test(line)) {
          stripeImportLine = index + 1; // 1-indexed per src/core/types.ts Finding.line
          break;
        }
      }

      if (stripeImportLine === undefined) {
        // No stripe import on this route file — nothing to verify here.
        return Promise.resolve([]);
      }

      // MISSING-VERIFY SIGNAL (signal b): constructEvent/constructEventAsync
      // present anywhere in content means the handler DOES verify the
      // signature — zero findings, this is the clean case.
      if (CONSTRUCT_EVENT_RE.test(ctx.content)) {
        return Promise.resolve([]);
      }

      const finding: Finding = {
        ruleId: "PAY-01",
        category: "payment",
        detectorName: "stripe-webhook",
        file: ctx.filePath,
        line: stripeImportLine,
        severity: "CRITICAL",
        confidence: "HIGH",
        message: "Stripe webhook handler does not verify the signature (missing constructEvent).",
        remediation:
          "Verify the raw request body with stripe.webhooks.constructEvent using the endpoint's signing secret before trusting the event.",
      };

      return Promise.resolve([finding]);
    } catch {
      // No-throw contract (src/core/types.ts Detector.detect): a malformed
      // or unexpected ctx.content must resolve to [], never reject.
      return Promise.resolve([]);
    }
  },
};

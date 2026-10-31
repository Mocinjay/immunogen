/**
 * stripeDetector — CAT-4 (Payment) detector, PAY-01 and PAY-02.
 *
 * PAY-02 (HIGH/MEDIUM): in any file that imports the Stripe server SDK, a
 * charge amount (`amount:` / `unit_amount:`) read straight from the request
 * (`req.body`, `body`, `input`, `payload`, `formData.get(...)`,
 * `searchParams.get(...)`) — the buyer sets their own price. Prices belong
 * on the server (a Stripe Price id or a server-side catalog lookup).
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
import { isTestOrFixturePath } from "../shared/test-paths.js";

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

/** A Stripe charge amount assigned straight from client-controlled request data. */
const CLIENT_AMOUNT_RE =
  /\b(?:unit_amount|amount)\s*:\s*(?:Number\(|parseInt\(|parseFloat\(|Math\.round\()?\s*(?:req\.body|request\.body|body|input|payload|formData\.get\(|searchParams\.get\()/;

/** Python / Go: the file uses the Stripe SDK. */
const PY_GO_STRIPE_IMPORT_RE = /^\s*import\s[^\n]*\bstripe\b|^\s*from\s+stripe\b|"github\.com\/stripe\/stripe-go/m;

/** Python / Go: webhook signature verification. */
const PY_GO_CONSTRUCT_EVENT_RE = /\bWebhook\.construct_event\(|\bwebhook\.ConstructEvent(?:WithOptions)?\(/;

/** Python / Go: a route registration whose path names a webhook. */
const PY_GO_WEBHOOK_ROUTE_RE = /(?:^\s*@\w+\.(?:post|route|api_route)\(|\.(?:POST|Post|HandleFunc|Handle)\()\s*["'][^"']*webhook[^"']*["']/i;

/** Python / Go: a Stripe amount taken from request data. */
const PY_GO_CLIENT_AMOUNT_RE =
  /\b(?:unit_amount|amount)\s*=\s*(?:int\(|float\(|round\()?\s*(?:request\.|body\b|payload\b)|["'](?:unit_amount|amount)["']\s*:\s*(?:int\(|float\()?\s*(?:request\.|body\b|payload\b)|\b(?:UnitAmount|Amount):\s*stripe\.Int64\(\s*(?:int64\()?\s*(?:req|body|input|payload|params)\./;

/** PAY-01 / PAY-02 for a Python or Go file that uses the Stripe SDK. */
function pythonGoFindings(ctx: DetectorContext, lines: string[]): Finding[] {
  if (!PY_GO_STRIPE_IMPORT_RE.test(ctx.content)) {
    return [];
  }
  const findings: Finding[] = [];
  const verifiesSignature = PY_GO_CONSTRUCT_EVENT_RE.test(ctx.content);
  for (const [index, line] of lines.entries()) {
    if (!verifiesSignature && PY_GO_WEBHOOK_ROUTE_RE.test(line)) {
      findings.push({
        ruleId: "PAY-01",
        category: "payment",
        detectorName: "stripe-webhook",
        file: ctx.filePath,
        line: index + 1,
        severity: "CRITICAL",
        confidence: "HIGH",
        message: "Stripe webhook handler does not verify the signature (missing construct_event / webhook.ConstructEvent).",
        remediation:
          "Verify the raw request body with stripe.Webhook.construct_event (Python) or webhook.ConstructEvent (Go) using the endpoint's signing secret before trusting the event.",
      });
    }
    if (PY_GO_CLIENT_AMOUNT_RE.test(line)) {
      findings.push({
        ruleId: "PAY-02",
        category: "payment",
        detectorName: "stripe-webhook",
        file: ctx.filePath,
        line: index + 1,
        severity: "HIGH",
        confidence: "MEDIUM",
        message: "Stripe charge amount is taken from the request — a buyer can pay any price they choose.",
        remediation:
          "Look the price up on the server (a Stripe Price id from your catalog, or a server-side product table keyed by the item id) and never accept an amount from the client.",
        matchedText: line.trim().slice(0, 120),
      });
    }
  }
  return findings;
}

/** Builds the PAY-02 findings for every client-controlled amount line in a Stripe-importing file. */
function clientAmountFindings(ctx: DetectorContext, lines: string[]): Finding[] {
  const findings: Finding[] = [];
  for (const [index, line] of lines.entries()) {
    if (!CLIENT_AMOUNT_RE.test(line)) {
      continue;
    }
    findings.push({
      ruleId: "PAY-02",
      category: "payment",
      detectorName: "stripe-webhook",
      file: ctx.filePath,
      line: index + 1, // 1-indexed per src/core/types.ts Finding.line
      severity: "HIGH",
      confidence: "MEDIUM",
      message: "Stripe charge amount is taken from the request — a buyer can pay any price they choose.",
      remediation:
        "Look the price up on the server (a Stripe Price id from your catalog, or a server-side product table keyed by the item id) and never accept an amount from the client.",
      matchedText: line.trim().slice(0, 120),
    });
  }
  return findings;
}

export const stripeDetector: Detector = {
  config: {
    name: "stripe-webhook",
    category: "payment",
    globs: ["**/*.{ts,tsx,js,jsx,mjs,cjs,py,go}"],
    requiresStack: ["stripe"],
    requiresNetwork: false,
  },

  // Not declared `async` — no network/disk wait in this text-only detector;
  // the body is plain synchronous work wrapped in `Promise.resolve()`.
  detect(ctx: DetectorContext): Promise<Finding[]> {
    try {
      // STACK GATE FIRST: a repo with no stripe dependency never runs the
      // rest of the scan. The registry enforces config.requiresStack
      // ("stripe" is in StackHints.frameworks); this repeats it for direct
      // callers of detect().
      if (!ctx.stackHints.hasStripe) {
        return Promise.resolve([]);
      }

      // FP allowlist (PITFALLS.md Pitfall 1): suppress every finding for
      // test/fixture/mock/example/story paths.
      if (isTestOrFixturePath(ctx.filePath)) {
        return Promise.resolve([]);
      }

      const lines = ctx.content.split("\n");
      if (/\.(?:py|go)$/.test(ctx.filePath)) {
        return Promise.resolve(pythonGoFindings(ctx, lines));
      }

      // IMPORT SIGNAL: confirm the file actually imports/requires stripe.
      // Capture the first match's line for the Finding's reported line.
      let stripeImportLine: number | undefined;
      for (const [index, line] of lines.entries()) {
        if (STRIPE_IMPORT_RE.test(line)) {
          stripeImportLine = index + 1; // 1-indexed per src/core/types.ts Finding.line
          break;
        }
      }

      if (stripeImportLine === undefined) {
        // No stripe import in this file — nothing to check here.
        return Promise.resolve([]);
      }

      // PAY-02 applies to every Stripe-importing file (checkout routes,
      // server actions, Express handlers).
      const amountFindings = clientAmountFindings(ctx, lines);

      // PATH MATCH (signal a): only webhook/stripe route files are eligible
      // for PAY-01. Both signals (path-match AND missing-constructEvent) are
      // required — a stripe import on a non-route file must never fire
      // PAY-01 (FP mitigation per FEATURES.md CAT-4).
      if (!isWebhookOrStripeRoute(ctx.filePath)) {
        return Promise.resolve(amountFindings);
      }

      // MISSING-VERIFY SIGNAL (signal b): constructEvent/constructEventAsync
      // present anywhere in content means the handler DOES verify the
      // signature — zero findings, this is the clean case.
      if (CONSTRUCT_EVENT_RE.test(ctx.content)) {
        return Promise.resolve(amountFindings);
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

      return Promise.resolve([finding, ...amountFindings]);
    } catch {
      // No-throw contract (src/core/types.ts Detector.detect): a malformed
      // or unexpected ctx.content must resolve to [], never reject.
      return Promise.resolve([]);
    }
  },
};

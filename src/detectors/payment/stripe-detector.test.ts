import { describe, expect, it } from "vitest";

import { stripeDetector } from "./stripe-detector.js";

import type { DetectorContext, StackHints } from "../../core/types.js";

/** StackHints fixture with hasStripe true — the gate this detector reads. */
const STACK_HINTS_WITH_STRIPE: StackHints = {
  frameworks: new Set(),
  hasSupabase: false,
  hasFirebase: false,
  hasStripe: true,
  hasEnvFiles: false,
  hasMcpJson: false,
  hasClaudeSkills: false,
  hasCursorRules: false,
};

/** StackHints fixture with hasStripe false — proves the stack gate suppresses PAY-01. */
const STACK_HINTS_WITHOUT_STRIPE: StackHints = {
  ...STACK_HINTS_WITH_STRIPE,
  hasStripe: false,
};

/** Builds a DetectorContext literal for `content` at the given `filePath`/`stackHints`, without the ingestion layer. */
function makeContext(
  content: string,
  filePath: string,
  stackHints: StackHints = STACK_HINTS_WITH_STRIPE,
): DetectorContext {
  return {
    filePath,
    content,
    stackHints,
    fileSet: new Map(),
  };
}

const VULNERABLE_WEBHOOK_CONTENT = [
  'import Stripe from "stripe";',
  "",
  "export async function POST(req: Request) {",
  '  const body = await req.text();',
  "  const event = JSON.parse(body);",
  "  // No signature verification at all.",
  "  return new Response(JSON.stringify({ received: true }));",
  "}",
].join("\n");

const CLEAN_WEBHOOK_CONTENT = [
  'import Stripe from "stripe";',
  "",
  'const stripe = new Stripe(process.env.STRIPE_SECRET_KEY ?? "");',
  "",
  "export async function POST(req: Request) {",
  '  const sig = req.headers.get("stripe-signature") ?? "";',
  "  const body = await req.text();",
  "  const event = stripe.webhooks.constructEvent(body, sig, process.env.STRIPE_WEBHOOK_SECRET ?? \"\");",
  "  return new Response(JSON.stringify({ received: true }));",
  "}",
].join("\n");

describe("stripeDetector — PAY-01 (missing constructEvent, stack-gated)", () => {
  it("flags a webhook handler that imports stripe but never calls constructEvent as CRITICAL/HIGH (app/api/webhook)", async () => {
    const ctx = makeContext(VULNERABLE_WEBHOOK_CONTENT, "app/api/webhook/route.ts");

    const findings = await stripeDetector.detect(ctx);

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      ruleId: "PAY-01",
      category: "payment",
      severity: "CRITICAL",
      confidence: "HIGH",
      file: "app/api/webhook/route.ts",
      line: 1,
    });
  });

  it("flags the same vulnerable shape under pages/api/stripe.ts", async () => {
    const ctx = makeContext(VULNERABLE_WEBHOOK_CONTENT, "pages/api/stripe.ts");

    const findings = await stripeDetector.detect(ctx);

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      ruleId: "PAY-01",
      category: "payment",
      severity: "CRITICAL",
      confidence: "HIGH",
      file: "pages/api/stripe.ts",
    });
  });

  it("does NOT flag a webhook handler that DOES call stripe.webhooks.constructEvent (clean)", async () => {
    const ctx = makeContext(CLEAN_WEBHOOK_CONTENT, "app/api/webhook/route.ts");

    const findings = await stripeDetector.detect(ctx);

    expect(findings).toHaveLength(0);
  });

  it("does NOT flag a stripe-importing file that is not a webhook/stripe route (path-match required)", async () => {
    const ctx = makeContext(VULNERABLE_WEBHOOK_CONTENT, "lib/checkout.ts");

    const findings = await stripeDetector.detect(ctx);

    expect(findings).toHaveLength(0);
  });

  it("does NOT flag the vulnerable shape when stackHints.hasStripe is false (stack gate)", async () => {
    const ctx = makeContext(VULNERABLE_WEBHOOK_CONTENT, "app/api/webhook/route.ts", STACK_HINTS_WITHOUT_STRIPE);

    const findings = await stripeDetector.detect(ctx);

    expect(findings).toHaveLength(0);
  });

  it("does NOT flag vulnerable content inside a __tests__/fixtures path (FP allowlist guard)", async () => {
    const ctx = makeContext(VULNERABLE_WEBHOOK_CONTENT, "src/__tests__/fixtures/webhook-route.ts");

    const findings = await stripeDetector.detect(ctx);

    expect(findings).toHaveLength(0);
  });
});

describe("stripeDetector — config", () => {
  it("declares category payment and a name of 'stripe-webhook'", () => {
    expect(stripeDetector.config.name).toBe("stripe-webhook");
    expect(stripeDetector.config.category).toBe("payment");
  });

  it("declares requiresStack including stripe", () => {
    expect(stripeDetector.config.requiresStack).toContain("stripe");
  });
});

describe("stripeDetector — no-throw contract", () => {
  it("resolves to [] for empty content", async () => {
    const ctx = makeContext("", "app/api/webhook/route.ts");

    const findings = await stripeDetector.detect(ctx);

    expect(findings).toEqual([]);
  });
});

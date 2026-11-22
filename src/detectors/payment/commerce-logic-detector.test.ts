import { describe, expect, it } from "vitest";

import { buildAstCache } from "../../core/parse/ast-cache.js";
import { commerceLogicDetector } from "./commerce-logic-detector.js";

import type { DetectorContext, StackHints } from "../../core/types.js";

const STACK_HINTS: StackHints = {
  frameworks: new Set(["nextjs"]),
  hasSupabase: false,
  hasFirebase: false,
  hasStripe: true,
  hasEnvFiles: false,
  hasMcpJson: false,
  hasClaudeSkills: false,
  hasCursorRules: false,
};

const lines = (...parts: string[]): string => parts.join("\n");

async function summarize(content: string, filePath = "app/api/checkout/route.ts"): Promise<string[]> {
  const { astCache } = buildAstCache(new Map([[filePath, content]]));
  const ctx: DetectorContext = { filePath, content, ast: astCache.get(filePath), stackHints: STACK_HINTS, fileSet: new Map([[filePath, content]]) };
  const findings = await commerceLogicDetector.detect(ctx);
  return findings.map((finding) => `${finding.ruleId} ${finding.severity}/${finding.confidence} L${finding.line} ${finding.matchedText ?? ""}`);
}

describe("commerceLogicDetector — PAY-03 client-controlled price", () => {
  it("flags an order total taken from the request (the video's $0.01 Pro plan)", async () => {
    const code = lines(
      "export async function POST(req: Request) {",
      "  const { planId, price } = await req.json();",
      "  const order = await prisma.order.create({ data: { planId, total: price, userId: user.id } });",
      "}",
    );
    expect(await summarize(code)).toEqual(["PAY-03 HIGH/MEDIUM L3 total"]);
  });

  it("follows prices through a cart reduce and a Stripe line item", async () => {
    const code = lines(
      'import Stripe from "stripe";',
      "export async function POST(req: Request) {",
      "  const { items } = await req.json();",
      "  const session = await stripe.checkout.sessions.create({",
      "    line_items: items.map((item) => ({ quantity: 1, price_data: { currency: 'usd', unit_amount: Math.round(item.price * 100) } })),",
      "  });",
      "  const total = items.reduce((sum, item) => sum + item.price, 0);",
      "  await db.insert(orders).values({ total });",
      "}",
    );
    expect(await summarize(code)).toEqual(["PAY-03 HIGH/MEDIUM L5 unit_amount", "PAY-03 HIGH/MEDIUM L8 total"]);
  });

  it("flags a Server Action that receives the price as an argument", async () => {
    const code = lines('"use server";', "export async function buyPlan(planId: string, price: number) {", "  await prisma.purchase.create({ data: { planId, amount: price } });", "}");
    expect(await summarize(code, "app/pricing/actions.ts")).toEqual(["PAY-03 HIGH/MEDIUM L3 amount"]);
  });

  it.each([
    [
      "a price looked up on the server by the request's product id",
      lines(
        "export async function POST(req: Request) {",
        "  const { productId, quantity } = await req.json();",
        "  if (!Number.isInteger(quantity) || quantity < 1) return bad();",
        "  const product = await prisma.product.findUnique({ where: { id: productId } });",
        "  await prisma.order.create({ data: { productId, total: product.price * quantity } });",
        "}",
      ),
    ],
    [
      "a client price compared against the server price",
      lines(
        "export async function POST(req: Request) {",
        "  const body = await req.json();",
        "  const product = await getProduct(body.productId);",
        "  if (body.price !== product.price) return bad();",
        "  await prisma.order.create({ data: { total: body.price } });",
        "}",
      ),
    ],
    [
      "a Stripe amount line PAY-02 already reports",
      lines('import Stripe from "stripe";', "export async function POST(req) {", "  const body = await req.json();", "  await stripe.paymentIntents.create({ amount: body.amount });", "}"),
    ],
  ])("does NOT flag %s", async (_label, code) => {
    expect(await summarize(code)).toEqual([]);
  });
});

describe("commerceLogicDetector — PAY-04 faked payment", () => {
  it("flags the video's POST /api/orders/1042/paid endpoint", async () => {
    const code = lines(
      "export async function POST(req, { params }) {",
      "  const order = await prisma.order.update({",
      "    where: { id: params.id },",
      '    data: { status: "paid", shipped: true },',
      "  });",
      "  return Response.json(order);",
      "}",
    );
    expect(await summarize(code, "app/api/orders/[id]/paid/route.ts")).toEqual(["PAY-04 HIGH/MEDIUM L4 status"]);
  });

  it("flags paid flags, paidAt, and raw SQL", async () => {
    expect(await summarize('app.post("/api/confirm", async (req, res) => { await Order.updateOne({ _id: req.body.id }, { isPaid: true, paidAt: new Date() }); });', "server/orders.ts")).toEqual([
      "PAY-04 HIGH/MEDIUM L1 isPaid",
      "PAY-04 HIGH/MEDIUM L1 paidAt",
    ]);
    const sql = lines("export async function POST(req) {", "  const { id } = await req.json();", "  await pool.query(\"UPDATE orders SET status = 'paid' WHERE id = $1\", [id]);", "}");
    expect(await summarize(sql)).toEqual(["PAY-04 HIGH/MEDIUM L3 status = 'paid'"]);
  });

  it.each([
    [
      "a verified Stripe webhook",
      lines("export async function POST(req) {", "  const event = stripe.webhooks.constructEvent(body, sig, secret);", '  await prisma.order.update({ where: { id }, data: { status: "paid" } });', "}"),
    ],
    [
      "a success page that retrieves the session from Stripe",
      lines(
        "export async function GET(req) {",
        "  const session = await stripe.checkout.sessions.retrieve(searchParams.get('session_id'));",
        '  if (session.payment_status === "paid") await prisma.order.update({ where: { id }, data: { status: "paid" } });',
        "}",
      ),
    ],
    [
      "an admin marking an invoice paid",
      lines("export async function POST(req) {", '  if (session.user.role !== "admin") return forbidden();', "  await prisma.invoice.update({ where: { id }, data: { paid: true } });", "}"),
    ],
    ["a todo marked completed", lines("export async function POST(req) {", '  await prisma.todo.update({ where: { id }, data: { status: "completed" } });', "}")],
    ["selecting paidAt", lines("export async function POST(req) {", "  await prisma.order.update({ where: { id }, data: { note: 'x' }, select: { paidAt: true } });", "}")],
  ])("does NOT flag %s", async (_label, code) => {
    expect(await summarize(code)).toEqual([]);
  });
});

describe("commerceLogicDetector — PAY-05 coupon reuse", () => {
  it("flags a coupon applied with no redemption tracking (FREE10 x100)", async () => {
    const code = lines(
      "export async function POST(req: Request) {",
      "  const { cartId, couponCode } = await req.json();",
      "  const coupon = await prisma.coupon.findUnique({ where: { code: couponCode } });",
      "  if (!coupon) return bad();",
      "  await prisma.cart.update({ where: { id: cartId }, data: { discount: { increment: 0 } } });",
      "}",
    );
    // `increment` is redemption-style bookkeeping; without it the finding appears.
    expect(await summarize(code, "app/api/cart/coupon/route.ts")).toEqual([]);
    const untracked = code.replace("data: { discount: { increment: 0 } }", "data: { discountAmount: coupon.amountOff }");
    expect(await summarize(untracked, "app/api/cart/coupon/route.ts")).toEqual(["PAY-05 MEDIUM/LOW L2 coupon"]);
  });

  it.each([
    ["redemptions recorded", "await prisma.couponRedemption.create({ data: { couponId: coupon.id, userId } });"],
    ["a max-uses check", "if (coupon.timesUsed >= coupon.maxUses) return bad();"],
    ["Stripe promotion codes", "await stripe.checkout.sessions.create({ discounts: [{ promotion_code: promo.id }] });"],
  ])("does NOT flag a coupon with %s", async (_label, extra) => {
    const code = lines(
      "export async function POST(req: Request) {",
      "  const { couponCode } = await req.json();",
      "  const coupon = await prisma.coupon.findUnique({ where: { code: couponCode } });",
      `  ${extra}`,
      "}",
    );
    expect(await summarize(code, "app/api/cart/coupon/route.ts")).toEqual([]);
  });

  it("does NOT treat an OTP `code` as a coupon", async () => {
    const code = lines("export async function POST(req) {", "  const { email, code } = await req.json();", "  if (user.otp !== code) return bad();", "}");
    expect(await summarize(code, "app/api/verify/route.ts")).toEqual([]);
  });
});

describe("commerceLogicDetector — PAY-06 unvalidated quantity", () => {
  it("flags a request quantity multiplied into the total (order -1 items)", async () => {
    const code = lines(
      "export async function POST(req: Request) {",
      "  const { productId, quantity } = await req.json();",
      "  const product = await prisma.product.findUnique({ where: { id: productId } });",
      "  await prisma.order.create({ data: { productId, quantity, total: product.price * quantity } });",
      "}",
    );
    expect(await summarize(code)).toEqual(["PAY-06 MEDIUM/MEDIUM L4 quantity"]);
  });

  it.each([
    ["an integer / bounds check", "if (!Number.isInteger(quantity) || quantity < 1) return bad();"],
    ["a zod schema", "const parsed = Order.parse({ quantity });"],
  ])("does NOT flag a quantity with %s", async (_label, guard) => {
    const code = lines(
      "export async function POST(req: Request) {",
      "  const { productId, quantity } = await req.json();",
      `  ${guard}`,
      "  const product = await prisma.product.findUnique({ where: { id: productId } });",
      "  await prisma.order.create({ data: { productId, quantity, total: product.price * quantity } });",
      "}",
    );
    expect(await summarize(code)).toEqual([]);
  });
});

describe("commerceLogicDetector — scope", () => {
  it("ignores client components, libraries, and tests", async () => {
    const code = lines("export async function POST(req) {", "  const { price } = await req.json();", "  await prisma.order.create({ data: { total: price } });", "}");
    expect(await summarize(`"use client";\n${code}`, "app/checkout/page.tsx")).toEqual([]);
    expect(await summarize("export function save(price) { return prisma.order.create({ data: { total: price } }); }", "lib/orders.ts")).toEqual([]);
    expect(await summarize(code, "app/api/checkout/route.test.ts")).toEqual([]);
  });
});

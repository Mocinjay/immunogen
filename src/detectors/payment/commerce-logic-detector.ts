/**
 * commerceLogicDetector — business-logic flaws in checkout and order code
 * that no secret scanner sees, because the code is "working": it just
 * trusts the buyer.
 *
 *   PAY-03 (HIGH/MEDIUM) — client-controlled price. An order, line item,
 *     or payment is created with a price / total / amount read from the
 *     request (`price: body.price`, `total: items.reduce(... i.price ...)`,
 *     `unit_amount: Math.round(item.price * 100)`). Edit the price in
 *     DevTools, resend, pay $0.01. Any payment provider or database, not
 *     only the Stripe `amount:` shapes PAY-02 matches line by line.
 *
 *   PAY-04 (HIGH/MEDIUM) — payment faked by a status flip. A server
 *     endpoint marks an order paid (`status: "paid"`, `paid: true`,
 *     `paidAt`, `UPDATE orders SET status = 'paid'`) without confirming the
 *     payment with the provider: no verified webhook signature, no
 *     retrieve-and-check of the checkout session / payment intent / PayPal
 *     order. `curl -X POST /api/orders/1042/paid` ships the order.
 *
 *   PAY-05 (MEDIUM/LOW) — coupon reuse. A coupon / promo / voucher code
 *     from the request is applied, and nothing in the file records or
 *     checks redemptions (`used`, `redeemedAt`, `usageCount`, `maxUses`,
 *     an atomic increment, Stripe promotion codes). FREE10 applied 100
 *     times, or replayed in parallel.
 *
 *   PAY-06 (MEDIUM/MEDIUM) — unvalidated quantity. A quantity from the
 *     request is multiplied into a total or written to an order and never
 *     checked to be a positive whole number. Order -1 items, get a refund.
 *
 * All four run only in server entry files (shared/server-entry.ts), where
 * request input is tracked with the strict "data" taint mode
 * (request-input.ts) — a value looked up from the database by a request id
 * is trusted, a value read from the request body is not. Server Action
 * arguments count as request input.
 *
 * AST + text (ENG-05): reads `ctx.ast` / `ctx.content`; never evaluates
 * scanned source. No-throw contract: returns `[]` on any failure.
 */
import { isBabelFile, traverseAst } from "../ast/ast-utils.js";
import { accessPath, collectRequestTaintedNames, isRequestControlled, serverActionParamNames } from "../injection/request-input.js";
import { isTestOrFixturePath } from "../shared/test-paths.js";
import { isClientModule, isServerEntryFile } from "../shared/server-entry.js";
import { isDbWriteCall } from "../shared/db-writes.js";
import { ROLE_GUARD_RE } from "../auth/auth-evidence.js";

import type { Detector, DetectorContext, Finding, Severity, Confidence } from "../../core/types.js";
import type { CallExpression, File, Node, ObjectProperty } from "@babel/types";

/** Keys / fields that carry a price. */
const PRICE_NAME_RE =
  /^(?:price|prices|unitPrice|unit_price|unitAmount|unit_amount|amount|total|totalPrice|total_price|totalAmount|total_amount|amountTotal|amount_total|subtotal|subTotal|sub_total|grandTotal|grand_total|finalPrice|final_price|customPrice|custom_price|cost|fee)$/;

/** Keys / fields that carry a quantity. */
const QUANTITY_NAME_RE = /^(?:quantity|qty|units|seats|itemCount|item_count|numItems|num_items|licenses|tickets)$/;

/** Keys / fields that carry a coupon or promo code. */
const COUPON_NAME_RE =
  /^(?:coupon|couponCode|coupon_code|couponId|promo|promoCode|promo_code|promotionCode|promotion_code|discountCode|discount_code|voucher|voucherCode|voucher_code|giftCard|giftCardCode|gift_code|giftCode|code)$/;

/** Payment-provider calls that take a price (Stripe, PayPal, Razorpay, Lemon Squeezy, Mollie, Square, Paddle, ...). */
const PAYMENT_CALL_RE =
  /(?:checkout\.sessions|paymentIntents|paymentLinks|charges|invoiceItems|invoices|prices|orders|payments|transactions|checkouts|transfers)\.create$|^(?:createOrder|createCheckout\w*|createPayment\w*|createInvoice|createCharge|charge)$/;

/** Evidence the client-sent price is checked against the server's (`if (body.price !== product.price)`). */
const PRICE_VERIFY_RE = /\b\w*(?:price|amount|total)\w*\s*(?:!==|!=|===|==)\s*[\w.?]*(?:price|amount|total)\b/i;

/** Payment confirmation with the provider: a verified webhook, or retrieving and checking the payment. */
const PAYMENT_CONFIRMATION_RE =
  /constructEvent|webhooks?\.verify|verify(?:Webhook|Signature|Payment|Transaction)\w*\s*\(|validate(?:Webhook|PaymentVerification)\w*\s*\(|timingSafeEqual|createHmac|stripe-signature|x-signature|paypal-transmission-sig|razorpay_signature|(?:checkout\.sessions|paymentIntents|charges|invoices|subscriptions)\.retrieve\(|orders\.(?:capture|get)\(|capture(?:Order|Payment)\s*\(|payments\.(?:get|retrieve|capture)\(|transaction\.verify\(|payment_status\s*={2,3}\s*["']paid["']|CRON_SECRET|\.status\s*={2,3}\s*["'](?:succeeded|COMPLETED|paid)["']/i;

/** Status values that mean "paid". */
const PAID_STATUS_RE = /^(?:paid|succeeded|captured)$/i;
const PAYMENT_STATUS_DONE_RE = /^(?:paid|succeeded|captured|complete|completed|success|successful)$/i;

/** Generic status keys, and payment-specific ones where "completed" also means paid. */
const STATUS_KEYS = new Set(["status", "orderStatus", "order_status", "state"]);
const PAYMENT_STATUS_KEYS = new Set(["paymentStatus", "payment_status", "paymentState", "payment_state"]);
const PAID_FLAG_KEYS = new Set(["paid", "isPaid", "is_paid", "hasPaid", "has_paid"]);
const PAID_AT_KEYS = new Set(["paidAt", "paid_at", "paidOn", "paid_on"]);

/** Raw SQL that marks an order paid. */
const SQL_MARK_PAID_RE = /\bupdate\s+\w+\s+set\s+[^;]*?\b(?:status|payment_status)\s*=\s*'(?:paid|succeeded)'|\bset\s+[^;]*?\b(?:is_)?paid\s*=\s*(?:true|1)\b/i;

/** Coupon handling vocabulary (gate for PAY-05). */
const COUPON_CONTEXT_RE = /coupon|promo|voucher|discount|gift_?card/i;

/** Evidence that redemptions are recorded or limited — or that the provider (Stripe promotion codes) enforces them. */
const REDEMPTION_TRACKING_RE =
  /\b(?:used|isUsed|is_used|usedAt|used_at|usedBy|used_by|redeemed|isRedeemed|is_redeemed|redeemedAt|redeemed_at|redeemedBy|redeemed_by|redemptions?|Redemptions?|usageCount|usage_count|usageLimit|usage_limit|timesUsed|times_used|timesRedeemed|times_redeemed|uses|maxUses|max_uses|usesLeft|remainingUses|remaining_uses|maxRedemptions|max_redemptions|claimed|claimedBy|oncePerUser|once_per_user|alreadyApplied|alreadyUsed|appliedCoupons?|couponUsages?|CouponUsages?)\b|\bincrement\b|\bdecrement\b|\$inc\b|promotion_code|allow_promotion_codes|discounts\s*:\s*\[|promotionCodes\.|[Rr]edemption|[Rr]edeemed|[Uu]sage(?:Count|Limit)|[Tt]imesUsed/;

/** Evidence the quantity is validated (bounds check, integer check, schema). */
const QUANTITY_VALIDATION_RE =
  /\b(?:quantity|qty|units|seats|itemCount|numItems|licenses|tickets)\b[^\n;]{0,40}?(?:<=?|>=?)\s*-?\d|(?:<=?|>=?)\s*[\w.?]*\b(?:quantity|qty|units|seats)\b|Number\.isInteger\(|Number\.isSafeInteger\(|\.int\(\)|\.positive\(\)|\.nonnegative\(\)|\.min\(\s*[1-9]|\bmin:\s*[1-9]|@Min\(|@IsPositive|@IsInt|Math\.max\(\s*1\b|Math\.abs\(|(?<!JSON)\.(?:safeParse|parse)\(|\bvalidate\w*\(|\bjoi\.|\bJoi\.|\byup\./;

/** The text name of a property key. */
function keyName(node: Node): string | undefined {
  if (node.type === "Identifier") {
    return node.name;
  }
  return node.type === "StringLiteral" ? node.value : undefined;
}

/** Child AST nodes of `node` (location / comment metadata skipped). */
function childNodes(node: Node): Node[] {
  const children: Node[] = [];
  for (const [key, value] of Object.entries(node)) {
    if (key === "loc" || key === "start" || key === "end" || key === "extra" || key.endsWith("Comments")) {
      continue;
    }
    for (const child of Array.isArray(value) ? (value as unknown[]) : [value]) {
      if (child !== null && typeof child === "object" && typeof (child as { type?: unknown }).type === "string") {
        children.push(child as Node);
      }
    }
  }
  return children;
}

/** Write-option keys whose objects are filters or projections, not written data. */
const NON_DATA_KEYS = new Set(["where", "select", "include", "orderBy", "omit", "returning", "cursor", "distinct"]);

/**
 * Tracks which local names hold a request value of a given kind (a price,
 * a quantity, a coupon code) — by field name, so `const { price } = body`,
 * `const total = items.reduce((s, i) => s + i.price * i.qty, 0)` and
 * `formData.get("price")` count, while `product.price` loaded from the
 * database by a request id does not.
 */
class FieldTaint {
  readonly names = new Set<string>();

  constructor(
    private readonly fieldRe: RegExp,
    private readonly isRequest: (node: Node | undefined) => boolean,
  ) {}

  /** True when `node` (or anything under it) reads a request field of this kind or a name holding one. */
  reads(node: Node | null | undefined): boolean {
    if (node === null || node === undefined) {
      return false;
    }
    switch (node.type) {
      case "Identifier":
        // A tracked local, or request input that is itself named like the field (a Server Action's `price` argument).
        return this.names.has(node.name) || (this.fieldRe.test(node.name) && this.isRequest(node));
      case "MemberExpression":
      case "OptionalMemberExpression":
        if (!node.computed && node.property.type === "Identifier") {
          // `body.price` counts; the `price` of `product.price` is a property name, not the local `price`.
          return (this.fieldRe.test(node.property.name) && this.isRequest(node.object)) || this.reads(node.object);
        }
        return this.reads(node.object) || this.reads(node.property);
      case "ObjectProperty":
        return (node.computed && this.reads(node.key)) || this.reads(node.value);
      case "CallExpression": {
        const callee = node.callee;
        const first = node.arguments.at(0);
        if (
          callee.type === "MemberExpression" &&
          callee.property.type === "Identifier" &&
          callee.property.name === "get" &&
          first?.type === "StringLiteral" &&
          this.fieldRe.test(first.value) &&
          (this.isRequest(callee.object) || /formData|searchParams/i.test(accessPath(callee.object) ?? ""))
        ) {
          // formData.get("price") / searchParams.get("qty")
          return true;
        }
        return childNodes(node).some((child) => this.reads(child));
      }
      default:
        return childNodes(node).some((child) => this.reads(child));
    }
  }

  /** Runs the binding pass to a fixed point. */
  collect(ast: File): void {
    const bindings: Array<{ names: string[]; init: Node; destructured: Array<{ key: string; name: string }> }> = [];
    traverseAst(ast, {
      VariableDeclarator(path) {
        const { id, init } = path.node;
        if (init === null || init === undefined) {
          return;
        }
        if (id.type === "Identifier") {
          bindings.push({ names: [id.name], init, destructured: [] });
        } else if (id.type === "ObjectPattern") {
          const destructured: Array<{ key: string; name: string }> = [];
          for (const property of id.properties) {
            if (property.type === "ObjectProperty") {
              const local = property.value.type === "AssignmentPattern" ? property.value.left : property.value;
              const key = keyName(property.key);
              if (key !== undefined && local.type === "Identifier") {
                destructured.push({ key, name: local.name });
              }
            }
          }
          bindings.push({ names: [], init, destructured });
        }
      },
      AssignmentExpression(path) {
        if (path.node.left.type === "Identifier" && ["=", "+=", "-=", "*="].includes(path.node.operator)) {
          bindings.push({ names: [path.node.left.name], init: path.node.right, destructured: [] });
        }
      },
    });
    let changed = true;
    while (changed) {
      changed = false;
      for (const binding of bindings) {
        for (const name of binding.names) {
          if (!this.names.has(name) && this.reads(binding.init)) {
            this.names.add(name);
            changed = true;
          }
        }
        for (const { key, name } of binding.destructured) {
          if (!this.names.has(name) && this.fieldRe.test(key) && this.isRequest(binding.init)) {
            this.names.add(name);
            changed = true;
          }
        }
      }
    }
  }
}

/** True when `call` writes an order / payment: a database write or a payment-provider call. */
function sinkKind(call: CallExpression, content: string): "db" | "payment" | undefined {
  const calleePath = accessPath(call.callee) ?? "";
  if (PAYMENT_CALL_RE.test(calleePath) || PAYMENT_CALL_RE.test(calleePath.split(".").at(-1) ?? "")) {
    return "payment";
  }
  return isDbWriteCall(call, content) ? "db" : undefined;
}

/** Every object property in `call`'s arguments that carries written data (filters and projections skipped). */
function argumentProperties(call: CallExpression): ObjectProperty[] {
  const properties: ObjectProperty[] = [];
  const walk = (node: Node): void => {
    if (node.type === "ObjectProperty") {
      if (NON_DATA_KEYS.has(keyName(node.key) ?? "")) {
        return;
      }
      properties.push(node);
      walk(node.value);
      return;
    }
    for (const child of childNodes(node)) {
      walk(child);
    }
  };
  for (const argument of call.arguments) {
    walk(argument);
  }
  return properties;
}

interface Hit {
  ruleId: "PAY-03" | "PAY-04" | "PAY-05" | "PAY-06";
  line: number;
  severity: Severity;
  confidence: Confidence;
  message: string;
  remediation: string;
  matchedText: string;
}

const COPY = {
  "PAY-03": {
    remediation:
      "Look the price up on the server from the product / plan id (your database, or a Stripe Price id) and compute totals there; never accept a price, total, or amount from the client. If an amount is deliberately user-chosen (a donation or top-up), enforce a server-side minimum and maximum.",
  },
  "PAY-04": {
    remediation:
      "Mark orders paid only from a signature-verified payment webhook (stripe.webhooks.constructEvent, PayPal / Lemon Squeezy / Razorpay signature checks), or after retrieving the checkout session / payment from the provider's API and checking its status and amount — never from a client-callable route or a success-page redirect.",
  },
  "PAY-05": {
    remediation:
      "Record every redemption (per code, and per user / order) and check it before applying: enforce max uses and one use per order inside a transaction or with an atomic conditional update (UPDATE coupons SET uses = uses + 1 WHERE code = $1 AND uses < max_uses), or let the payment provider enforce it (Stripe promotion codes with max_redemptions).",
  },
  "PAY-06": {
    remediation:
      "Validate every quantity on the server as a positive whole number within a sane maximum (e.g. z.number().int().min(1).max(100)) before pricing or saving the order, and compute totals from server-side prices.",
  },
} as const;

export const commerceLogicDetector: Detector = {
  config: {
    name: "commerce-logic",
    category: "payment",
    globs: ["**/*.{ts,tsx,js,jsx,mjs,cjs,mts,cts}"],
    usesAst: true,
  },

  detect(ctx: DetectorContext): Promise<Finding[]> {
    try {
      if (isTestOrFixturePath(ctx.filePath) || !isBabelFile(ctx.ast) || isClientModule(ctx.content) || !isServerEntryFile(ctx.filePath, ctx.content)) {
        return Promise.resolve([]);
      }
      const ast = ctx.ast;
      const content = ctx.content;
      const tainted = collectRequestTaintedNames(ast, content, { use: "data", seeds: serverActionParamNames(ast) });
      const isRequest = (node: Node | undefined): boolean => isRequestControlled(node, tainted, content, "data");
      const price = new FieldTaint(PRICE_NAME_RE, isRequest);
      const quantity = new FieldTaint(QUANTITY_NAME_RE, isRequest);
      const coupon = new FieldTaint(COUPON_NAME_RE, isRequest);
      price.collect(ast);
      quantity.collect(ast);
      coupon.collect(ast);

      const lines = content.split("\n");
      const hits: Hit[] = [];
      const checksPrice = !PRICE_VERIFY_RE.test(content);
      const confirmsPayment = PAYMENT_CONFIRMATION_RE.test(content) || ROLE_GUARD_RE.test(content);
      const validatesQuantity = QUANTITY_VALIDATION_RE.test(content);
      let quantityLine: number | undefined;
      let couponLine: number | undefined;

      traverseAst(ast, {
        CallExpression(path) {
          const call = path.node;
          // PAY-05: first read of a coupon code from the request.
          if (
            couponLine === undefined &&
            call.callee.type === "MemberExpression" &&
            call.callee.property.type === "Identifier" &&
            call.callee.property.name === "get" &&
            coupon.reads(call)
          ) {
            couponLine = call.loc?.start.line;
          }
          const kind = sinkKind(call, content);
          if (kind === undefined) {
            return;
          }
          for (const property of argumentProperties(call)) {
            const key = keyName(property.key) ?? "";
            const line = property.loc?.start.line ?? call.loc?.start.line ?? 1;
            // PAY-03 — a price field set from a request price.
            if (checksPrice && PRICE_NAME_RE.test(key) && price.reads(property.value)) {
              const lineText = lines.at(line - 1) ?? "";
              const pay02Covers = ctx.stackHints.hasStripe && /from\s+["']stripe["']|require\(\s*["']stripe["']\s*\)/.test(content) && /\b(?:unit_amount|amount)\s*:\s*(?:Number\(|parseInt\(|parseFloat\(|Math\.round\()?\s*(?:req\.body|request\.body|body|input|payload|formData\.get\(|searchParams\.get\()/.test(lineText);
              if (!pay02Covers) {
                hits.push({
                  ruleId: "PAY-03",
                  line,
                  severity: "HIGH",
                  confidence: "MEDIUM",
                  message: `${key} is taken from the request when creating an order or payment — the buyer can edit the price in DevTools and pay $0.01.`,
                  remediation: COPY["PAY-03"].remediation,
                  matchedText: key,
                });
              }
            }
            // PAY-04 — an order flipped to paid without confirming the payment.
            if (!confirmsPayment && kind === "db") {
              const value = property.value;
              const literal = value.type === "StringLiteral" ? value.value : undefined;
              const marksPaid =
                (STATUS_KEYS.has(key) && literal !== undefined && PAID_STATUS_RE.test(literal)) ||
                (PAYMENT_STATUS_KEYS.has(key) && literal !== undefined && PAYMENT_STATUS_DONE_RE.test(literal)) ||
                (PAID_FLAG_KEYS.has(key) && value.type === "BooleanLiteral" && value.value) ||
                (PAID_AT_KEYS.has(key) && value.type !== "NullLiteral");
              if (marksPaid) {
                hits.push({
                  ruleId: "PAY-04",
                  line,
                  severity: "HIGH",
                  confidence: "MEDIUM",
                  message: `Order is marked paid (${key}) by an endpoint that never confirms the payment with the provider — anyone can call it (curl -X POST .../paid) and get the order without paying.`,
                  remediation: COPY["PAY-04"].remediation,
                  matchedText: key,
                });
              }
            }
            // PAY-06 — a request quantity written to the order.
            if (!validatesQuantity && kind === "db" && quantity.reads(property.value)) {
              quantityLine ??= line;
            }
          }
        },
        BinaryExpression(path) {
          // PAY-06 — a request quantity multiplied into a total.
          if (!validatesQuantity && path.node.operator === "*" && (quantity.reads(path.node.left) || quantity.reads(path.node.right))) {
            quantityLine ??= path.node.loc?.start.line;
          }
        },
        MemberExpression(path) {
          if (couponLine === undefined && coupon.reads(path.node)) {
            couponLine = path.node.loc?.start.line;
          }
        },
        VariableDeclarator(path) {
          // `const { couponCode } = await req.json()`
          const id = path.node.id;
          if (couponLine === undefined && id.type === "ObjectPattern" && id.properties.some((p) => p.type === "ObjectProperty" && p.value.type === "Identifier" && coupon.names.has(p.value.name))) {
            couponLine = path.node.loc?.start.line;
          }
        },
      });

      // PAY-04 — raw SQL that marks an order paid.
      if (!confirmsPayment) {
        for (const [index, text] of lines.entries()) {
          if (SQL_MARK_PAID_RE.test(text)) {
            hits.push({
              ruleId: "PAY-04",
              line: index + 1,
              severity: "HIGH",
              confidence: "MEDIUM",
              message: "Order is marked paid by an SQL update in an endpoint that never confirms the payment with the provider — anyone can call it and get the order without paying.",
              remediation: COPY["PAY-04"].remediation,
              matchedText: "status = 'paid'",
            });
          }
        }
      }

      // PAY-05 — a coupon from the request, applied with no redemption tracking.
      if (couponLine !== undefined && COUPON_CONTEXT_RE.test(content) && !REDEMPTION_TRACKING_RE.test(content)) {
        hits.push({
          ruleId: "PAY-05",
          line: couponLine,
          severity: "MEDIUM",
          confidence: "LOW",
          message: "Coupon / promo code is applied without recording or checking redemptions — the same code can be redeemed again and again (FREE10 applied 100 times), or replayed in parallel requests.",
          remediation: COPY["PAY-05"].remediation,
          matchedText: "coupon",
        });
      }

      // PAY-06 — one finding per file.
      if (quantityLine !== undefined) {
        hits.push({
          ruleId: "PAY-06",
          line: quantityLine,
          severity: "MEDIUM",
          confidence: "MEDIUM",
          message: "Quantity comes from the request and is never checked to be a positive whole number — ordering -1 items makes the total negative (a refund or store credit), and 0.5 items halves the price.",
          remediation: COPY["PAY-06"].remediation,
          matchedText: "quantity",
        });
      }

      return Promise.resolve(
        hits.map((hit) => ({
          ruleId: hit.ruleId,
          category: "payment",
          detectorName: "commerce-logic",
          file: ctx.filePath,
          line: hit.line,
          severity: hit.severity,
          confidence: hit.confidence,
          message: hit.message,
          remediation: hit.remediation,
          matchedText: hit.matchedText,
        })),
      );
    } catch {
      return Promise.resolve([]);
    }
  },
};

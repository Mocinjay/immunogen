// 8. Orders are marked paid only from a signature-verified Stripe webhook.
import Stripe from "stripe";
import { prisma } from "@/lib/db";

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY ?? "");

export async function POST(req: Request) {
  const body = await req.text();
  const signature = req.headers.get("stripe-signature") ?? "";
  const event = stripe.webhooks.constructEvent(body, signature, process.env.STRIPE_WEBHOOK_SECRET ?? "");
  if (event.type === "checkout.session.completed") {
    const checkout = event.data.object;
    await prisma.order.update({ where: { stripeSessionId: checkout.id }, data: { status: "paid" } });
  }
  return new Response(null, { status: 200 });
}

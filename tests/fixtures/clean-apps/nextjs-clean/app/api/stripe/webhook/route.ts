// PAY-01 must NOT fire: the handler verifies the signature via
// stripe.webhooks.constructEvent before trusting the event body.
import Stripe from "stripe";
import { NextResponse } from "next/server";

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY ?? "");

// Stripe webhook authenticates via signature verification (constructEvent
// below), not session/user auth — AUTH-01 does not apply to this handler.
// public
export async function POST(request: Request) {
  const rawBody = await request.text();
  const signature = request.headers.get("stripe-signature") ?? "";

  const event = stripe.webhooks.constructEvent(rawBody, signature, process.env.STRIPE_WEBHOOK_SECRET ?? "");

  if (event.type === "checkout.session.completed") {
    // handle the verified event
  }
  return NextResponse.json({ received: true });
}

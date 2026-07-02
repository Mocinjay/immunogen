// PAY-01: a Stripe webhook handler that imports stripe but never verifies
// the request signature — any caller can forge an event.
import Stripe from "stripe";
import { NextResponse } from "next/server";

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY ?? "");

export async function POST(request: Request) {
  const body = await request.json();
  // Trusts the raw event body directly with no signature verification.
  if (body.type === "checkout.session.completed") {
    console.log("payment completed", stripe.apiVersion);
  }
  return NextResponse.json({ received: true });
}

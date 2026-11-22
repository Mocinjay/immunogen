// 7. The price comes from our catalog, keyed by the plan id.
import { auth } from "@/auth";
import { prisma } from "@/lib/db";
import { stripe } from "@/lib/stripe";

export async function POST(req: Request) {
  const session = await auth();
  if (!session) return new Response("Unauthorized", { status: 401 });
  const { planId } = await req.json();
  const plan = await prisma.plan.findUnique({ where: { id: planId } });
  if (!plan) return new Response("Not found", { status: 404 });
  const checkout = await stripe.checkout.sessions.create({
    mode: "payment",
    line_items: [{ price: plan.stripePriceId, quantity: 1 }],
    client_reference_id: session.user.id,
    success_url: "https://yourapp.com/thanks",
  });
  return Response.json({ url: checkout.url });
}

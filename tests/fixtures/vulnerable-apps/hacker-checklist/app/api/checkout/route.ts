// 7. Edit the price — <span class="price">$0.01</span>, resend, pay a cent for a year of Pro.
import { auth } from "@/auth";
import { stripe } from "@/lib/stripe";

export async function POST(req: Request) {
  const session = await auth();
  if (!session) return new Response("Unauthorized", { status: 401 });
  const { planName, price } = await req.json();
  const checkout = await stripe.checkout.sessions.create({
    mode: "payment",
    line_items: [{ quantity: 1, price_data: { currency: "usd", product_data: { name: planName }, unit_amount: Math.round(price * 100) } }],
    success_url: "https://yourapp.com/thanks",
  });
  return Response.json({ url: checkout.url });
}

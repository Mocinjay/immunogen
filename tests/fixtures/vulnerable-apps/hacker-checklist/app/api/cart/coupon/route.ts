// 9. Redeem it 100 times — FREE10 applied, applied, applied...
import { auth } from "@/auth";
import { prisma } from "@/lib/db";

export async function POST(req: Request) {
  const session = await auth();
  if (!session) return new Response("Unauthorized", { status: 401 });
  const { couponCode } = await req.json();
  const coupon = await prisma.coupon.findUnique({ where: { code: couponCode } });
  if (!coupon) return Response.json({ error: "Invalid code" }, { status: 400 });
  const cart = await prisma.cart.update({
    where: { userId: session.user.id },
    data: { discountTotal: { push: coupon.amountOff } },
  });
  return Response.json(cart);
}

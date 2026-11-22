// 9. Each code is redeemed at most maxUses times, once per user, atomically.
import { auth } from "@/auth";
import { prisma } from "@/lib/db";

export async function POST(req: Request) {
  const session = await auth();
  if (!session) return new Response("Unauthorized", { status: 401 });
  const { couponCode } = await req.json();
  const redeemed = await prisma.$transaction(async (tx) => {
    const coupon = await tx.coupon.findUnique({ where: { code: couponCode } });
    if (!coupon || coupon.timesUsed >= coupon.maxUses) return null;
    await tx.couponRedemption.create({ data: { couponId: coupon.id, userId: session.user.id } });
    await tx.coupon.update({ where: { id: coupon.id }, data: { timesUsed: { increment: 1 } } });
    return coupon;
  });
  if (!redeemed) return Response.json({ error: "Invalid or used code" }, { status: 400 });
  return Response.json({ ok: true });
}

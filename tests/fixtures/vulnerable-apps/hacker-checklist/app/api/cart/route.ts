// 10. Order -1 items — Wireless headphones x -1 = Total -$49.00
import { auth } from "@/auth";
import { prisma } from "@/lib/db";

export async function POST(req: Request) {
  const session = await auth();
  if (!session) return new Response("Unauthorized", { status: 401 });
  const { productId, quantity } = await req.json();
  const product = await prisma.product.findUnique({ where: { id: productId } });
  if (!product) return new Response("Not found", { status: 404 });
  const order = await prisma.order.create({
    data: { userId: session.user.id, productId, quantity, total: product.price * quantity },
  });
  return Response.json(order);
}

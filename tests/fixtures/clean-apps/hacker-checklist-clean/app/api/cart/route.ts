// 10. Quantities are positive whole numbers, prices come from the server.
import { z } from "zod";
import { auth } from "@/auth";
import { prisma } from "@/lib/db";

const AddToCart = z.object({ productId: z.string(), quantity: z.number().int().min(1).max(10) });

export async function POST(req: Request) {
  const session = await auth();
  if (!session) return new Response("Unauthorized", { status: 401 });
  const { productId, quantity } = AddToCart.parse(await req.json());
  const product = await prisma.product.findUnique({ where: { id: productId } });
  if (!product) return new Response("Not found", { status: 404 });
  const order = await prisma.order.create({
    data: { userId: session.user.id, productId, quantity, total: product.price * quantity },
  });
  return Response.json(order);
}

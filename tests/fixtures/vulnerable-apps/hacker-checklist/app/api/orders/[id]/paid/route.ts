// 8. Fake a payment — curl -X POST yourapp.com/api/orders/1042/paid  ->  { "status": "paid", "shipped": true }
import { auth } from "@/auth";
import { prisma } from "@/lib/db";

export async function POST(req: Request, { params }: { params: { id: string } }) {
  const session = await auth();
  if (!session) return new Response("Unauthorized", { status: 401 });
  const order = await prisma.order.update({
    where: { id: params.id, userId: session.user.id },
    data: { status: "paid", shipped: true },
  });
  return Response.json(order);
}

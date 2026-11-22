// 3. Admin API checks the role itself, too.
import { auth } from "@/auth";
import { prisma } from "@/lib/db";

export async function DELETE(req: Request) {
  const session = await auth();
  if (session?.user.role !== "admin") return new Response("Forbidden", { status: 403 });
  const { userId } = await req.json();
  await prisma.user.delete({ where: { id: userId } });
  return new Response(null, { status: 204 });
}

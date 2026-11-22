// 3. Type /admin — "Delete all users" only checks that someone is signed in.
import { auth } from "@/auth";
import { prisma } from "@/lib/db";

export async function DELETE() {
  const session = await auth();
  if (!session) return new Response("Unauthorized", { status: 401 });
  await prisma.user.deleteMany();
  return new Response(null, { status: 204 });
}

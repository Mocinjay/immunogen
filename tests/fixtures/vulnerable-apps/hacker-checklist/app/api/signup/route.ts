// 6. Admin at signup — POST /api/signup { "email": "me@mail.com", "password": "...", "role": "admin" }
import { prisma } from "@/lib/db";
import { hash } from "@/lib/password";

export async function POST(req: Request) {
  const { email, password, role } = await req.json();
  const user = await prisma.user.create({ data: { email, passwordHash: await hash(password), role } });
  return Response.json({ id: user.id });
}

// 6. Only the fields a new user may set; the role is assigned on the server.
import { z } from "zod";
import { prisma } from "@/lib/db";
import { hash } from "@/lib/password";

const SignUp = z.object({ email: z.string().email(), password: z.string().min(12) }).strict();

export async function POST(req: Request) {
  const { email, password } = SignUp.parse(await req.json());
  const user = await prisma.user.create({ data: { email, passwordHash: await hash(password), role: "user" } });
  return Response.json({ id: user.id });
}

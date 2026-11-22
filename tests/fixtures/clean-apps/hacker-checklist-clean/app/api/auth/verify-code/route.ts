// 11. Five attempts per code (plus the global rate limit in middleware.ts), then it is burned.
import { timingSafeEqual } from "node:crypto";
import { prisma } from "@/lib/db";
import { createSession } from "@/lib/session";

export async function POST(req: Request) {
  const { email, code } = await req.json();
  const user = await prisma.user.findUnique({ where: { email } });
  if (!user || user.loginCodeAttempts >= 5) return Response.json({ error: "Request a new code" }, { status: 429 });
  const ok = user.loginCode.length === code.length && timingSafeEqual(Buffer.from(user.loginCode), Buffer.from(code));
  if (!ok) {
    await prisma.user.update({ where: { id: user.id }, data: { loginCodeAttempts: { increment: 1 } } });
    return Response.json({ error: "Wrong code. Try again." }, { status: 401 });
  }
  return createSession(user.id);
}

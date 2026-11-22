// 11. Guess the login code — ...checked with no attempt limit. "Wrong code. Try again. Attempt 418"
import { prisma } from "@/lib/db";
import { createSession } from "@/lib/session";

export async function POST(req: Request) {
  const { email, code } = await req.json();
  const user = await prisma.user.findUnique({ where: { email } });
  if (!user || user.loginCode !== code) {
    return Response.json({ error: "Wrong code. Try again." }, { status: 401 });
  }
  return createSession(user.id);
}

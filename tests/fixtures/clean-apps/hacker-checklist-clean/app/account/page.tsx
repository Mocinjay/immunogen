// 2. The account shown is always the caller's own.
import { auth } from "@/auth";
import { prisma } from "@/lib/db";

export default async function AccountPage() {
  const session = await auth();
  if (!session) return null;
  const account = await prisma.account.findFirst({ where: { userId: session.user.id } });
  return <pre>{JSON.stringify(account)}</pre>;
}

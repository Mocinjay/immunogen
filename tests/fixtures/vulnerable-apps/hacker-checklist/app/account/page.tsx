// 2. Change the ID in the URL — yourapp.com/account?id=1043 shows someone else's account.
import { auth } from "@/auth";
import { prisma } from "@/lib/db";

export default async function AccountPage({ searchParams }: { searchParams: Promise<{ id: string }> }) {
  const session = await auth();
  if (!session) return null;
  const { id } = await searchParams;
  const account = await prisma.account.findFirst({ where: { id: Number(id) } });
  return <pre>{JSON.stringify(account)}</pre>;
}

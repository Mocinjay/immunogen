import { prisma } from "@/lib/db";

export default async function AdminPage() {
  const users = await prisma.user.findMany({ select: { id: true, email: true } });
  return <ul>{users.map((user) => <li key={user.id}>{user.email}</li>)}</ul>;
}

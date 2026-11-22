// 3. Type /admin — the admin dashboard has no role check.
import { prisma } from "@/lib/db";

export default async function AdminPage() {
  const users = await prisma.user.findMany();
  return <ul>{users.map((user) => <li key={user.id}>{user.email}</li>)}</ul>;
}

// 12. Bound parameters, never spliced SQL.
import { pool } from "@/lib/pg";

// public: product search is open to everyone
export async function GET(req: Request) {
  const q = new URL(req.url).searchParams.get("q") ?? "";
  const { rows } = await pool.query("SELECT id, name, price FROM products WHERE name ILIKE $1", [`%${q}%`]);
  return Response.json(rows);
}

// 12. Query your database — search for: ' OR 1=1; DROP TABLE users;--
import { pool } from "@/lib/pg";

// public: product search is open to everyone
export async function GET(req: Request) {
  const q = new URL(req.url).searchParams.get("q") ?? "";
  const sql = `SELECT id, name, price FROM products WHERE name LIKE '%${q}%'`;
  const { rows } = await pool.query(sql);
  return Response.json(rows);
}

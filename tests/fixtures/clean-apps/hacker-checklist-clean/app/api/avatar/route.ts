// 14. Images only, renamed on the server.
import { randomUUID } from "node:crypto";
import { writeFile } from "node:fs/promises";
import path from "node:path";
import { auth } from "@/auth";

const ALLOWED_TYPES: Record<string, string> = { "image/png": "png", "image/jpeg": "jpg", "image/webp": "webp" };

export async function POST(req: Request) {
  const session = await auth();
  if (!session) return new Response("Unauthorized", { status: 401 });
  const formData = await req.formData();
  const file = formData.get("avatar") as File;
  const extension = ALLOWED_TYPES[file.type];
  if (!extension) return new Response("Images only", { status: 415 });
  const storedName = `${randomUUID()}.${extension}`;
  await writeFile(path.join(process.env.UPLOAD_DIR ?? "/var/uploads", storedName), Buffer.from(await file.arrayBuffer()));
  return Response.json({ name: storedName });
}

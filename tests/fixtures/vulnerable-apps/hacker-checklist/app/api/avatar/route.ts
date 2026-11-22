// 14. Upload a non-photo — selfie.jpg.php is saved as-is under public/uploads.
import { writeFile } from "node:fs/promises";
import path from "node:path";
import { auth } from "@/auth";

export async function POST(req: Request) {
  const session = await auth();
  if (!session) return new Response("Unauthorized", { status: 401 });
  const formData = await req.formData();
  const file = formData.get("avatar") as File;
  const bytes = Buffer.from(await file.arrayBuffer());
  await writeFile(path.join(process.cwd(), "public/uploads", file.name), bytes);
  return Response.json({ url: `/uploads/${file.name}` });
}

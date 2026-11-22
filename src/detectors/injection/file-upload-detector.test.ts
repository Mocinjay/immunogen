import { describe, expect, it } from "vitest";

import { fileUploadDetector } from "./file-upload-detector.js";

import type { DetectorContext, StackHints } from "../../core/types.js";

const STACK_HINTS: StackHints = {
  frameworks: new Set(),
  hasSupabase: false,
  hasFirebase: false,
  hasStripe: false,
  hasEnvFiles: false,
  hasMcpJson: false,
  hasClaudeSkills: false,
  hasCursorRules: false,
};

const lines = (...parts: string[]): string => parts.join("\n");

async function summarize(content: string, filePath: string): Promise<string[]> {
  const ctx: DetectorContext = { filePath, content, stackHints: STACK_HINTS, fileSet: new Map([[filePath, content]]) };
  const findings = await fileUploadDetector.detect(ctx);
  return findings.map((finding) => `${finding.ruleId} ${finding.severity} L${finding.line}`);
}

describe("fileUploadDetector — UPLOAD-01 flags", () => {
  it("flags a Next.js avatar route that writes file.name to disk with no type check (selfie.jpg.php)", async () => {
    const code = lines(
      "export async function POST(req: Request) {",
      "  const formData = await req.formData();",
      '  const file = formData.get("avatar") as File;',
      "  const bytes = Buffer.from(await file.arrayBuffer());",
      '  await writeFile(path.join(process.cwd(), "public/uploads", file.name), bytes);',
      "}",
    );
    expect(await summarize(code, "app/api/avatar/route.ts")).toEqual(["UPLOAD-01 HIGH L5", "UPLOAD-01 MEDIUM L3"]);
  });

  it("flags multer diskStorage keeping the original name, without a fileFilter", async () => {
    const code = lines(
      'const storage = multer.diskStorage({ destination: "uploads/", filename: (req, file, cb) => cb(null, Date.now() + "-" + file.originalname) });',
      "const upload = multer({ storage });",
      'app.post("/api/profile-photo", upload.single("photo"), (req, res) => res.json({ ok: true }));',
    );
    expect(await summarize(code, "server/upload.ts")).toEqual(["UPLOAD-01 HIGH L1", "UPLOAD-01 MEDIUM L2"]);
  });

  it("flags a Supabase storage upload keyed by the client file name", async () => {
    const code = lines(
      '"use server";',
      "export async function uploadAvatar(formData: FormData) {",
      '  const file = formData.get("file") as File;',
      '  if (!file.type.startsWith("image/")) throw new Error("images only");',
      '  await supabase.storage.from("avatars").upload(`${user.id}/${file.name}`, file);',
      "}",
    );
    expect(await summarize(code, "app/profile/actions.ts")).toEqual(["UPLOAD-01 HIGH L5"]);
  });

  it("flags Flask saving request.files with the raw filename and no extension check", async () => {
    const code = lines("@app.post('/upload')", "def upload():", "    f = request.files['photo']", "    f.save(os.path.join(UPLOAD_FOLDER, f.filename))");
    expect(await summarize(code, "app.py")).toEqual(["UPLOAD-01 HIGH L4", "UPLOAD-01 MEDIUM L3"]);
  });
});

describe("fileUploadDetector — UPLOAD-01 stays quiet", () => {
  it.each([
    [
      "a type allowlist and a server-generated name",
      "app/api/avatar/route.ts",
      lines(
        "export async function POST(req: Request) {",
        '  const file = (await req.formData()).get("avatar") as File;',
        '  if (!ALLOWED_TYPES.includes(file.type)) return new Response("Unsupported", { status: 415 });',
        "  await writeFile(path.join(UPLOAD_DIR, `${crypto.randomUUID()}.png`), Buffer.from(await file.arrayBuffer()));",
        "}",
      ),
    ],
    [
      "multer with a fileFilter and uuid names",
      "server/upload.ts",
      lines(
        "const upload = multer({",
        "  storage: multer.diskStorage({ filename: (req, file, cb) => cb(null, uuid() + path.extname(file.originalname)) }),",
        '  fileFilter: (req, file, cb) => cb(null, ["image/png", "image/jpeg"].includes(file.mimetype)),',
        "});",
      ),
    ],
    [
      "Flask with secure_filename and allowed_file",
      "app.py",
      lines("f = request.files['photo']", "if f and allowed_file(f.filename):", "    f.save(os.path.join(UPLOAD_FOLDER, secure_filename(f.filename)))"),
    ],
    [
      "a client component that only appends a file to form data",
      "components/AvatarForm.tsx",
      lines('"use client";', 'const file = form.get("avatar") as File;', 'fd.append("avatar", file, file.name);'),
    ],
    ["a non-upload route", "app/api/users/route.ts", "export async function GET() { return Response.json(await getUsers()); }"],
    [
      "a FastAPI upload written to a server-generated path and never named by the client",
      "server/main.py",
      lines("async def caption(file: UploadFile):", "    job_dir = WORK_DIR / uuid.uuid4().hex", "    (job_dir / 'in.mp4').write_bytes(await file.read())"),
    ],
  ])("does NOT flag %s", async (_label, filePath, code) => {
    expect(await summarize(code, filePath)).toEqual([]);
  });
});

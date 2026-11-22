/**
 * fileUploadDetector — UPLOAD-01: unrestricted file upload. "Upload a
 * non-photo": a profile-photo endpoint that accepts `selfie.jpg.php`,
 * `avatar.html`, or `../../app/page.js` because it never checks what the
 * file is and stores it under the name the client chose.
 *
 * Two findings per upload handler (JS/TS via text over the file; Python
 * Flask / FastAPI via text):
 *   - HIGH/MEDIUM (once per file) — the client's file name is used as the storage path or
 *     key (`file.originalname`, `file.name`, `upload.filename` inside
 *     `writeFile` / `createWriteStream` / `path.join` / a multer
 *     `diskStorage` filename callback / Supabase `.upload()` / S3 `Key:` /
 *     Vercel Blob `put()` / Firebase `ref()`; Python `os.path.join` /
 *     `open()` / `.save()` without `secure_filename`): the client picks the
 *     extension (`.php`, `.html`, `.svg` -> stored XSS or code execution)
 *     and can traverse directories (`../`). A server-generated name (uuid,
 *     nanoid, `crypto.randomUUID`, a sanitizer) on that line clears it.
 *   - MEDIUM/MEDIUM — no file-type validation anywhere in the file: no
 *     multer `fileFilter`, MIME / extension allowlist, `file.type` check,
 *     magic-byte sniffing (`file-type`), or image re-encoding (`sharp`).
 *     Not reported when the upload is stored under a server-generated name
 *     (uuid, nanoid, ...) and the client's file name is never read: such a
 *     file cannot be executed or served as HTML by its extension.
 *
 * An upload handler is a file that uses multer / formidable / busboy /
 * express-fileupload, reads `req.file(s)`, or pulls a file field out of
 * `formData()` in a server entry point; Python files that read
 * `request.files` or take an `UploadFile`.
 *
 * Text-only (ENG-05); no-throw contract.
 */
import { isTestOrFixturePath } from "../shared/test-paths.js";
import { isClientModule, isServerEntryFile } from "../shared/server-entry.js";

import type { Detector, DetectorContext, Finding } from "../../core/types.js";

/** A JS/TS upload handler: upload middleware, `req.file(s)`, or a File pulled from form data. */
const JS_UPLOAD_SOURCE_RE =
  /\bmulter\s*\(|\bformidable\s*\(|\bnew\s+(?:formidable\.)?IncomingForm\b|\bbusboy\b|\bBusboy\s*\(|express-fileupload|\breq\.files?\b|\brequest\.files?\b|\bformData\.get(?:All)?\(\s*["'`](?:file|files|image|images|avatar|photo|picture|upload|attachment|document|logo|video|media|resume|cv)["'`]\s*\)|\binstanceof\s+File\b|\bas\s+File\b/;

/** Python upload handler. */
const PY_UPLOAD_SOURCE_RE = /\brequest\.files\b|\bUploadFile\b|\bFileStorage\b/;

/** The client-chosen file name, read off an upload object. */
const JS_CLIENT_NAME_RE =
  /\b(?:file|files\[\d+\]|upload|uploaded\w*|image|avatar|photo|picture|attachment|document|doc|f|blob|item|media)\??\.(?:originalname|originalName|originalFilename|name|filename|newFilename)\b/;

/** Storage sinks a client file name must not flow into (on the same line). */
const JS_STORAGE_SINK_RE =
  /\bwriteFile(?:Sync)?\s*\(|\bcreateWriteStream\s*\(|\bBun\.write\s*\(|\bpath\.(?:join|resolve)\s*\(|\bjoin\s*\(|\.upload\s*\(|\bput\s*\(|\bKey\s*:|\buploadBytes(?:Resumable)?\s*\(|\bref\s*\(\s*storage|\bcb\s*\(\s*null\s*,|\bcallback\s*\(\s*null\s*,|\bmv\s*\(|\buploadDir\b|\bpathname\s*:|`[^`]*\/\$\{/;

/** A server-generated or sanitized name on the same line. */
const SAFE_NAME_RE = /sanitize|randomUUID|\buuid|\bv4\(|nanoid|\bcuid|createId|crypto\.random|randomBytes|slugify|secure_filename/i;

/** Any file-type validation in a JS/TS file. */
const JS_TYPE_CHECK_RE =
  /fileFilter|mimetype|mimeType|\.type\s*(?:===|!==|==|!=)|\.type\??\.(?:startsWith|includes|match|endsWith)\(|(?:allowed|accepted|valid)_?(?:Types|Mime\w*|Extensions?|Exts?|Formats|ContentTypes)|(?:ALLOWED|ACCEPTED|VALID)_(?:TYPES|MIME\w*|EXTENSIONS?|EXTS?|FORMATS|CONTENT_TYPES)|allowedContentTypes|fileTypeFrom\w*\(|from\s+["']file-type["']|magic-bytes|\bsharp\s*\(|\.(?:endsWith|test)\([^)\n]*(?:png|jpe?g|webp|gif|pdf)|image\/(?:png|jpe?g|webp|gif|\*)/i;

/** Client name used in a Python storage path, without secure_filename. */
const PY_CLIENT_NAME_SINK_RE = /(?:os\.path\.join|open|\.save|Path|shutil\.copyfileobj|aiofiles\.open)\s*\([^\n]*\.filename\b|f["'][^"'\n]*\{[^}\n]*\.filename\}/;

/** Any file-type validation in a Python file. */
const PY_TYPE_CHECK_RE = /allowed_file|ALLOWED_(?:EXTENSIONS|TYPES|MIME\w*)|content_type|mimetype|imghdr|\bmagic\.|filetype\.|Image\.open|\.endswith\(|splitext|guess_type/;

/** 1-indexed line of the first match of `re` in `lines`. */
function firstLine(lines: readonly string[], re: RegExp): number {
  const index = lines.findIndex((line) => re.test(line));
  return index === -1 ? 1 : index + 1;
}

export const fileUploadDetector: Detector = {
  config: {
    name: "file-upload",
    category: "injection",
    globs: ["**/*.{ts,tsx,js,jsx,mjs,cjs,mts,cts,py}"],
  },

  detect(ctx: DetectorContext): Promise<Finding[]> {
    try {
      if (isTestOrFixturePath(ctx.filePath)) {
        return Promise.resolve([]);
      }
      const content = ctx.content;
      const python = ctx.filePath.endsWith(".py");
      if (python ? !PY_UPLOAD_SOURCE_RE.test(content) : !JS_UPLOAD_SOURCE_RE.test(content)) {
        return Promise.resolve([]);
      }
      if (!python && (isClientModule(content) || (!isServerEntryFile(ctx.filePath, content) && !/\bmulter\s*\(|formidable|busboy|express-fileupload/i.test(content)))) {
        return Promise.resolve([]);
      }

      const lines = content.split("\n");
      const findings: Finding[] = [];
      const push = (line: number, severity: "HIGH" | "MEDIUM", message: string, remediation: string, matchedText: string): void => {
        findings.push({
          ruleId: "UPLOAD-01",
          category: "injection",
          detectorName: "file-upload",
          file: ctx.filePath,
          line,
          severity,
          confidence: "MEDIUM",
          message,
          remediation,
          matchedText,
        });
      };

      // Client-chosen file name used as the storage path / key — reported once per file, on its first use.
      for (const [index, line] of lines.entries()) {
        if (findings.length > 0) {
          break;
        }
        const clientName = python
          ? PY_CLIENT_NAME_SINK_RE.test(line) && !/secure_filename/.test(line)
          : JS_CLIENT_NAME_RE.test(line) && JS_STORAGE_SINK_RE.test(line) && !SAFE_NAME_RE.test(line);
        if (clientName) {
          push(
            index + 1,
            "HIGH",
            "Uploaded file is stored under the name the client sent — the client picks the extension (selfie.jpg.php, avatar.html, logo.svg) and can climb directories with ../, turning a photo upload into stored XSS or code execution.",
            python
              ? "Generate the stored name on the server (uuid4().hex plus an extension from your allowlist), or at minimum pass it through werkzeug's secure_filename, and keep uploads outside the web root."
              : "Generate the stored name on the server (crypto.randomUUID() plus an extension from your allowlist) instead of file.name / file.originalname, keep uploads outside your web root, and serve them with Content-Disposition: attachment or from a separate domain.",
            line.match(python ? /\w+\.filename/ : JS_CLIENT_NAME_RE)?.[0] ?? "filename",
          );
        }
      }

      // No file-type validation at all. Skipped when the file is stored under a
      // server-generated name and the client's name / extension is never read:
      // it can then be neither executed nor served as HTML by extension.
      const checksType = python ? PY_TYPE_CHECK_RE.test(content) : JS_TYPE_CHECK_RE.test(content);
      const readsClientName = python ? /\.filename\b/.test(content) : JS_CLIENT_NAME_RE.test(content);
      const serverNamed = SAFE_NAME_RE.test(content) && !readsClientName;
      if (!checksType && !serverNamed) {
        push(
          firstLine(lines, python ? PY_UPLOAD_SOURCE_RE : JS_UPLOAD_SOURCE_RE),
          "MEDIUM",
          "File upload accepts any file type — nothing checks the upload is the kind of file you expect, so a \"photo\" that is really HTML, SVG with script, or a server script gets stored and served.",
          python
            ? "Allow only the extensions and content types you need (ALLOWED_EXTENSIONS), verify the bytes (python-magic / Pillow Image.open), cap the size, and re-encode images before storing them."
            : "Allow only the types you need — check the extension against an allowlist and the file's magic bytes (file-type), not just the client-sent MIME type — cap the size (multer limits), and re-encode images (sharp) before storing them.",
          "upload",
        );
      }
      return Promise.resolve(findings);
    } catch {
      return Promise.resolve([]);
    }
  },
};

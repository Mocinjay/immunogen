/**
 * FileWalker — the ingestion layer's filter.
 *
 * `walkFiles(rootDir, options)` walks a directory tree and returns exactly
 * the `Map<relativePath, rawText>` a detector should see: ScanContext.fileSet
 * (see src/core/types.ts). It hard-excludes universal noise directories
 * (`node_modules/`, `.next/`, `dist/`, `build/`, `.git/`, ...), applies
 * `.gitignore` via the `ignore` package, skips binaries and over-cap files —
 * BUT always preserves the high-signal security files (`.env*`, `.mcp.json`,
 * `.cursor/mcp.json`, `.cursor/rules`, `.cursor/rules/**`, `.claude/**`) even
 * when `.gitignore` would exclude them, because the secrets and AI-layer
 * detectors need them. See .planning/research/ARCHITECTURE.md ("File Walker
 * Rules") and .planning/research/PITFALLS.md (Pitfall 2, Pitfall 11) for the
 * rationale behind each rule below.
 *
 * Total-repo bounds (belt-and-suspenders alongside the per-file size cap):
 * once either `maxTotalBytes` or `maxTotalFiles` is exceeded, the walker
 * stops reading further files and returns whatever it already read, plus a
 * single `SCAN_TRUNCATED` `Diagnostic` (`diagnostics`, alongside `fileSet`)
 * so callers can surface a degraded/partial scan — this never throws.
 *
 * Security-critical: `followSymbolicLinks: false` is load-bearing (T-03-05 —
 * a symlink pointing at /etc/shadow must never be followed or read). This
 * module never imports child_process and never exec/spawn/eval/requires a
 * scanned file (ENG-05).
 */
import fg from "fast-glob";
import ignore from "ignore";
import { readFile } from "node:fs/promises";
import { extname, join } from "node:path";

import type { Diagnostic, ScanOptions } from "../types.js";

/** Default per-file size cap, in bytes (overridable via ScanOptions). */
const DEFAULT_MAX_FILE_SIZE_BYTES = 512 * 1024;

/** Default total-repo byte cap across all read files (overridable via ScanOptions.maxTotalBytes). */
const DEFAULT_MAX_TOTAL_BYTES = 50 * 1024 * 1024;

/** Default total-repo file-count cap (overridable via ScanOptions.maxTotalFiles). */
const DEFAULT_MAX_TOTAL_FILES = 25_000;

/** Stable diagnostic code emitted when the total-repo cap truncates the walk before every candidate file was read. */
const SCAN_TRUNCATED_CODE = "SCAN_TRUNCATED";

/** Number of leading bytes sniffed for a NUL byte when detecting binaries. */
const BINARY_SNIFF_BYTES = 8192;

/**
 * Hard-coded, non-configurable exclude-dir list. Applied at the fast-glob
 * level so the walker never descends into these directories at all —
 * critical for monorepo performance (PITFALLS Pitfall 2: a naive walk into
 * node_modules/.next/dist on a Turbo monorepo can be millions of files).
 */
const HARD_EXCLUDE_DIRS = [
  "node_modules",
  ".git",
  ".next",
  ".nuxt",
  "dist",
  "build",
  "out",
  ".turbo",
  ".cache",
  "coverage",
  ".nyc_output",
  "storybook-static",
  ".svelte-kit",
  ".venv",
  "venv",
  "Pods", // CocoaPods' vendored-dependency directory (iOS/macOS) — never developer-authored, analogous to node_modules.
];

/** fast-glob `ignore` patterns matching each hard-excluded directory anywhere in the tree. */
const HARD_EXCLUDE_GLOBS = HARD_EXCLUDE_DIRS.map((dir) => `**/${dir}/**`);

/**
 * Binary asset extensions that might slip past the NUL-byte content sniff
 * (e.g. an SVG is technically text but is not source code; a small icon
 * might not contain a NUL in its first 8KB). Checked without the leading
 * dot — see `BINARY_EXT_BLOCKLIST.has(extname(path).slice(1))`.
 */
const BINARY_EXT_BLOCKLIST = new Set([
  "png",
  "jpg",
  "jpeg",
  "gif",
  "ico",
  "svg",
  "webp",
  "woff",
  "woff2",
  "ttf",
  "eot",
  "otf",
  "mp4",
  "mov",
  "webm",
  "mp3",
  "wav",
  "zip",
  "tar",
  "gz",
  "pdf",
  "wasm",
]);

/** Exact relative paths always preserved even when `.gitignore` lists them. */
const ALWAYS_PRESERVE_EXACT = new Set([
  ".mcp.json",
  ".cursor/mcp.json",
  ".cursor/rules",
  ".cursorrules",
]);

/** Relative-path prefixes (directories) always preserved even when `.gitignore` lists them. */
const ALWAYS_PRESERVE_PREFIXES = [".cursor/rules/", ".claude/"];

/**
 * The criterion-3 nuance: `.env`, `.env.*`, `.mcp.json`, `.cursor/mcp.json`,
 * `.cursor/rules` (both the legacy single file and the modern per-file
 * `.mdc` directory form), `.cursorrules`, and anything under `.claude/` are
 * high-signal security files for this scanner (secrets + AI-layer
 * detection) and must survive even when a developer's `.gitignore` excludes
 * them — a gitignored `.env` is exactly the kind of file the secrets
 * detector exists to catch.
 */
function isAlwaysPreserved(relPath: string): boolean {
  if (ALWAYS_PRESERVE_EXACT.has(relPath)) {
    return true;
  }
  if (ALWAYS_PRESERVE_PREFIXES.some((prefix) => relPath.startsWith(prefix))) {
    return true;
  }
  const basename = relPath.slice(relPath.lastIndexOf("/") + 1);
  return basename === ".env" || basename.startsWith(".env.");
}

/**
 * Loads `.gitignore` at `rootDir` if present and returns a populated
 * `ignore()` instance. Returns an empty (no-op) instance when no
 * `.gitignore` exists — every `.ignores()` call then returns false.
 */
async function loadGitignore(rootDir: string): Promise<ignore.Ignore> {
  const matcher = ignore();
  try {
    const gitignorePath = join(rootDir, ".gitignore");
    // eslint-disable-next-line security/detect-non-literal-fs-filename -- walker reads caller-supplied repo paths by design
    const contents = await readFile(gitignorePath, "utf8");
    matcher.add(contents);
  } catch {
    // No .gitignore at rootDir (or unreadable) — proceed with no gitignore rules.
  }
  return matcher;
}

/**
 * Reads `path` and reports whether it should be skipped as binary or
 * over-cap, returning its text content when it survives both checks.
 * Returns `undefined` when the file should be skipped.
 */
async function readIfEligible(
  absPath: string,
  maxFileSizeBytes: number,
): Promise<string | undefined> {
  // eslint-disable-next-line security/detect-non-literal-fs-filename -- walker reads caller-supplied repo paths by design
  const buffer = await readFile(absPath);

  if (buffer.length > maxFileSizeBytes) {
    return undefined;
  }

  const sniffLength = Math.min(buffer.length, BINARY_SNIFF_BYTES);
  const sniffWindow = buffer.subarray(0, sniffLength);
  if (sniffWindow.includes(0x00)) {
    return undefined;
  }

  return buffer.toString("utf8");
}

/**
 * Walks `rootDir` and returns a `Map<relativePath, rawText>` of exactly the
 * files a detector should see, plus any `Diagnostic[]` warnings. Order of
 * rules applied per candidate path (ARCHITECTURE.md "File Walker Rules"):
 *
 * 1. Hard-coded blocklist directories never visited (glob-level `ignore`).
 * 2. `.gitignore` applied via the `ignore` package — UNLESS the path is in
 *    the always-preserve allowlist, which bypasses this check entirely.
 * 3. Binary extension blocklist.
 * 4. Size cap (`options.maxFileSizeBytes ?? 512KB`).
 * 5. Binary content sniff (NUL byte in the first 8KB).
 * 6. Total-repo caps (`options.maxTotalBytes ?? 50MB`, `options.maxTotalFiles
 *    ?? 25,000`) — checked BEFORE each file is read; once either is
 *    exceeded, the walk stops reading further candidates and returns
 *    whatever was already accumulated, plus a single `SCAN_TRUNCATED`
 *    diagnostic. This never throws.
 *
 * Never follows symlinks (`followSymbolicLinks: false` — T-03-05).
 */
export async function walkFiles(
  rootDir: string,
  options?: ScanOptions,
): Promise<{ fileSet: Map<string, string>; diagnostics: Diagnostic[] }> {
  const maxFileSizeBytes = options?.maxFileSizeBytes ?? DEFAULT_MAX_FILE_SIZE_BYTES;
  const maxTotalBytes = options?.maxTotalBytes ?? DEFAULT_MAX_TOTAL_BYTES;
  const maxTotalFiles = options?.maxTotalFiles ?? DEFAULT_MAX_TOTAL_FILES;
  const fileSet = new Map<string, string>();
  const diagnostics: Diagnostic[] = [];
  let totalBytesRead = 0;

  const gitignoreMatcher = await loadGitignore(rootDir);

  const candidates = await fg("**/*", {
    cwd: rootDir,
    dot: true,
    onlyFiles: true,
    followSymbolicLinks: false,
    absolute: false,
    ignore: HARD_EXCLUDE_GLOBS,
  });

  for (const relPath of candidates) {
    if (totalBytesRead >= maxTotalBytes || fileSet.size >= maxTotalFiles) {
      diagnostics.push({
        level: "warn",
        code: SCAN_TRUNCATED_CODE,
        message:
          "Total-repo scan cap exceeded; the file walk stopped early and results may be incomplete.",
      });
      break;
    }

    const preserved = isAlwaysPreserved(relPath);

    if (!preserved && gitignoreMatcher.ignores(relPath)) {
      continue;
    }

    if (!preserved) {
      const ext = extname(relPath).slice(1).toLowerCase();
      if (BINARY_EXT_BLOCKLIST.has(ext)) {
        continue;
      }
    }

    const absPath = join(rootDir, relPath);
    const content = await readIfEligible(absPath, maxFileSizeBytes);
    if (content === undefined) {
      continue;
    }

    fileSet.set(relPath, content);
    totalBytesRead += Buffer.byteLength(content, "utf8");
  }

  return { fileSet, diagnostics };
}

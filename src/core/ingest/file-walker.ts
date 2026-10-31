/**
 * FileWalker — the ingestion layer's filter.
 *
 * `walkFiles(rootDir, options)` walks a directory tree and returns exactly
 * the `Map<relativePath, rawText>` a detector should see: ScanContext.fileSet
 * (see src/core/types.ts). It hard-excludes universal noise directories
 * (`node_modules/`, `.next/`, `dist/`, `build/`, `.git/`, ...), applies
 * every `.gitignore` in the tree (root and nested, each scoped to its own
 * directory) via the `ignore` package, skips binaries and over-cap files —
 * BUT always preserves the AI-layer files (`.mcp.json`, `.cursor/mcp.json`,
 * `.cursor/rules`, `.cursor/rules/**`, `.claude/**`) even when `.gitignore`
 * would exclude them, because a local agent still loads them.
 *
 * Environment files (`.env*`) follow the question that actually matters for
 * a leak — is this file committed? Inside a git work tree, a TRACKED env
 * file is always kept (a `.env` committed once and gitignored later is still
 * in the repo), while an untracked one is kept only when `.gitignore` does
 * not exclude it (it would be committed by the next `git add .`). Outside a
 * git work tree, `.gitignore` is the only signal. A gitignored, untracked
 * `.env.local` holding real keys is the correct local setup and is never
 * scanned. Tracked paths come from `readTrackedFiles` (git-index.ts), which
 * parses `.git/index` directly instead of running git. Each rule's
 * rationale is noted where it is applied below.
 *
 * Total-repo bounds (belt-and-suspenders alongside the per-file size cap):
 * once either `maxTotalBytes` or `maxTotalFiles` is exceeded, the walker
 * stops reading further files and returns whatever it already read, plus a
 * single `SCAN_TRUNCATED` `Diagnostic` (`diagnostics`, alongside `fileSet`)
 * so callers can surface a degraded/partial scan — this never throws.
 *
 * Security-critical: `followSymbolicLinks: false` is load-bearing (a
 * symlink pointing at /etc/shadow must never be followed or read). This
 * module never imports child_process and never exec/spawn/eval/requires a
 * scanned file (ENG-05).
 */
import fg from "fast-glob";
import ignore from "ignore";
import { readFile, stat } from "node:fs/promises";
import { extname, join } from "node:path";

import { readTrackedFiles } from "./git-index.js";

import type { Diagnostic, ScanOptions } from "../types.js";

/** Default per-file size cap, in bytes (overridable via ScanOptions). */
const DEFAULT_MAX_FILE_SIZE_BYTES = 512 * 1024;

/**
 * Per-file cap for package-manager lockfiles. A real app's
 * package-lock.json / pnpm-lock.yaml routinely exceeds the default cap, and
 * it is the only record of the exact (and transitive) versions installed,
 * which the dependency check reads.
 */
const LOCKFILE_MAX_FILE_SIZE_BYTES = 16 * 1024 * 1024;

/** Lockfile basenames that get LOCKFILE_MAX_FILE_SIZE_BYTES. */
const LOCKFILE_BASENAMES = new Set([
  "package-lock.json",
  "npm-shrinkwrap.json",
  "pnpm-lock.yaml",
  "yarn.lock",
  "bun.lock",
  "poetry.lock",
  "uv.lock",
  "Pipfile.lock",
]);

/** Default total-repo byte cap across all read files (overridable via ScanOptions.maxTotalBytes). */
const DEFAULT_MAX_TOTAL_BYTES = 50 * 1024 * 1024;

/** Default total-repo file-count cap (overridable via ScanOptions.maxTotalFiles). */
const DEFAULT_MAX_TOTAL_FILES = 25_000;

/** Stable diagnostic code emitted when the total-repo cap truncates the walk before every candidate file was read. */
const SCAN_TRUNCATED_CODE = "SCAN_TRUNCATED";

/** Stable diagnostic code summarizing files skipped for exceeding the per-file size cap. */
const FILES_SKIPPED_CODE = "FILES_SKIPPED";

/** Skipped paths named in the FILES_SKIPPED diagnostic before the rest are counted. */
const MAX_SKIPPED_PATHS_LISTED = 5;

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
 * `.mcp.json`, `.cursor/mcp.json`, `.cursor/rules` (both the legacy single
 * file and the modern per-file `.mdc` directory form), `.cursorrules`, and
 * anything under `.claude/` are high-signal AI-layer files and must survive
 * even when a developer's `.gitignore` excludes them — a local agent loads
 * them whether or not they are committed. (Env files are NOT on this list:
 * see the module doc comment.)
 */
function isAlwaysPreserved(relPath: string): boolean {
  if (ALWAYS_PRESERVE_EXACT.has(relPath)) {
    return true;
  }
  return ALWAYS_PRESERVE_PREFIXES.some((prefix) => relPath.startsWith(prefix));
}

/** A `.gitignore` matcher scoped to the directory that holds it (`""` for the root). */
interface ScopedGitignore {
  dir: string;
  matcher: ignore.Ignore;
}

/**
 * Loads every `.gitignore` among `candidates` (root and nested), each as a
 * matcher scoped to its own directory, matching git's own semantics where
 * `app/.gitignore` patterns apply relative to `app/`. Unreadable files are
 * skipped.
 */
async function loadGitignores(rootDir: string, candidates: string[]): Promise<ScopedGitignore[]> {
  const scoped: ScopedGitignore[] = [];
  for (const relPath of candidates) {
    if (relPath !== ".gitignore" && !relPath.endsWith("/.gitignore")) {
      continue;
    }
    try {
      // eslint-disable-next-line security/detect-non-literal-fs-filename -- walker reads caller-supplied repo paths by design
      const contents = await readFile(join(rootDir, relPath), "utf8");
      const dir = relPath === ".gitignore" ? "" : relPath.slice(0, -"/.gitignore".length);
      scoped.push({ dir, matcher: ignore().add(contents) });
    } catch {
      // Unreadable .gitignore — proceed without its rules.
    }
  }
  return scoped;
}

/**
 * Loads the root `.immunogenignore` (gitignore syntax) — paths the repo's
 * owner has excluded from scanning, e.g. vendored code or a seed-data dump.
 * Returns `undefined` when absent.
 */
async function loadScanIgnore(rootDir: string): Promise<ignore.Ignore | undefined> {
  try {
    // eslint-disable-next-line security/detect-non-literal-fs-filename -- walker reads caller-supplied repo paths by design
    const contents = await readFile(join(rootDir, ".immunogenignore"), "utf8");
    return ignore().add(contents);
  } catch {
    return undefined;
  }
}

/** True when any `.gitignore` scoped to an ancestor directory of `relPath` ignores it. */
function isGitignored(gitignores: ScopedGitignore[], relPath: string): boolean {
  return gitignores.some(({ dir, matcher }) => {
    if (dir === "") {
      return matcher.ignores(relPath);
    }
    return relPath.startsWith(`${dir}/`) && matcher.ignores(relPath.slice(dir.length + 1));
  });
}

/** Why a candidate produced no content. */
type SkipReason = "oversize" | "binary" | "unreadable";

/**
 * Reads `absPath` as text, or reports why it was skipped. The size is checked
 * with `stat` BEFORE reading, so an oversized file (a multi-GB dump or
 * build artifact) is never loaded into memory just to be discarded.
 */
async function readIfEligible(
  absPath: string,
  maxFileSizeBytes: number,
): Promise<{ content: string } | { skipped: SkipReason }> {
  try {
    // eslint-disable-next-line security/detect-non-literal-fs-filename -- walker reads caller-supplied repo paths by design
    const info = await stat(absPath);
    if (info.size > maxFileSizeBytes) {
      return { skipped: "oversize" };
    }
    // eslint-disable-next-line security/detect-non-literal-fs-filename -- walker reads caller-supplied repo paths by design
    const buffer = await readFile(absPath);
    // Re-check: the file may have grown between stat and read.
    if (buffer.length > maxFileSizeBytes) {
      return { skipped: "oversize" };
    }
    const sniffWindow = buffer.subarray(0, Math.min(buffer.length, BINARY_SNIFF_BYTES));
    if (sniffWindow.includes(0x00)) {
      return { skipped: "binary" };
    }
    return { content: buffer.toString("utf8") };
  } catch {
    // Vanished or permission-denied mid-walk: skip it rather than abort the scan.
    return { skipped: "unreadable" };
  }
}

/**
 * Walks `rootDir` and returns a `Map<relativePath, rawText>` of exactly the
 * files a detector should see, plus any `Diagnostic[]` warnings. Order of
 * rules applied per candidate path:
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
 * Never follows symlinks (`followSymbolicLinks: false`).
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
  const oversized: string[] = [];
  let totalBytesRead = 0;

  const candidates = await fg("**/*", {
    cwd: rootDir,
    dot: true,
    onlyFiles: true,
    followSymbolicLinks: false,
    absolute: false,
    ignore: HARD_EXCLUDE_GLOBS,
  });
  const gitignores = await loadGitignores(rootDir, candidates);
  const trackedFiles = await readTrackedFiles(rootDir);
  const scanIgnore = options?.noIgnore === true ? undefined : await loadScanIgnore(rootDir);

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

    if (scanIgnore?.ignores(relPath) === true) {
      continue;
    }

    const preserved = isAlwaysPreserved(relPath);
    const committed = trackedFiles?.has(relPath) === true;

    if (!preserved && !committed && isGitignored(gitignores, relPath)) {
      continue;
    }

    if (!preserved) {
      const ext = extname(relPath).slice(1).toLowerCase();
      if (BINARY_EXT_BLOCKLIST.has(ext)) {
        continue;
      }
    }

    const absPath = join(rootDir, relPath);
    const isLockfile = LOCKFILE_BASENAMES.has(relPath.slice(relPath.lastIndexOf("/") + 1));
    const read = await readIfEligible(
      absPath,
      isLockfile ? Math.max(maxFileSizeBytes, LOCKFILE_MAX_FILE_SIZE_BYTES) : maxFileSizeBytes,
    );
    if ("skipped" in read) {
      if (read.skipped === "oversize") {
        oversized.push(relPath);
      }
      continue;
    }

    fileSet.set(relPath, read.content);
    totalBytesRead += Buffer.byteLength(read.content, "utf8");
  }

  if (oversized.length > 0) {
    const listed = oversized.slice(0, MAX_SKIPPED_PATHS_LISTED).join(", ");
    const more = oversized.length > MAX_SKIPPED_PATHS_LISTED ? `, +${String(oversized.length - MAX_SKIPPED_PATHS_LISTED)} more` : "";
    diagnostics.push({
      level: "info",
      code: FILES_SKIPPED_CODE,
      message: `${String(oversized.length)} file(s) larger than the ${String(Math.round(maxFileSizeBytes / 1024))} KB per-file cap were not scanned: ${listed}${more}.`,
    });
  }

  return { fileSet, diagnostics };
}

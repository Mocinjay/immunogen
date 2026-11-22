/**
 * ingest() — the ingestion layer's single entry point.
 *
 * Resolves any supported input (local directory / git URL / ZIP) via
 * InputResolver, walks the resolved working directory via FileWalker,
 * detects framework signals via StackDetector, and assembles a
 * `ScanContext` (src/core/types.ts). Parsing is NOT done here: the detector
 * registry parses each JS/TS file on demand and frees the tree afterwards,
 * because holding every AST at once does not fit in memory on real repos.
 *
 * Cleanup contract: the resolver's `cleanup()` — which removes
 * any temp directory created for git/zip modes — runs inside a `finally`
 * so it executes even if a downstream step (walk/detect/parse) throws. The
 * assembled `ScanContext` holds only in-memory data (the walker already
 * read every file's content into `fileSet` before this function returns),
 * so removing the temp dir after assembly never invalidates the result.
 *
 * Library-first: this module never calls
 * `console.*` or `process.exit` — it is pure data-in/data-out. It never
 * imports child_process and never evals/requires scanned content (ENG-05);
 * it only calls the components below and constructs an object.
 *
 * Pipeline order is fixed and never reordered: resolve -> walk -> detect ->
 * assemble.
 */
import { resolveInput } from "./input-resolver.js";
import { walkFiles } from "./file-walker.js";
import { detectStack } from "./stack-detector.js";

import type { ScanContext, ScanOptions } from "../types.js";

/** Diagnostic code for a scan that read no files at all. */
export const NO_FILES_SCANNED_CODE = "NO_FILES_SCANNED";

/**
 * Resolves `input` (a local directory path, a git URL, or a ZIP file path),
 * walks the resolved working directory into a `fileSet`, detects stack
 * hints, and returns the fully-assembled
 * `ScanContext`. The resolver's temp-dir cleanup always runs before this
 * function returns or throws — no git/zip temp directory is ever leaked.
 */
export async function ingest(input: string, options?: ScanOptions): Promise<ScanContext> {
  const requested = options ?? {};
  const { workingDir, kind, cleanup, diagnostics: inputDiagnostics } = await resolveInput(input, requested);
  // A git URL or ZIP is someone else's code: its own `.immunogenignore` and
  // `immunogen-ignore` comments must not be able to silence the scan.
  const untrusted = kind === "git" || kind === "zip";
  const opts: ScanOptions = untrusted ? { ...requested, noIgnore: true } : requested;

  try {
    // A ZIP has no git history and everything inside it shipped with it, so
    // nothing it says to exclude (.gitignore, .git/info/exclude, worktree
    // pointers) is honored, and its env files are always scanned.
    const walked = await walkFiles(workingDir, opts, { keepIgnoredEnvFiles: kind === "zip", ignoreInputExclusions: kind === "zip" });
    const { fileSet } = walked;
    const diagnostics = [...(inputDiagnostics ?? []), ...walked.diagnostics];
    if (untrusted && requested.noIgnore !== true) {
      diagnostics.push({
        level: "info",
        code: "INPUT_IGNORES_DISREGARDED",
        message: `This ${kind === "zip" ? "ZIP archive" : "git repository"} is scanned as untrusted input: its .immunogenignore file and immunogen-ignore comments${kind === "zip" ? ", .gitignore files, and .git/info/exclude" : ""} were not honored.`,
      });
    }
    if (fileSet.size === 0) {
      diagnostics.push({
        level: "warn",
        code: NO_FILES_SCANNED_CODE,
        message: `No files were scanned in ${input} — the path is empty, or everything in it was excluded. A score from a scan that read nothing is meaningless.`,
      });
    }
    const stackHints = detectStack(fileSet);

    return {
      rootPath: workingDir,
      fileSet,
      stackHints,
      options: opts,
      diagnostics,
    };
  } finally {
    await cleanup();
  }
}

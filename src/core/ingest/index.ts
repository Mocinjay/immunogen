/**
 * ingest() — the ingestion layer's single entry point.
 *
 * Composes the four wave-2 ingestion components into one call: resolves any
 * supported input (local directory / git URL / ZIP) via InputResolver,
 * walks the resolved working directory via FileWalker, detects framework
 * signals via StackDetector, builds the shared AST cache via ASTCache, and
 * assembles the result into a `ScanContext` (src/core/types.ts) — the one
 * object the rest of the pipeline (Phase 4's `scan()`) needs to run
 * detectors. This is the integration point that proves ENG-01 + ENG-02 +
 * ENG-04 compose into a usable whole.
 *
 * Cleanup contract (T-03-12): the resolver's `cleanup()` — which removes
 * any temp directory created for git/zip modes — runs inside a `finally`
 * so it executes even if a downstream step (walk/detect/parse) throws. The
 * assembled `ScanContext` holds only in-memory data (the walker already
 * read every file's content into `fileSet` before this function returns),
 * so removing the temp dir after assembly never invalidates the result.
 *
 * Library-first (ARCHITECTURE.md Pattern 3): this module never calls
 * `console.*` or `process.exit` — it is pure data-in/data-out. It never
 * imports child_process and never evals/requires scanned content (ENG-05);
 * it only calls the four components below and constructs an object.
 *
 * Pipeline order is fixed and never reordered: resolve -> walk -> detect ->
 * parse -> assemble.
 */
import { resolveInput } from "./input-resolver.js";
import { walkFiles } from "./file-walker.js";
import { detectStack } from "./stack-detector.js";
import { buildAstCache } from "../parse/ast-cache.js";

import type { ScanContext, ScanOptions } from "../types.js";

/**
 * Resolves `input` (a local directory path, a git URL, or a ZIP file path),
 * walks the resolved working directory into a `fileSet`, detects stack
 * hints, builds the AST cache, and returns the fully-assembled
 * `ScanContext`. The resolver's temp-dir cleanup always runs before this
 * function returns or throws — no git/zip temp directory is ever leaked.
 */
export async function ingest(input: string, options?: ScanOptions): Promise<ScanContext> {
  const opts = options ?? {};
  const { workingDir, cleanup } = await resolveInput(input, opts);

  try {
    const { fileSet, diagnostics: walkDiagnostics } = await walkFiles(workingDir, opts);
    const stackHints = detectStack(fileSet);
    const { astCache, diagnostics: astDiagnostics } = buildAstCache(fileSet);

    return {
      rootPath: workingDir,
      fileSet,
      astCache,
      stackHints,
      options: opts,
      diagnostics: [...walkDiagnostics, ...astDiagnostics],
    };
  } finally {
    await cleanup();
  }
}

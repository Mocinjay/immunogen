/**
 * ASTCache — parse-once-share-many AST builder for the ingestion layer.
 *
 * `buildAstCache(fileSet)` parses every `.js`/`.jsx`/`.ts`/`.tsx`/`.mjs`/`.cjs`
 * file in the walker's `Map<relativePath, rawText>` output (see
 * src/core/ingest/file-walker.ts) with `@babel/parser` exactly once, and
 * returns a `Map<relativePath, AST>` plus any non-fatal `Diagnostic[]`
 * warnings. This realizes ARCHITECTURE.md Pattern 1 ("Parse Once, Share
 * Many") — every detector added from Phase 5 onward reads `ctx.ast` from
 * this cache and never calls a parser itself (ARCHITECTURE.md Anti-Pattern
 * 1: parsing inside detectors multiplies parse cost by detector count).
 *
 * Load-bearing robustness contract (ROADMAP criterion 5; PITFALLS Pitfall
 * 3): a parse failure on a malformed or exotic-syntax file must never
 * crash the scan or silently vanish the file from the cache without a
 * trace — a dangerous finding in that file would then never be reported.
 * Every parse is wrapped in try/catch; a thrown error becomes a single
 * `PARSE_WARN` Diagnostic naming the file, and the file is simply absent
 * from the cache (no entry, no rethrow).
 *
 * Cache value type: the public return types the cache value as `unknown`
 * to match `ScanContext.astCache` (src/core/types.ts) exactly. The
 * "correct" type would be `ParseResult<File>` from `@babel/parser` /
 * `@babel/types`, but that pulls a new dependency this phase does not
 * need — at runtime the value IS a real Babel `File` AST node; Phase 5
 * detectors narrow it (via `@babel/types` type guards) when they consume
 * it from the cache.
 *
 * AST-only (ENG-05): @babel/parser only builds a syntax tree from text; it
 * never executes the source. This module never imports child_process,
 * never evals, and never require()s/Function()s scanned content.
 */
import { parse } from "@babel/parser";

import type { Diagnostic } from "../types.js";

/** Extensions this cache parses. Anything else is skipped (no entry, no diagnostic). */
const PARSEABLE_EXTENSIONS = new Set(["js", "jsx", "ts", "tsx", "mjs", "cjs"]);

/** Returns the lowercase extension (no leading dot) of `relPath`, or `""` if none. */
function extensionOf(relPath: string): string {
  const lastDot = relPath.lastIndexOf(".");
  const lastSlash = relPath.lastIndexOf("/");
  if (lastDot === -1 || lastDot < lastSlash) {
    return "";
  }
  return relPath.slice(lastDot + 1).toLowerCase();
}

/** True when `relPath`'s extension is one this cache parses. */
function isParseable(relPath: string): boolean {
  return PARSEABLE_EXTENSIONS.has(extensionOf(relPath));
}

/**
 * Parses every parseable file in `fileSet` exactly once with
 * `@babel/parser` (`plugins: ["typescript", "jsx"]`, `errorRecovery:
 * true` — a single plugin set handles `.js`/`.jsx`/`.ts`/`.tsx` in one
 * pass per STACK.md). Successes are keyed by their `fileSet` relative
 * path in the returned `astCache`. A parse that still throws despite
 * `errorRecovery` produces one `PARSE_WARN` Diagnostic naming the file
 * and is otherwise skipped — `buildAstCache` itself never throws.
 *
 * Non-parseable paths (`.json`, `.md`, `.env`, etc.) are skipped
 * entirely: no cache entry, no diagnostic.
 */
export function buildAstCache(fileSet: Map<string, string>): {
  astCache: Map<string, unknown>;
  diagnostics: Diagnostic[];
} {
  const astCache = new Map<string, unknown>();
  const diagnostics: Diagnostic[] = [];

  for (const [relPath, content] of fileSet) {
    if (!isParseable(relPath)) {
      continue;
    }

    try {
      const ast = parse(content, {
        sourceType: "module",
        plugins: ["typescript", "jsx"],
        errorRecovery: true,
      });
      astCache.set(relPath, ast);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      diagnostics.push({
        level: "warn",
        code: "PARSE_WARN",
        message: `failed to parse ${relPath}: ${message}`,
        file: relPath,
      });
    }
  }

  return { astCache, diagnostics };
}

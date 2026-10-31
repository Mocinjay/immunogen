/**
 * Source parser for the AST-based detectors.
 *
 * `parseSource(relPath, content)` parses ONE JS/TS file with `@babel/parser`
 * and returns its `File` AST, or a `PARSE_WARN` diagnostic when the file
 * cannot be parsed. The detector registry calls it lazily, once per file, only
 * when at least one AST-consuming detector (`DetectorConfig.usesAst`) applies
 * to that file, and drops the tree as soon as that file's detectors finish.
 *
 * Why not a whole-repo cache: a Babel AST is ~100x the size of its source
 * (10k small files / 14 MB of TypeScript measured at 1.5 GB of heap), so
 * holding every tree for the scan's lifetime runs any mid-size repo out of
 * memory. No detector needs another file's AST — cross-file detectors read
 * `fileSet` text — so there is nothing to share across files.
 *
 * Parser plugins are chosen per extension. A single `typescript` + `jsx` set
 * for every file breaks real code: in `.ts` files the JSX plugin turns
 * `<T>value` type assertions into unterminated JSX, and without a decorators
 * plugin every NestJS / Angular / TypeORM class fails to parse. Both throw
 * even under `errorRecovery`, which silently hid those files from every AST
 * detector.
 *
 * AST-only: @babel/parser builds a syntax tree from text; it never executes
 * the source.
 */
import { parse } from "@babel/parser";

import type { ParserPlugin } from "@babel/parser";

import type { Diagnostic } from "../types.js";

/** Plugin set per parseable extension (lowercase, no leading dot). */
const PLUGINS_BY_EXTENSION: ReadonlyMap<string, ParserPlugin[]> = new Map<string, ParserPlugin[]>([
  ["ts", ["typescript", "decorators-legacy"]],
  ["mts", ["typescript", "decorators-legacy"]],
  ["cts", ["typescript", "decorators-legacy"]],
  ["tsx", ["typescript", "jsx", "decorators-legacy"]],
  ["js", ["jsx", "decorators-legacy"]],
  ["jsx", ["jsx", "decorators-legacy"]],
  ["mjs", ["jsx", "decorators-legacy"]],
  ["cjs", ["jsx", "decorators-legacy"]],
]);

/** Returns the lowercase extension (no leading dot) of `relPath`, or `""` if none. */
function extensionOf(relPath: string): string {
  const lastDot = relPath.lastIndexOf(".");
  const lastSlash = relPath.lastIndexOf("/");
  if (lastDot === -1 || lastDot < lastSlash) {
    return "";
  }
  return relPath.slice(lastDot + 1).toLowerCase();
}

/** True when `relPath`'s extension is one this module parses. */
export function isParseable(relPath: string): boolean {
  return PLUGINS_BY_EXTENSION.has(extensionOf(relPath));
}

/** Outcome of parsing one file: an AST, a diagnostic, or neither (not a JS/TS file). */
export interface ParseOutcome {
  ast?: unknown;
  diagnostic?: Diagnostic;
}

/**
 * Parses one file. Never throws: a non-JS/TS path yields `{}`, a file that
 * still fails despite `errorRecovery` yields a `PARSE_WARN` diagnostic naming
 * it, so the gap in AST coverage is reported instead of silent.
 */
export function parseSource(relPath: string, content: string): ParseOutcome {
  const plugins = PLUGINS_BY_EXTENSION.get(extensionOf(relPath));
  if (plugins === undefined) {
    return {};
  }
  try {
    const ast = parse(content, {
      sourceType: "module",
      plugins,
      errorRecovery: true,
      allowReturnOutsideFunction: true,
      allowAwaitOutsideFunction: true,
      allowImportExportEverywhere: true,
    });
    return { ast };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      diagnostic: {
        level: "warn",
        code: "PARSE_WARN",
        message: `failed to parse ${relPath}: ${message}`,
        file: relPath,
      },
    };
  }
}

/**
 * Parses every parseable file in a small `fileSet` and returns the trees by
 * path. A convenience for unit tests and one-off tooling — the scan pipeline
 * itself never builds a whole-repo cache (see the module comment).
 */
export function buildAstCache(fileSet: ReadonlyMap<string, string>): {
  astCache: Map<string, unknown>;
  diagnostics: Diagnostic[];
} {
  const astCache = new Map<string, unknown>();
  const diagnostics: Diagnostic[] = [];
  for (const [relPath, content] of fileSet) {
    const { ast, diagnostic } = parseSource(relPath, content);
    if (ast !== undefined) {
      astCache.set(relPath, ast);
    }
    if (diagnostic !== undefined) {
      diagnostics.push(diagnostic);
    }
  }
  return { astCache, diagnostics };
}

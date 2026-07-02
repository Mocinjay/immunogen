/**
 * ast-utils — shared @babel/traverse primitives for AST-based detectors.
 *
 * Phase 5's structural detectors (AUTH-01 route-auth, INJECT-01 xss, and any
 * future AST rule) all consume the pre-built `ctx.ast` produced by
 * `buildAstCache` (src/core/parse/ast-cache.ts) — the realization of
 * ARCHITECTURE.md Pattern 1 ("Parse Once, Share Many"). No detector calls a
 * parser itself; instead they read `ctx.ast` and walk it. This module owns the
 * two primitives every such detector needs:
 *
 *   - `isBabelFile(ast)` — a narrowing type guard that turns the `unknown`
 *     typed `DetectorContext.ast` (src/core/types.ts) into a real @babel/types
 *     `File` node. The runtime check is a pure structural shape test (object,
 *     `type === "File"`, has a `program`), so it NEVER throws on `undefined`,
 *     `null`, or arbitrary garbage — a detector can safely guard with
 *     `if (!isBabelFile(ctx.ast)) return Promise.resolve([])` (PITFALLS.md
 *     Pitfall 3: a parse-failed file has no AST and must yield zero findings,
 *     not a crash).
 *
 *   - `traverseAst(ast, visitors)` — a thin wrapper over @babel/traverse that
 *     handles the package's ESM/CJS default-export interop. Under this
 *     project's NodeNext/ESM setup, `import traverse from "@babel/traverse"`
 *     resolves to the CJS module-namespace OBJECT whose `.default` is the
 *     actual traverse function; the wrapper unwraps `(imported).default ??
 *     imported` once, here, so no detector has to repeat the dance.
 *
 * AST-only (ENG-05): this module only walks a syntax tree of nodes that
 * @babel/parser already produced from text. It never imports a process/exec
 * primitive, never evaluates, requires, or otherwise executes any scanned
 * source — walking a tree is not running it.
 */
import traverseImport from "@babel/traverse";

import type { NodePath, TraverseOptions } from "@babel/traverse";
import type { File, Node } from "@babel/types";

export type { NodePath };

/**
 * Structural narrowing guard: true when `ast` is a non-null object that looks
 * like a @babel/types `File` node (its `type` is the literal `"File"` and it
 * carries a `program`). This is exactly the shape `buildAstCache` stores —
 * the value returned by `@babel/parser`'s `parse(...)` is a `ParseResult<File>`
 * whose root node `type` is `"File"`. Implemented as a defensive shape test
 * (no field access that could throw on a non-object) so it doubles as the
 * "do we even have an AST?" check: `undefined`/`null`/a number/a string all
 * return `false`.
 */
export function isBabelFile(ast: unknown): ast is File {
  if (typeof ast !== "object" || ast === null) {
    return false;
  }
  const candidate = ast as { type?: unknown; program?: unknown };
  return candidate.type === "File" && typeof candidate.program === "object" && candidate.program !== null;
}

/** The runtime traverse call signature this module relies on. */
type TraverseFn = (node: Node, opts: TraverseOptions) => void;

/**
 * `@babel/traverse`'s default export under this project's ESM/CJS interop is
 * the CJS module-namespace object, with the callable traverse function hung
 * off its `.default`. `@types/babel__traverse` instead types the import as
 * the callable namespace directly, so the two views disagree — bridge them by
 * casting to `unknown` first (per TS2352 guidance) then reading an optional
 * `.default`, falling back to the import itself (covers the build where the
 * named function IS the direct default). The `.default ?? import` runtime
 * check stays correct regardless of which resolution the bundler picks.
 */
const traverse: TraverseFn =
  (traverseImport as unknown as { default?: TraverseFn }).default ??
  (traverseImport as unknown as TraverseFn);

/**
 * Runs `visitors` over the `File` node `ast` via @babel/traverse. A thin
 * convenience pass-through that hides the default-export interop unwrap above
 * from every detector. Walks nodes only — does not execute the source the
 * tree was parsed from (ENG-05).
 */
export function traverseAst(ast: File, visitors: TraverseOptions): void {
  traverse(ast, visitors);
}

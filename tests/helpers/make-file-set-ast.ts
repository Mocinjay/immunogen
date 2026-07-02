/**
 * Builds an in-memory `Map<relativePath, rawText>` from a flat spec object,
 * for ASTCache tests. Mirrors `make-file-set.ts` (the Plan 03-03 helper
 * used by StackDetector's tests) but is owned by this plan to avoid
 * cross-plan file contention — both are trivial one-line Map builders
 * over the same `Record<string, string>` shape.
 *
 * Lives under tests/helpers/ (not tests/**\/*.test.ts) so vitest does not
 * treat it as a spec file — see vitest.config.ts's `include` pattern.
 */

/** Map of repo-relative path -> raw file contents, for an in-memory fileSet fixture. */
export type FileSetAstSpec = Record<string, string>;

/** Builds a `Map<relativePath, rawText>` from `entries`, mirroring the FileWalker's output shape. */
export function makeFileSet(entries: FileSetAstSpec): Map<string, string> {
  return new Map(Object.entries(entries));
}

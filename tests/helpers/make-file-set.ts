/**
 * Builds an in-memory `Map<relativePath, rawText>` from a flat spec object,
 * for StackDetector tests. Unlike `make-repo-tree.ts` (which materializes a
 * real temp directory for FileWalker), `detectStack` consumes the walker's
 * Map output directly and never touches the filesystem — so its fixtures
 * need no disk I/O either.
 *
 * Lives under tests/helpers/ (not tests/**\/*.test.ts) so vitest does not
 * treat it as a spec file — see vitest.config.ts's `include` pattern.
 */

/** Map of repo-relative path -> raw file contents, for an in-memory fileSet fixture. */
export type FileSetSpec = Record<string, string>;

/** Builds a `Map<relativePath, rawText>` from `entries`, mirroring the FileWalker's output shape. */
export function makeFileSet(entries: FileSetSpec): Map<string, string> {
  return new Map(Object.entries(entries));
}

/**
 * Materializes a temp directory tree from a flat spec object for FileWalker
 * tests. Keys are repo-relative paths (forward slashes); values are the raw
 * text to write at that path. Intermediate directories are created with
 * `mkdir({ recursive: true })`.
 *
 * Lives under tests/helpers/ (not tests/**\/*.test.ts) so vitest does not
 * treat it as a spec file — see vitest.config.ts's `include` pattern.
 */
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

/** Map of repo-relative path -> raw file contents to materialize on disk. */
export type RepoTreeSpec = Record<string, string>;

export interface MadeRepoTree {
  /** Absolute path to the materialized temp directory root. */
  root: string;
  /** Removes the temp directory tree. Safe to call more than once. */
  cleanup: () => Promise<void>;
}

/**
 * Builds a temp directory tree from `spec` and returns its root path plus a
 * `cleanup()` to remove it. Binary fixtures (e.g. a NUL-containing
 * "blob.bin") can be written by passing a string containing the literal
 * `\0` character — `writeFile` with the default utf8 encoding preserves it
 * as a single NUL byte on disk.
 */
export async function makeRepoTree(spec: RepoTreeSpec): Promise<MadeRepoTree> {
  const root = await mkdtemp(join(tmpdir(), "immunogen-repo-tree-"));

  for (const [relPath, contents] of Object.entries(spec)) {
    const absPath = join(root, relPath);
    // eslint-disable-next-line security/detect-non-literal-fs-filename -- test helper materializes a caller-supplied fixture spec by design
    await mkdir(dirname(absPath), { recursive: true });
    // eslint-disable-next-line security/detect-non-literal-fs-filename -- test helper materializes a caller-supplied fixture spec by design
    await writeFile(absPath, contents);
  }

  return {
    root,
    cleanup: async () => {
      await rm(root, { recursive: true, force: true });
    },
  };
}

/**
 * Materializes a temp directory tree from a flat spec object, for ingest()
 * end-to-end tests. Mirrors `make-repo-tree.ts` (used by FileWalker's
 * tests) — both are the same trivial spec-to-disk-tree builder over a
 * `Record<string, string>` shape.
 *
 * Lives under tests/helpers/ (not tests/**\/*.test.ts) so vitest does not
 * treat it as a spec file — see vitest.config.ts's `include` pattern.
 */
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

/** Map of repo-relative path -> raw file contents to materialize on disk. */
export type RepoTreeIngestSpec = Record<string, string>;

export interface MadeRepoTreeIngest {
  /** Absolute path to the materialized temp directory root. */
  root: string;
  /** Removes the temp directory tree. Safe to call more than once. */
  cleanup: () => Promise<void>;
}

/**
 * Builds a temp directory tree from `spec` and returns its root path plus a
 * `cleanup()` to remove it.
 */
export async function makeRepoTreeIngest(spec: RepoTreeIngestSpec): Promise<MadeRepoTreeIngest> {
  const root = await mkdtemp(join(tmpdir(), "immunogen-ingest-tree-"));

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

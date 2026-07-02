/**
 * InputResolver — the ingestion layer's front door.
 *
 * Accepts a local directory path, a git URL, or a ZIP file path and
 * normalizes all three to a working directory the FileWalker (plan 02) can
 * read, handing back a `cleanup()` to remove any temp directory created
 * along the way.
 *
 * Security-critical: this module is the single place Zip-Slip path
 * traversal (ROADMAP criterion 1) and CVE-2024-32002-style recursive-clone
 * symlink RCE are mitigated. See .planning/research/PITFALLS.md Pitfall 6
 * and this plan's <threat_model> (T-03-01, T-03-02, T-03-03).
 *
 * ENG-05 invariant: this module never directly executes a subprocess or
 * the dynamic-evaluation primitive, and it never requires/imports/evals an
 * extracted or cloned file. extract-zip and simple-git are npm
 * dependencies that wrap subprocess/native behavior internally —
 * importing them does not violate ENG-05, which forbids the primitive in
 * OUR code (enforced by eslint.config.js's no-execute ruleset on src/**).
 */
import extract from "extract-zip";
import { simpleGit } from "simple-git";
import { mkdtemp, rm, stat } from "node:fs/promises";
import { statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve, sep } from "node:path";

import type { ScanOptions } from "../types.js";

/**
 * The normalized result of resolving any of the three supported input
 * modes (local directory, git URL, ZIP file) to a single working
 * directory the rest of the pipeline can read.
 */
export interface ResolvedInput {
  /** Absolute path to the directory the FileWalker should read. */
  workingDir: string;
  /**
   * Removes any temp directory created during resolution. A no-op (but
   * still awaitable) for the local-directory passthrough mode.
   */
  cleanup: () => Promise<void>;
}

const GIT_URL_PATTERN = /^(https?:\/\/|git@)/i;

/**
 * Classifies an input string into one of the three supported modes.
 * Order matters: a `.zip` suffix is checked first (an explicit, cheap
 * string check), then the git URL patterns, with local-directory
 * passthrough as the default fallback.
 */
type InputMode = "zip" | "git" | "dir";

function classifyInput(input: string): InputMode {
  if (input.toLowerCase().endsWith(".zip")) {
    return "zip";
  }
  if (GIT_URL_PATTERN.test(input) || input.endsWith(".git")) {
    return "git";
  }
  return "dir";
}

async function noopCleanup(): Promise<void> {
  // Local-directory passthrough mode creates no temp resources.
}

async function makeTempDir(prefix: string): Promise<string> {
  return mkdtemp(join(tmpdir(), prefix));
}

function makeCleanup(tempDir: string): () => Promise<void> {
  return async () => {
    await rm(tempDir, { recursive: true, force: true });
  };
}

/**
 * Resolves a local directory path: returns its absolute form unchanged as
 * `workingDir`, with a no-op `cleanup`.
 *
 * Existence/type-checked BEFORE being handed back (mirrors the zip-branch
 * `stat` guard in `resolveInput` below): a nonexistent path used to resolve
 * silently to an empty `fileSet` downstream, producing a false "100/100
 * Ready to ship" verdict; a file-as-path used to surface as a raw ENOTDIR
 * stack trace once the FileWalker tried to read it as a directory. Both now
 * throw a clean, user-readable `Error` here instead.
 */
function resolveDir(input: string): ResolvedInput {
  const resolved = resolve(input);
  // eslint-disable-next-line security/detect-non-literal-fs-filename -- resolver operates on caller-supplied paths by design
  const dirStat = statSync(resolved, { throwIfNoEntry: false });
  if (dirStat === undefined) {
    throw new Error(`Path not found: ${input}`);
  }
  if (!dirStat.isDirectory()) {
    throw new Error(`Not a directory: ${input}`);
  }

  return {
    workingDir: resolved,
    cleanup: noopCleanup,
  };
}

/**
 * Resolves a git URL: shallow-clones (`--depth 1`) into an isolated
 * `mkdtemp` directory. Never passes `--recurse-submodules`
 * (CVE-2024-32002: recursive clone + symlink can achieve RCE on checkout).
 * Relies on simple-git's default of not invoking a shell and not running
 * arbitrary repo-defined hooks during a plain clone.
 */
async function resolveGit(url: string): Promise<ResolvedInput> {
  const tempDir = await makeTempDir("immunogen-git-");
  await simpleGit().clone(url, tempDir, ["--depth", "1"]);
  return {
    workingDir: tempDir,
    cleanup: makeCleanup(tempDir),
  };
}

/**
 * Per-entry Zip-Slip containment guard. Computes the resolved destination
 * for `entry.fileName` against `extractRoot` and throws BEFORE any byte is
 * written if the destination would escape the extraction root.
 *
 * extract-zip@2.0.1's `yauzl` dependency already rejects any entry name
 * containing `..`, a leading `/`, or a `\` with an "invalid relative path"
 * / "absolute path" error before the `onEntry` callback ever runs for that
 * entry — see yauzl's `validateFileName`. This guard is defense-in-depth:
 * it catches traversal forms yauzl's check might miss and guards against
 * future yauzl relaxations, per this plan's threat model (T-03-01).
 */
function assertEntryWithinRoot(entryFileName: string, extractRoot: string): void {
  const dest = resolve(extractRoot, entryFileName);
  const isWithinRoot = dest === extractRoot || dest.startsWith(extractRoot + sep);
  if (!isWithinRoot) {
    throw new Error(
      `Zip-Slip path traversal detected: entry "${entryFileName}" resolves outside the extraction root`,
    );
  }
}

/**
 * Resolves a ZIP file path: extracts into an isolated `mkdtemp` directory
 * with a per-entry containment guard (`onEntry`) that fires before any
 * write for that entry. A malicious entry causes the extraction promise to
 * reject; `extract-zip`'s `Extractor` cancels and closes the zipfile on any
 * thrown error from `onEntry`, so no further entries are processed either.
 */
async function resolveZip(zipPath: string): Promise<ResolvedInput> {
  const tempDir = await makeTempDir("immunogen-zip-");
  try {
    await extract(zipPath, {
      dir: tempDir,
      onEntry: (entry) => {
        assertEntryWithinRoot(entry.fileName, tempDir);
      },
    });
  } catch (err) {
    // Re-throw our own Zip-Slip containment error unchanged (it is already
    // a clean, user-readable Error); wrap anything else (yauzl/extract-zip's
    // raw parse/format errors on a corrupt or non-ZIP file) into a single
    // clean message rather than letting a raw library stack trace surface.
    await rm(tempDir, { recursive: true, force: true });
    if (err instanceof Error && err.message.includes("Zip-Slip")) {
      throw err;
    }
    throw new Error(`Not a valid ZIP archive: ${zipPath}`);
  }
  return {
    workingDir: tempDir,
    cleanup: makeCleanup(tempDir),
  };
}

/**
 * Resolves a local directory path, a git URL, or a ZIP file path to a
 * single working directory the rest of the pipeline can read.
 *
 * `options` is accepted for forward compatibility with `ScanOptions`
 * (e.g. a future `offline` flag could gate git-mode); it is unused by the
 * current resolution logic.
 */
export async function resolveInput(
  input: string,
  // eslint-disable-next-line @typescript-eslint/no-unused-vars -- accepted for forward-compatible ScanOptions wiring (see doc comment); not yet consumed by any input mode
  options?: ScanOptions,
): Promise<ResolvedInput> {
  const mode = classifyInput(input);

  if (mode === "zip") {
    // eslint-disable-next-line security/detect-non-literal-fs-filename -- resolver operates on caller-supplied paths by design
    const zipStat = await stat(input);
    if (!zipStat.isFile()) {
      throw new Error(`Input ends with .zip but is not a file: ${input}`);
    }
    return resolveZip(input);
  }

  if (mode === "git") {
    return resolveGit(input);
  }

  return resolveDir(input);
}

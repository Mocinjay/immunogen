/**
 * InputResolver — the ingestion layer's front door.
 *
 * Accepts a local directory path, a git URL, or a ZIP file path and
 * normalizes all three to a working directory the FileWalker (plan 02) can
 * read, handing back a `cleanup()` to remove any temp directory created
 * along the way.
 *
 * Security-critical: this module is the single place Zip-Slip path
 * traversal and CVE-2024-32002-style recursive-clone
 * symlink RCE are mitigated.
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
 * An input refused for a policy reason (path traversal, archive limits,
 * option-shaped git URL). Its message is already user-facing and is
 * re-thrown unchanged rather than folded into a generic error.
 */
export class InputRejectedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "InputRejectedError";
  }
}

/** Wall-clock limit for a git clone — an unreachable or huge remote must fail, not hang a CI job. */
const GIT_CLONE_TIMEOUT_MS = 5 * 60 * 1000;

/** ZIP entry-count cap — far above the walker's 25k-file default, far below a zip bomb. */
const MAX_ZIP_ENTRIES = 100_000;

/** ZIP total uncompressed-size cap, checked per entry BEFORE it is written (yauzl verifies the declared sizes). */
const MAX_ZIP_UNCOMPRESSED_BYTES = 1024 * 1024 * 1024;

/**
 * Environment variables simple-git refuses to spawn with (they let the
 * environment run arbitrary programs: askpass helpers, ssh commands, editor,
 * pager, injected `-c` config). Dropped from the clone's environment so an
 * unrelated setting in the caller's shell cannot make every clone fail.
 */
const UNSAFE_GIT_ENV_RE =
  /^(?:GIT_ASKPASS|SSH_ASKPASS|GIT_EDITOR|GIT_SEQUENCE_EDITOR|GIT_PAGER|GIT_EXTERNAL_DIFF|GIT_EXEC_PATH|GIT_PROXY_COMMAND|GIT_SSH|GIT_SSH_COMMAND|GIT_TEMPLATE_DIR|GIT_CONFIG|GIT_CONFIG_GLOBAL|GIT_CONFIG_SYSTEM|GIT_CONFIG_COUNT|GIT_CONFIG_KEY_\d+|GIT_CONFIG_VALUE_\d+)$/i;

/** The clone's environment: the caller's, minus unsafe git variables, never prompting for credentials. */
function cloneEnvironment(): Record<string, string> {
  const env: Record<string, string> = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (value !== undefined && !UNSAFE_GIT_ENV_RE.test(key)) {
      env[key] = value; // eslint-disable-line security/detect-object-injection -- copying the process's own environment
    }
  }
  // A private or mistyped HTTPS URL must fail fast instead of blocking on a
  // username prompt; LFS objects are binaries the walker skips anyway.
  env.GIT_TERMINAL_PROMPT = "0";
  env.GIT_LFS_SKIP_SMUDGE = "1";
  return env;
}

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

/** A repository URL on a well-known git host (`https://github.com/owner/repo`, optional `.git` / trailing slash). */
const GIT_HOST_REPO_RE = /^https?:\/\/(?:www\.)?(?:github\.com|gitlab\.com|bitbucket\.org|codeberg\.org)\/[\w.-]+\/[\w.-]+\/?$/i;

/**
 * True when `input` is an http(s) URL that names a git repository to clone
 * and scan — a repo page on a well-known git host, or any URL ending in
 * `.git` — rather than a deployed website to screen live.
 */
export function isGitRepoUrl(input: string): boolean {
  return /^https?:\/\//i.test(input) && (GIT_HOST_REPO_RE.test(input) || /\.git\/?$/i.test(input));
}

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
 *
 * The clone never prompts (GIT_TERMINAL_PROMPT=0), is aborted after
 * GIT_CLONE_TIMEOUT_MS, and refuses an input that starts with `-` (it would
 * reach git as an option, not a URL). A failed clone removes its temp dir
 * and reports a clean one-line error.
 */
async function resolveGit(url: string): Promise<ResolvedInput> {
  if (url.startsWith("-")) {
    throw new InputRejectedError(`Refusing git input that looks like a command-line option: ${url}`);
  }
  const tempDir = await makeTempDir("immunogen-git-");
  const controller = new AbortController();
  const timer = setTimeout(() => {
    controller.abort();
  }, GIT_CLONE_TIMEOUT_MS);
  try {
    await simpleGit({ abort: controller.signal }).env(cloneEnvironment()).clone(url, tempDir, ["--depth", "1"]);
  } catch (err) {
    await rm(tempDir, { recursive: true, force: true });
    const reason = controller.signal.aborted
      ? `timed out after ${String(GIT_CLONE_TIMEOUT_MS / 1000)}s`
      : (err instanceof Error ? err.message : String(err)).trim().split("\n").at(-1) ?? "unknown error";
    throw new Error(`git clone failed for ${url}: ${reason}`);
  } finally {
    clearTimeout(timer);
  }
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
 * future yauzl relaxations.
 */
function assertEntryWithinRoot(entryFileName: string, extractRoot: string): void {
  const dest = resolve(extractRoot, entryFileName);
  const isWithinRoot = dest === extractRoot || dest.startsWith(extractRoot + sep);
  if (!isWithinRoot) {
    throw new InputRejectedError(
      `Zip-Slip path traversal detected: entry "${entryFileName}" resolves outside the extraction root`,
    );
  }
}

/** Running totals for one extraction, enforcing the zip-bomb caps entry by entry. */
export interface ZipBudget {
  entries: number;
  uncompressedBytes: number;
}

/** Throws before an entry is written if it would push the archive past MAX_ZIP_ENTRIES / MAX_ZIP_UNCOMPRESSED_BYTES. */
export function chargeZipBudget(budget: ZipBudget, uncompressedSize: number, zipPath: string): void {
  budget.entries += 1;
  budget.uncompressedBytes += uncompressedSize;
  if (budget.entries > MAX_ZIP_ENTRIES) {
    throw new InputRejectedError(`ZIP archive has more than ${String(MAX_ZIP_ENTRIES)} entries: ${zipPath}`);
  }
  if (budget.uncompressedBytes > MAX_ZIP_UNCOMPRESSED_BYTES) {
    throw new InputRejectedError(
      `ZIP archive expands to more than ${String(MAX_ZIP_UNCOMPRESSED_BYTES / (1024 * 1024))} MB (possible zip bomb): ${zipPath}`,
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
  const budget: ZipBudget = { entries: 0, uncompressedBytes: 0 };
  try {
    await extract(zipPath, {
      dir: tempDir,
      onEntry: (entry) => {
        assertEntryWithinRoot(entry.fileName, tempDir);
        chargeZipBudget(budget, entry.uncompressedSize, zipPath);
      },
    });
  } catch (err) {
    // Re-throw our own policy errors unchanged (already clean and
    // user-readable); wrap anything else (yauzl/extract-zip's raw parse/
    // format errors on a corrupt or non-ZIP file) into one clean message.
    await rm(tempDir, { recursive: true, force: true });
    if (err instanceof InputRejectedError) {
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

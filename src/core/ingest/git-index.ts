/**
 * git-index — reads the set of git-TRACKED file paths straight from the
 * repository's `.git/index` file, without running git.
 *
 * Why: whether a `.env` file is a leak depends on whether it is actually
 * committed, not on whether it sits on disk. A gitignored, untracked
 * `.env.local` on a developer's machine is the correct practice; a `.env`
 * that was committed once and gitignored later is still in the repo and
 * still a leak. `.gitignore` alone cannot tell those apart — the index can.
 *
 * Why not `git ls-files`: running git inside an untrusted checkout honors
 * that checkout's own `.git/config`, and settings like `core.fsmonitor`
 * execute arbitrary commands. Parsing the index as plain bytes keeps the
 * scanner's never-execute guarantee (ENG-05) intact.
 *
 * Supports index versions 2, 3, and 4 (path-prefix compressed) with SHA-1
 * object ids. Anything unexpected (no repo, a SHA-256 repo, a corrupt or
 * truncated index) yields `undefined` — callers fall back to `.gitignore`
 * semantics rather than guessing.
 */
import { readFile, stat } from "node:fs/promises";
import { dirname, join, relative, resolve, sep } from "node:path";

/** `DIRC` — the index file signature. */
const INDEX_SIGNATURE = 0x44495243;

/** Fixed-size portion of an index entry before the flags field: 10 x uint32 stat data + 20-byte SHA-1. */
const ENTRY_FIXED_BYTES = 40 + 20;

/** Flags bit marking a v3+ entry that carries an extra 16-bit extended-flags field. */
const EXTENDED_FLAG = 0x4000;

/** Upper bound on how many parent directories are searched for `.git`. */
const MAX_PARENT_HOPS = 64;

/**
 * Locates the git directory for `startDir`: walks up from `startDir` to the
 * nearest `.git` (a directory, or a `gitdir: <path>` file as used by
 * worktrees and submodules). Returns the work-tree root and the git dir, or
 * `undefined` when `startDir` is not inside a repository.
 */
async function findGitDir(startDir: string): Promise<{ workTree: string; gitDir: string } | undefined> {
  let current = resolve(startDir);
  for (let hop = 0; hop < MAX_PARENT_HOPS; hop += 1) {
    const candidate = join(current, ".git");
    try {
      // eslint-disable-next-line security/detect-non-literal-fs-filename -- probes the scan target's own .git, never executes it
      const info = await stat(candidate);
      if (info.isDirectory()) {
        return { workTree: current, gitDir: candidate };
      }
      if (info.isFile()) {
        // eslint-disable-next-line security/detect-non-literal-fs-filename -- reads the scan target's own .git pointer file as text
        const pointer = await readFile(candidate, "utf8");
        const match = pointer.match(/^gitdir:\s*(.+)$/m);
        const target = match?.[1]?.trim();
        if (target !== undefined && target.length > 0) {
          return { workTree: current, gitDir: resolve(current, target) };
        }
      }
    } catch {
      // No .git at this level — keep walking up.
    }
    const parent = dirname(current);
    if (parent === current) {
      return undefined;
    }
    current = parent;
  }
  return undefined;
}

/** Decodes git's offset varint (index v4 path-prefix strip length) at `offset`; returns [value, nextOffset]. */
function readVarint(buffer: Buffer, offset: number): [number, number] {
  let position = offset;
  let byte = buffer.readUInt8(position);
  position += 1;
  let value = byte & 0x7f;
  while ((byte & 0x80) !== 0) {
    value += 1;
    byte = buffer.readUInt8(position);
    position += 1;
    value = (value << 7) + (byte & 0x7f);
  }
  return [value, position];
}

/**
 * Parses the entry paths out of a raw `.git/index` buffer. Returns
 * `undefined` for anything that is not a well-formed v2/v3/v4 index.
 * Exported for unit tests.
 */
export function parseIndexPaths(buffer: Buffer): string[] | undefined {
  try {
    if (buffer.length < 12 || buffer.readUInt32BE(0) !== INDEX_SIGNATURE) {
      return undefined;
    }
    const version = buffer.readUInt32BE(4);
    if (version < 2 || version > 4) {
      return undefined;
    }
    const entryCount = buffer.readUInt32BE(8);

    const paths: string[] = [];
    let offset = 12;
    let previousPath: Buffer = Buffer.alloc(0);

    for (let entry = 0; entry < entryCount; entry += 1) {
      const entryStart = offset;
      const flags = buffer.readUInt16BE(offset + ENTRY_FIXED_BYTES);
      offset += ENTRY_FIXED_BYTES + 2;
      if (version >= 3 && (flags & EXTENDED_FLAG) !== 0) {
        offset += 2;
      }

      let pathBytes: Buffer;
      if (version === 4) {
        const [stripLength, afterVarint] = readVarint(buffer, offset);
        const terminator = buffer.indexOf(0, afterVarint);
        if (terminator === -1 || stripLength > previousPath.length) {
          return undefined;
        }
        pathBytes = Buffer.concat([
          previousPath.subarray(0, previousPath.length - stripLength),
          buffer.subarray(afterVarint, terminator),
        ]);
        offset = terminator + 1;
      } else {
        const terminator = buffer.indexOf(0, offset);
        if (terminator === -1) {
          return undefined;
        }
        pathBytes = buffer.subarray(offset, terminator);
        // v2/v3 entries are NUL-padded to a multiple of 8 bytes (at least one NUL).
        const entryLength = terminator - entryStart;
        offset = entryStart + (Math.floor(entryLength / 8) + 1) * 8;
      }

      if (pathBytes.length === 0 || offset > buffer.length) {
        return undefined;
      }
      paths.push(pathBytes.toString("utf8"));
      previousPath = pathBytes;
    }

    return paths;
  } catch {
    // Out-of-range read on a truncated/corrupt index.
    return undefined;
  }
}

/**
 * Returns the git-tracked files under `rootDir`, as forward-slash paths
 * relative to `rootDir` (the same key shape as `ScanContext.fileSet`), or
 * `undefined` when `rootDir` is not inside a git work tree or the index
 * cannot be read.
 */
export async function readTrackedFiles(rootDir: string): Promise<Set<string> | undefined> {
  const located = await findGitDir(rootDir);
  if (located === undefined) {
    return undefined;
  }

  let buffer: Buffer;
  try {
    // eslint-disable-next-line security/detect-non-literal-fs-filename -- reads the scan target's own git index as bytes, never executes it
    buffer = await readFile(join(located.gitDir, "index"));
  } catch {
    return undefined;
  }

  const paths = parseIndexPaths(buffer);
  if (paths === undefined) {
    return undefined;
  }

  const relativeRoot = relative(located.workTree, resolve(rootDir)).split(sep).join("/");
  const prefix = relativeRoot === "" ? "" : `${relativeRoot}/`;
  const tracked = new Set<string>();
  for (const path of paths) {
    if (path.startsWith(prefix)) {
      tracked.add(path.slice(prefix.length));
    }
  }
  return tracked;
}

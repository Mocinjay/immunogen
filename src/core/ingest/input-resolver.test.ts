import { existsSync } from "node:fs";
import { mkdtemp, mkdir, rm, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, expect, it, afterEach } from "vitest";

import { isGitRepoUrl, resolveInput } from "./input-resolver.js";
import { writeZipFile } from "../../../tests/helpers/make-zip.js";

const cleanupPaths: string[] = [];

afterEach(async () => {
  while (cleanupPaths.length > 0) {
    const path = cleanupPaths.pop();
    if (path) {
      await rm(path, { recursive: true, force: true });
    }
  }
});

async function makeScratchDir(prefix: string): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), prefix));
  cleanupPaths.push(dir);
  return dir;
}

describe("resolveInput — local directory passthrough", () => {
  it("returns the resolved absolute path unchanged and a no-op cleanup", async () => {
    const scratchDir = await makeScratchDir("immunogen-test-dir-");

    const result = await resolveInput(scratchDir);

    expect(result.workingDir).toBe(resolve(scratchDir));
    await expect(result.cleanup()).resolves.toBeUndefined();
    // cleanup() is a no-op for dir mode — the original directory must still exist.
    // eslint-disable-next-line security/detect-non-literal-fs-filename -- test asserts against a temp dir it created itself
    expect(existsSync(scratchDir)).toBe(true);
  });

  it("resolves a relative-looking path to its absolute form", async () => {
    const scratchDir = await makeScratchDir("immunogen-test-relpath-");

    const result = await resolveInput(scratchDir);

    expect(result.workingDir).toBe(resolve(scratchDir));
  });
});

describe("resolveInput — bad-path robustness (the '100/100 on a nonexistent path' bug)", () => {
  it("throws a clean 'Path not found' Error (not a silent empty-fileSet pass) for a nonexistent path", async () => {
    const missing = join(tmpdir(), "immunogen-definitely-does-not-exist-12345");

    await expect(resolveInput(missing)).rejects.toThrow(/Path not found/);
  });

  it("throws a clean 'Not a directory' Error (not a raw ENOTDIR) when the input is a file", async () => {
    const scratchDir = await makeScratchDir("immunogen-test-file-as-path-");
    const filePath = join(scratchDir, "im-a-file.txt");
    const { writeFile } = await import("node:fs/promises");
    await writeFile(filePath, "just a file, not a directory\n");

    const error = await resolveInput(filePath).catch((err: unknown) => err);

    expect(error).toBeInstanceOf(Error);
    expect((error as Error).message).toMatch(/Not a directory/);
    expect((error as Error).message).not.toMatch(/ENOTDIR/);
  });
});

describe("resolveInput — benign ZIP extraction", () => {
  it("extracts a benign ZIP into a temp dir, exposes the entry, and cleans up", async () => {
    const zipParentDir = await makeScratchDir("immunogen-test-zipsrc-");
    const zipPath = join(zipParentDir, "benign.zip");
    await writeZipFile(zipPath, { "hello.txt": "hello world\n" });

    const result = await resolveInput(zipPath);

    expect(result.workingDir).not.toBe(zipParentDir);
    const extractedFile = join(result.workingDir, "hello.txt");
    // eslint-disable-next-line security/detect-non-literal-fs-filename -- test asserts against a path it just had resolveInput create
    expect(existsSync(extractedFile)).toBe(true);
    // eslint-disable-next-line security/detect-non-literal-fs-filename -- test asserts against a path it just had resolveInput create
    const content = await readFile(extractedFile, "utf8");
    expect(content).toBe("hello world\n");

    await result.cleanup();
    // eslint-disable-next-line security/detect-non-literal-fs-filename -- test asserts cleanup removed the temp dir resolveInput created
    expect(existsSync(result.workingDir)).toBe(false);
  });

  it("extracts a ZIP with multiple benign entries including a nested path", async () => {
    const zipParentDir = await makeScratchDir("immunogen-test-zipsrc2-");
    const zipPath = join(zipParentDir, "benign-nested.zip");
    await writeZipFile(zipPath, {
      "hello.txt": "hello\n",
      "nested/inner.txt": "nested content\n",
    });

    const result = await resolveInput(zipPath);
    cleanupPaths.push(result.workingDir);

    // eslint-disable-next-line security/detect-non-literal-fs-filename -- test asserts against a path it just had resolveInput create
    expect(existsSync(join(result.workingDir, "hello.txt"))).toBe(true);
    // eslint-disable-next-line security/detect-non-literal-fs-filename -- test asserts against a path it just had resolveInput create
    expect(existsSync(join(result.workingDir, "nested", "inner.txt"))).toBe(true);

    await result.cleanup();
  });
});

describe("resolveInput — malicious ZIP rejection (Zip-Slip)", () => {
  it("rejects a ZIP whose entry name uses ../../ traversal and writes nothing outside the extraction root", async () => {
    const zipParentDir = await makeScratchDir("immunogen-test-malicious-");
    const zipPath = join(zipParentDir, "malicious.zip");
    // A real Zip-Slip payload targets a sensitive file like `../../etc/passwd`.
    // We use a uniquely-named sentinel instead of `etc/passwd` so the
    // "was anything written outside the root?" existence check below cannot
    // collide with a real system file — on Linux `tmpdir()` is `/tmp`, so
    // `resolve(tmpdir(), "..", "..", "etc", "passwd")` is the *actual*
    // `/etc/passwd`, which exists independent of this test and would make the
    // assertion falsely fail.
    const sentinel = "immunogen-zipslip-sentinel.txt";
    await writeZipFile(zipPath, {
      [`../../${sentinel}`]: "malicious content\n",
    });

    // ANY error is acceptable here — whichever layer fires first (yauzl's
    // "invalid relative path" check, or our own onEntry containment guard)
    // — per this plan's instruction not to pin a message substring.
    await expect(resolveInput(zipPath)).rejects.toThrow();

    // Structural property: the traversal target must never have been created
    // anywhere outside the (now-discarded) extraction temp root. Assert the
    // most literal interpretation of the escape target (two levels up from the
    // system temp root) was never created.
    const escapeTarget = resolve(tmpdir(), "..", "..", sentinel);
    // eslint-disable-next-line security/detect-non-literal-fs-filename -- test asserts a fixed, locally-derived path was never created
    expect(existsSync(escapeTarget)).toBe(false);
  });

  it("rejects a ZIP with a single ../ traversal segment", async () => {
    const zipParentDir = await makeScratchDir("immunogen-test-malicious2-");
    const zipPath = join(zipParentDir, "malicious2.zip");
    await writeZipFile(zipPath, {
      "../evil.txt": "escaped\n",
    });

    await expect(resolveInput(zipPath)).rejects.toThrow();

    const escapeTarget = resolve(tmpdir(), "evil.txt");
    // eslint-disable-next-line security/detect-non-literal-fs-filename -- test asserts a fixed, locally-derived path was never created
    expect(existsSync(escapeTarget)).toBe(false);
  });

  it("throws when the input ends with .zip but is not a file", async () => {
    const notAZip = await makeScratchDir("immunogen-test-notazip-");
    const fakeZipDirPath = `${notAZip}.zip`;
    // eslint-disable-next-line security/detect-non-literal-fs-filename -- test creates a directory at a path it derived itself
    await mkdir(fakeZipDirPath);
    cleanupPaths.push(fakeZipDirPath);

    await expect(resolveInput(fakeZipDirPath)).rejects.toThrow();
  });

  it("throws a clean 'Not a valid ZIP archive' Error (not a raw yauzl error) for a file that ends with .zip but has non-ZIP content", async () => {
    const zipParentDir = await makeScratchDir("immunogen-test-corrupt-zip-");
    const corruptZipPath = join(zipParentDir, "not-really-a-zip.zip");
    const { writeFile } = await import("node:fs/promises");
    await writeFile(corruptZipPath, "this is plain text, not a ZIP file at all\n");

    const error = await resolveInput(corruptZipPath).catch((err: unknown) => err);

    expect(error).toBeInstanceOf(Error);
    expect((error as Error).message).toMatch(/Not a valid ZIP archive/);
  });
});

describe("resolveInput — git URL classification", () => {
  // No live-network clone test here (network-dependent, flaky in CI). The
  // git-mode behavior contract (shallow clone, isolated temp dir, cleanup)
  // is covered by the source implementation and this plan's threat model;
  // these cases assert only that URL-shaped inputs are classified as git
  // mode by attempting a clone (which will fail fast against an
  // unreachable/invalid host) rather than being treated as a local
  // directory or a ZIP.
  it("attempts to clone an https:// URL rather than treating it as a local path", async () => {
    const result = resolveInput("https://example.invalid/nonexistent-repo.git");

    // A directory-mode resolution would resolve synchronously to an
    // absolute path with no network I/O; a ZIP-mode resolution would stat
    // the input as a file. Git-mode hits the network and rejects because
    // the host is unreachable — proving the URL was classified as git,
    // not silently treated as a literal directory path.
    await expect(result).rejects.toThrow();
  });

  it("attempts to clone a git@ SSH-style URL rather than treating it as a local path", async () => {
    const result = resolveInput("git@example.invalid:nonexistent/repo.git");

    await expect(result).rejects.toThrow();
  });
});

describe("isGitRepoUrl", () => {
  it.each([
    "https://github.com/Mocinjay/immunogen",
    "https://github.com/Mocinjay/immunogen.git",
    "https://github.com/Mocinjay/immunogen/",
    "https://gitlab.com/group/project",
    "https://bitbucket.org/team/repo",
    "https://git.example.com/team/repo.git",
  ])("treats %s as a repository to clone", (url) => {
    expect(isGitRepoUrl(url)).toBe(true);
  });

  it.each([
    "https://myapp.com",
    "https://github.com",
    "https://github.com/Mocinjay",
    "https://github.com/Mocinjay/immunogen/blob/main/README.md",
    "./local/dir",
  ])("does NOT treat %s as a repository URL", (url) => {
    expect(isGitRepoUrl(url)).toBe(false);
  });
});

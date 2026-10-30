/**
 * Installed-CLI smoke test — runs the BUILT `dist/immunogen.js` the way npm,
 * pnpm, and npx actually run it: through a SYMLINK (`node_modules/.bin/
 * immunogen` -> `../immunogen/dist/immunogen.js`). Node resolves
 * `import.meta.url` through that link while `process.argv[1]` keeps the link
 * path, so an entry-script guard that compares them naively makes every
 * installed invocation print nothing and exit 0 — a silent pass in any CI
 * gate. This proves the shipped bin really scans, really sets the exit
 * code, and scans the current directory when no path is given (the README
 * quickstart, `npx immunogen`).
 *
 * Standalone node script, NOT a vitest test (mirrors
 * tests/dist/dual-import.test.mjs): run via `node tests/dist/cli-symlink.test.mjs`
 * after `pnpm run build`. Every run passes `--offline`, so it never touches
 * the network.
 */
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const repoRoot = resolve(import.meta.dirname, "..", "..");
const builtCli = join(repoRoot, "dist", "immunogen.js");
const linkDir = mkdtempSync(join(tmpdir(), "immunogen-bin-"));
const linkedCli = join(linkDir, "immunogen");

/** Runs the symlinked CLI with `args` from `cwd`; returns { status, stdout, stderr }. */
function runLinkedCli(args, cwd) {
  // NO_COLOR + ANSI stripping: CI forces colored output (picocolors honors the CI env var).
  const result = spawnSync(process.execPath, [linkedCli, ...args], {
    cwd,
    encoding: "utf8",
    env: { ...process.env, NO_COLOR: "1" },
  });
  const stripAnsi = (text) => text.replace(/\u001b\[[0-9;]*m/g, "");
  return { status: result.status, stdout: stripAnsi(result.stdout), stderr: stripAnsi(result.stderr) };
}

/** Throws a descriptive error when `condition` is false. */
function check(condition, message, run) {
  if (!condition) {
    throw new Error(`${message}\nstatus=${String(run.status)}\nstdout=${run.stdout}\nstderr=${run.stderr}`);
  }
}

try {
  // eslint-disable-next-line security/detect-non-literal-fs-filename -- link path is this test's own mkdtemp dir, never scanned-repo content
  symlinkSync(builtCli, linkedCli);

  const blocked = runLinkedCli(
    [join(repoRoot, "tests/fixtures/scan/with-secret"), "--offline", "--format", "json"],
    repoRoot,
  );
  check(blocked.status === 1, "symlinked CLI must exit 1 on a blocked scan", blocked);
  const parsed = JSON.parse(blocked.stdout);
  check(parsed.score.verdict === "blocked", "symlinked CLI must print the JSON ScanResult", blocked);

  const clean = runLinkedCli(["--offline"], join(repoRoot, "tests/fixtures/scan/clean"));
  check(clean.status === 0, "symlinked CLI with no path must scan the current directory and pass", clean);
  check(clean.stdout.includes("Scanned: ."), "no-path run must report scanning '.'", clean);

  const { version } = JSON.parse(readFileSync(join(repoRoot, "package.json"), "utf8"));
  const versionRun = runLinkedCli(["--version"], repoRoot);
  check(versionRun.status === 0, "symlinked CLI --version must exit 0", versionRun);
  check(versionRun.stdout.trim() === version, "symlinked CLI --version must print the package.json version", versionRun);

  console.log("CLI symlink OK: installed-bin invocation scans, sets exit codes, defaults to the current directory, and reports --version.");
} finally {
  rmSync(linkDir, { recursive: true, force: true });
}

/**
 * committedEnvDetector — text-only CAT-1 (Leaked Secrets) detector, SEC-05.
 *
 * The finding here is about a FILE's existence in the scanned tree, not a
 * string pattern inside it (.planning/research/FEATURES.md CAT-1 SEC-05:
 * "`.env`, `.env.local`, `.env.production`, `.env.staging` present in git
 * tree (not in .gitignore)"). The registry (src/detectors/registry.ts)
 * calls `detect()` once per file matching `config.globs`, so this detector
 * keys entirely off `ctx.filePath` — `ctx.content` is never read.
 *
 * Three guards run in sequence before a Finding is ever pushed:
 *   1. FP allowlist — test/fixture/mock/example directories never fire
 *      (.planning/research/PITFALLS.md Pitfall 1).
 *   2. Template exclusion — `.env.example`/`.env.sample`/etc. carry no real
 *      secrets by convention and are excluded outright.
 *   3. .gitignore check — reads `ctx.fileSet.get(".gitignore")`; if any
 *      non-comment, non-blank line excludes this file (exact basename,
 *      `.env*` glob, or the full relative path), the file is treated as
 *      "not committed" per FEATURES.md SEC-05's own qualifier and produces
 *      no finding.
 *
 * No-throw contract (src/core/types.ts `Detector.detect`): the entire body
 * runs inside try/catch returning `[]` on any failure.
 *
 * ENG-05 (text-only invariant): reads `ctx.filePath` and `ctx.fileSet`
 * string values only; never reads `ctx.ast`, never imports a parser, and
 * never evaluates, requires, or spawns a subprocess from scanned content.
 *
 * No `matchedText` is set on the pushed Finding — there is no single secret
 * string to mask; the finding IS the file's presence, not a value within it
 * (see plan 05-01 task 2 action).
 */
import type { Detector, DetectorContext, Finding } from "../../core/types.js";

/** Path segments that suppress every finding from this detector (FP allowlist — PITFALLS.md Pitfall 1). */
const FP_ALLOWLIST_SEGMENTS = new Set(["__tests__", "fixtures", "mocks", "examples"]);

/**
 * Template-suffix basenames that carry no real secrets by convention and
 * must never be flagged, even though their basename otherwise matches the
 * ".env or .env.-prefixed" rule below.
 */
const TEMPLATE_BASENAMES = new Set([
  ".env.example",
  ".env.sample",
  ".env.template",
  ".env.dist",
  ".env.local.example",
]);

/** True when `filePath` falls inside a test/fixture/mock/example directory. */
function isAllowlistedPath(filePath: string): boolean {
  const segments = filePath.split("/");
  return segments.some((segment) => FP_ALLOWLIST_SEGMENTS.has(segment));
}

/**
 * Returns the basename of a repo-relative path (the text after the final
 * `/`, or the whole string if there is no `/`). Mirrors the exact rule the
 * walker's own stack detector uses (src/core/ingest/stack-detector.ts
 * `hasEnvFile`) so "is an env file" stays defined identically across both
 * call sites.
 */
function basenameOf(filePath: string): string {
  return filePath.slice(filePath.lastIndexOf("/") + 1);
}

/** True when `basename` is `.env` or starts with `.env.`, per the walker's own env-file rule. */
function isEnvBasename(basename: string): boolean {
  return basename === ".env" || basename.startsWith(".env.");
}

/**
 * Parses `.gitignore` text into its non-blank, non-comment, trimmed entry
 * lines. Comment lines start with `#` (after trimming leading whitespace);
 * blank lines are skipped entirely — both per standard gitignore semantics.
 */
function parseGitignoreEntries(gitignoreContent: string): string[] {
  const entries: string[] = [];
  for (const rawLine of gitignoreContent.split("\n")) {
    const trimmed = rawLine.trim();
    if (trimmed === "" || trimmed.startsWith("#")) {
      continue;
    }
    entries.push(trimmed);
  }
  return entries;
}

/**
 * True when `entry` (one parsed .gitignore line) excludes `filePath`/its
 * `basename`. Supports the three forms FEATURES.md SEC-05 and the plan's
 * action describe: an exact basename match (`.env`), a `.env*`-style glob
 * on the basename, or the full relative path. This is a small, dedicated
 * check — not a general gitignore engine — sufficient for the documented
 * "is this specific env file excluded" question this detector asks.
 */
function gitignoreEntryExcludes(entry: string, filePath: string, basename: string): boolean {
  if (entry === basename || entry === filePath) {
    return true;
  }
  if (entry.endsWith("*")) {
    const prefix = entry.slice(0, -1);
    return basename.startsWith(prefix) || filePath.startsWith(prefix);
  }
  return false;
}

/**
 * True when `fileSet`'s `.gitignore` (if present) contains an entry that
 * excludes `filePath`. A missing `.gitignore` never excludes anything —
 * absence of the file means absence of any exclusion rule.
 */
function isGitignoreExcluded(fileSet: ReadonlyMap<string, string>, filePath: string, basename: string): boolean {
  const gitignoreContent = fileSet.get(".gitignore");
  if (gitignoreContent === undefined) {
    return false;
  }
  const entries = parseGitignoreEntries(gitignoreContent);
  return entries.some((entry) => gitignoreEntryExcludes(entry, filePath, basename));
}

export const committedEnvDetector: Detector = {
  config: {
    name: "committed-env",
    category: "secrets",
    globs: ["**/.env*"],
  },

  // Not declared `async` — no network/disk wait; the body is plain
  // synchronous work wrapped in `Promise.resolve()`, matching the same
  // sync-detector convention documented in entropy-detector.ts.
  detect(ctx: DetectorContext): Promise<Finding[]> {
    try {
      if (isAllowlistedPath(ctx.filePath)) {
        return Promise.resolve([]);
      }

      const basename = basenameOf(ctx.filePath);
      if (!isEnvBasename(basename)) {
        // Should not happen given config.globs, but the no-throw contract
        // means this path must still resolve cleanly rather than assume.
        return Promise.resolve([]);
      }
      if (TEMPLATE_BASENAMES.has(basename)) {
        return Promise.resolve([]);
      }
      if (isGitignoreExcluded(ctx.fileSet, ctx.filePath, basename)) {
        return Promise.resolve([]);
      }

      const finding: Finding = {
        ruleId: "SEC-05",
        category: "secrets",
        detectorName: "committed-env",
        file: ctx.filePath,
        line: 1,
        severity: "CRITICAL",
        confidence: "HIGH",
        message: `Committed environment file (${ctx.filePath}) found in the scanned tree.`,
        remediation:
          "Add this file to .gitignore, remove it from git history (e.g. git filter-repo or BFG), and rotate every secret it contained — committing it once is enough to leak everything inside.",
      };

      return Promise.resolve([finding]);
    } catch {
      // No-throw contract (src/core/types.ts Detector.detect): any
      // unexpected failure must resolve to [], never reject.
      return Promise.resolve([]);
    }
  },
};

/**
 * StackDetector — the ingestion layer's framework/service gate.
 *
 * `detectStack(fileSet)` reads the already-scanned repo's `package.json`
 * dependencies and directory structure (the walker's `Map<relativePath,
 * rawText>` output — see src/core/ingest/file-walker.ts) and returns a
 * frozen `StackHints` object (src/core/types.ts) identifying Next.js,
 * Vite, Express, Supabase, Firebase, Stripe, Prisma, MCP JSON, Claude
 * skills, and Cursor rules.
 *
 * These hints gate which framework-specific detectors run later in the
 * pipeline (ARCHITECTURE.md Pattern 4: a Supabase RLS detector should
 * never run on a plain Express API). ENG-04 — stack detection is the
 * primary false-positive control for framework-specific rules, so
 * detection here deliberately errs toward eager activation: a missed
 * hint silently disables a whole detector category, which is worse than
 * an occasional unnecessary detector run.
 *
 * Pure and synchronous: no fs, no network, no code execution. detectStack
 * never imports child_process, never evals, and never require()s the
 * scanned package.json as a module (ENG-05) — it only reads strings out
 * of the in-memory fileSet and JSON.parses one of them, defensively.
 */
import type { StackHints } from "../types.js";

/** package.json dependency/devDependency record shape, defensively typed. */
type DepRecord = Record<string, unknown>;

/** Minimal package.json shape this module cares about. */
interface ParsedPackageJson {
  dependencies?: DepRecord;
  devDependencies?: DepRecord;
}

/**
 * Parses `fileSet`'s `package.json` (if present) and returns a merged
 * `dependencies` + `devDependencies` record. Never throws: a missing
 * `package.json` yields `"{}"`; a malformed one is caught and treated as
 * `{}` (T-03-08 — a hostile or malformed package.json from a foreign repo
 * must degrade to empty deps, not crash the scan).
 */
function readMergedDeps(fileSet: Map<string, string>): DepRecord {
  const rawPackageJson = fileSet.get("package.json") ?? "{}";

  let parsed: ParsedPackageJson;
  try {
    parsed = JSON.parse(rawPackageJson) as ParsedPackageJson;
  } catch {
    return {};
  }

  return {
    ...parsed.dependencies,
    ...parsed.devDependencies,
  };
}

/** True when any fileSet key matches one of `configBasenames` at the repo root. */
function hasRootConfigFile(fileSet: Map<string, string>, configBasenames: readonly string[]): boolean {
  return configBasenames.some((basename) => fileSet.has(basename));
}

/** True when any fileSet key starts with `prefix`. */
function hasKeyWithPrefix(fileSet: Map<string, string>, prefix: string): boolean {
  for (const key of fileSet.keys()) {
    if (key.startsWith(prefix)) {
      return true;
    }
  }
  return false;
}

/** True when any fileSet key's basename is `.env` or starts with `.env.`. */
function hasEnvFile(fileSet: Map<string, string>): boolean {
  for (const key of fileSet.keys()) {
    const basename = key.slice(key.lastIndexOf("/") + 1);
    if (basename === ".env" || basename.startsWith(".env.")) {
      return true;
    }
  }
  return false;
}

const NEXT_CONFIG_BASENAMES = ["next.config.js", "next.config.ts", "next.config.mjs", "next.config.cjs"];
const VITE_CONFIG_BASENAMES = ["vite.config.js", "vite.config.ts", "vite.config.mjs", "vite.config.cjs"];

/**
 * Reads `fileSet` (the FileWalker's `Map<relativePath, rawText>` output)
 * and returns the detected `StackHints` for the scanned repo.
 *
 * Per-signal rules (ARCHITECTURE.md "Stack Detection Signals" table):
 * - nextjs: `next` in deps, OR a `next.config.*` file, OR an `app/` or
 *   `pages/` directory (App Router or Pages Router) — directory signal
 *   alone is sufficient even with no `next` dependency.
 * - vite: `vite` in deps, OR a `vite.config.*` file.
 * - express: `express` in deps.
 * - supabase: `@supabase/supabase-js` in deps, OR `supabase/config.toml`.
 * - firebase: `firebase` or `firebase-admin` in deps.
 * - prisma: `prisma` in deps, OR `prisma/schema.prisma`.
 * - hasStripe: `stripe` in deps.
 * - hasMcpJson: `.mcp.json` OR `.cursor/mcp.json` present.
 * - hasClaudeSkills: any key under `.claude/skills/`.
 * - hasCursorRules: `.cursor/rules`, `.cursorrules`, or any key under
 *   `.cursor/rules/`.
 */
export function detectStack(fileSet: Map<string, string>): StackHints {
  const deps = readMergedDeps(fileSet);

  const hasNextDep = "next" in deps;
  const hasNextConfig = hasRootConfigFile(fileSet, NEXT_CONFIG_BASENAMES);
  const hasNextDir = hasKeyWithPrefix(fileSet, "app/") || hasKeyWithPrefix(fileSet, "pages/");
  const isNextjs = hasNextDep || hasNextConfig || hasNextDir;

  const hasViteDep = "vite" in deps;
  const hasViteConfig = hasRootConfigFile(fileSet, VITE_CONFIG_BASENAMES);
  const isVite = hasViteDep || hasViteConfig;

  const isExpress = "express" in deps;

  const hasSupabaseDep = "@supabase/supabase-js" in deps;
  const hasSupabaseConfig = fileSet.has("supabase/config.toml");
  const hasSupabase = hasSupabaseDep || hasSupabaseConfig;

  const hasFirebase = "firebase" in deps || "firebase-admin" in deps;

  const hasPrismaDep = "prisma" in deps;
  const hasPrismaSchema = fileSet.has("prisma/schema.prisma");
  const isPrisma = hasPrismaDep || hasPrismaSchema;

  const hasStripe = "stripe" in deps;

  const frameworks = new Set<string>();
  if (isNextjs) {
    frameworks.add("nextjs");
  }
  if (isVite) {
    frameworks.add("vite");
  }
  if (isExpress) {
    frameworks.add("express");
  }
  if (hasSupabase) {
    frameworks.add("supabase");
  }
  if (hasFirebase) {
    frameworks.add("firebase");
  }
  if (isPrisma) {
    frameworks.add("prisma");
  }

  const hasEnvFiles = hasEnvFile(fileSet);

  const hasMcpJson = fileSet.has(".mcp.json") || fileSet.has(".cursor/mcp.json");

  const hasClaudeSkills = hasKeyWithPrefix(fileSet, ".claude/skills/");

  const hasCursorRules =
    fileSet.has(".cursor/rules") || fileSet.has(".cursorrules") || hasKeyWithPrefix(fileSet, ".cursor/rules/");

  return {
    frameworks,
    hasSupabase,
    hasFirebase,
    hasStripe,
    hasEnvFiles,
    hasMcpJson,
    hasClaudeSkills,
    hasCursorRules,
  };
}

/**
 * StackDetector — the ingestion layer's framework/service gate.
 *
 * `detectStack(fileSet)` reads the already-scanned repo's `package.json`
 * dependencies and directory structure (the walker's `Map<relativePath,
 * rawText>` output — see src/core/ingest/file-walker.ts) and returns a
 * frozen `StackHints` object (src/core/types.ts) identifying Next.js,
 * Vite, Express, Fastify, Hono, Koa, React Native, Supabase, Firebase,
 * Stripe, Prisma, MCP JSON, Claude skills, and Cursor rules.
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
import { manifestParserFor } from "./manifests.js";

import type { StackHints } from "../types.js";

/** package.json dependency/devDependency record shape, defensively typed. */
type DepRecord = Record<string, unknown>;

/** Minimal package.json shape this module cares about. */
interface ParsedPackageJson {
  dependencies?: DepRecord;
  devDependencies?: DepRecord;
}

/** Directory segments whose package.json is never the app's own manifest. */
const SKIPPED_MANIFEST_SEGMENTS = new Set(["node_modules", "__tests__", "fixtures", "mocks", "examples"]);

/**
 * Merges `dependencies` + `devDependencies` across EVERY `package.json` in
 * the fileSet — the root manifest and any nested app/package manifest
 * (`app/`, `apps/web/`, `packages/*`), since AI-built projects routinely
 * keep the real app in a subdirectory — skipping node_modules and
 * test/fixture manifests. A malformed manifest contributes nothing rather
 * than throwing.
 */
function readMergedDeps(fileSet: Map<string, string>): DepRecord {
  let merged: DepRecord = {};
  for (const [path, content] of fileSet) {
    const segments = path.split("/");
    if (segments.at(-1) !== "package.json" || segments.some((segment) => SKIPPED_MANIFEST_SEGMENTS.has(segment))) {
      continue;
    }
    try {
      const parsed = JSON.parse(content) as ParsedPackageJson;
      merged = { ...merged, ...parsed.dependencies, ...parsed.devDependencies };
    } catch {
      // Malformed manifest — contributes no dependencies.
    }
  }
  return merged;
}

/**
 * Names of every Python and Go dependency declared in the repo's manifests
 * (requirements*.txt, pyproject.toml, Pipfile, go.mod), keyed by ecosystem.
 * Python names are PEP 503-normalized; Go names are full module paths.
 */
function readPythonAndGoDeps(fileSet: Map<string, string>): { python: Set<string>; go: Set<string> } {
  const python = new Set<string>();
  const go = new Set<string>();
  for (const [path, content] of fileSet) {
    const segments = path.split("/");
    const parse = manifestParserFor(path);
    if (parse === undefined || segments.some((segment) => SKIPPED_MANIFEST_SEGMENTS.has(segment))) {
      continue;
    }
    for (const dependency of parse(content)) {
      (dependency.ecosystem === "Go" ? go : python).add(dependency.name);
    }
  }
  return { python, go };
}

/** True when any Go module path in `go` starts with one of `prefixes`. */
function hasGoModule(go: Set<string>, prefixes: readonly string[]): boolean {
  return [...go].some((module) => prefixes.some((prefix) => module.startsWith(prefix)));
}

/** True when any fileSet key (root or a nested app directory, never node_modules) has one of `configBasenames`. */
function hasRootConfigFile(fileSet: Map<string, string>, configBasenames: readonly string[]): boolean {
  for (const key of fileSet.keys()) {
    const basename = key.slice(key.lastIndexOf("/") + 1);
    if (configBasenames.includes(basename) && !key.split("/").includes("node_modules")) {
      return true;
    }
  }
  return false;
}

/**
 * Next.js App Router / Pages Router file conventions — an `app/` folder
 * alone is not enough (React Native and Expo projects routinely have one).
 */
function isNextRouteFile(key: string): boolean {
  const segments = key.split("/");
  const basename = segments.at(-1) ?? "";
  const isScript = /\.(?:t|j)sx?$/.test(basename);
  if (!isScript) {
    return false;
  }
  if (segments.includes("app") && /^(?:page|layout|route)\./.test(basename)) {
    return true;
  }
  const pagesIndex = segments.indexOf("pages");
  if (pagesIndex === -1) {
    return false;
  }
  return segments.at(pagesIndex + 1) === "api" || /^_(?:app|document)\./.test(segments.at(pagesIndex + 1) ?? "");
}

/** True when any file follows a Next.js routing convention. */
function hasNextRouteFiles(fileSet: Map<string, string>): boolean {
  for (const key of fileSet.keys()) {
    if (isNextRouteFile(key)) {
      return true;
    }
  }
  return false;
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
  const { python, go } = readPythonAndGoDeps(fileSet);

  const hasNextDep = "next" in deps;
  const hasNextConfig = hasRootConfigFile(fileSet, NEXT_CONFIG_BASENAMES);
  const hasNextDir = hasNextRouteFiles(fileSet);
  const isNextjs = hasNextDep || hasNextConfig || hasNextDir;

  const hasViteDep = "vite" in deps;
  const hasViteConfig = hasRootConfigFile(fileSet, VITE_CONFIG_BASENAMES);
  const isVite = hasViteDep || hasViteConfig;

  const isExpress = "express" in deps;
  const isFastify = "fastify" in deps;
  const isHono = "hono" in deps;
  const isKoa = "koa" in deps || "@koa/router" in deps || "koa-router" in deps;

  const isReactNative = "react-native" in deps || "expo" in deps;

  const hasSupabaseDep = ["@supabase/supabase-js", "@supabase/ssr", "@supabase/auth-helpers-nextjs"].some(
    (name) => name in deps,
  );
  const hasSupabaseConfig = [...fileSet.keys()].some(
    (key) => key === "supabase/config.toml" || key.endsWith("/supabase/config.toml"),
  );
  const hasSupabase = hasSupabaseDep || hasSupabaseConfig || python.has("supabase") || hasGoModule(go, ["github.com/supabase-community/"]);

  const hasFirebase =
    ["firebase", "firebase-admin", "@react-native-firebase/app"].some((name) => name in deps) ||
    python.has("firebase-admin") ||
    hasGoModule(go, ["firebase.google.com/go"]);

  const hasPrismaDep = "prisma" in deps;
  const hasPrismaSchema = fileSet.has("prisma/schema.prisma");
  const isPrisma = hasPrismaDep || hasPrismaSchema;

  const hasStripe = "stripe" in deps || python.has("stripe") || hasGoModule(go, ["github.com/stripe/stripe-go"]);

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
  if (isFastify) {
    frameworks.add("fastify");
  }
  if (isHono) {
    frameworks.add("hono");
  }
  if (isKoa) {
    frameworks.add("koa");
  }
  if (isReactNative) {
    frameworks.add("react-native");
  }
  if (python.size > 0) {
    frameworks.add("python");
  }
  for (const name of ["fastapi", "flask", "django"]) {
    if (python.has(name)) {
      frameworks.add(name);
    }
  }
  if (go.size > 0 || [...fileSet.keys()].some((key) => key === "go.mod" || key.endsWith("/go.mod"))) {
    frameworks.add("go");
  }
  const goFrameworks: ReadonlyArray<[string, string]> = [
    ["gin", "github.com/gin-gonic/gin"],
    ["echo", "github.com/labstack/echo"],
    ["chi", "github.com/go-chi/chi"],
    ["fiber", "github.com/gofiber/fiber"],
  ];
  for (const [hint, module] of goFrameworks) {
    if (hasGoModule(go, [module])) {
      frameworks.add(hint);
    }
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

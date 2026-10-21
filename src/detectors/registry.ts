/**
 * Detector registry — fans `ScanContext.fileSet` out across every registered
 * `Detector`, glob-pre-filters which files each detector actually sees, and
 * aggregates the results into one deterministically-sorted `Finding[]`.
 *
 * Glob matching (`matchesGlob`) is a SELF-CONTAINED, dependency-free
 * implementation — it intentionally does NOT import `micromatch` or
 * `picomatch`. Neither is a declared dependency of this project, and under
 * pnpm's strict node_modules layout the `micromatch` package nested inside
 * fast-glob's own dependency tree is not resolvable from the project root: a
 * bare `import "micromatch"` throws `MODULE_NOT_FOUND`, and `@types/micromatch`
 * is absent from devDependencies. `matchesGlob` converts each glob pattern to
 * a `RegExp` supporting exactly three constructs, which is all this project's
 * detector globs ever need:
 *   - `**` — matches any number of path segments, including across `/`
 *            (and zero segments, so `**\/*.ts` also matches a root-level
 *            `a.ts` with no leading directory).
 *   - `*`  — matches any run of characters WITHIN a single path segment;
 *            never crosses a `/`.
 *   - `{a,b,c}` — brace alternation, expanded into a regex alternation
 *            group. Only one top-level brace group per glob is supported
 *            (sufficient for every glob declared by this project's
 *            detectors, e.g. `**\/*.{ts,tsx,js,jsx,...}`).
 *
 * Fan-out pattern (.planning/research/ARCHITECTURE.md Pattern 2): every
 * (detector, matching-file) pair's `detect()` call is collected into one
 * flat array of promises and awaited via `Promise.allSettled` — a throwing
 * detector (violating its own no-throw contract) is isolated and contributes
 * zero findings instead of aborting the whole run. This module performs no
 * terminal output and never terminates the host process directly — it is
 * pure data-in/data-out (library-first invariant).
 */
import { secretsDetector, committedEnvDetector } from "./secrets/index.js";
import { clientExposureDetector } from "./client-exposure/index.js";
import { configDebugDetector } from "./config/index.js";
import { corsDetector, cspDetector } from "./cors-headers/index.js";
import { stripeDetector } from "./payment/index.js";
import { legalDetector } from "./legal/index.js";
import { firebaseRulesDetector, supabaseDetector } from "./storage/index.js";
import { routeAuthDetector } from "./auth/index.js";
import { xssDetector } from "./injection/index.js";
import { osvDetector } from "./deps/index.js";
import {
  promptInjectionDetector,
  exfiltrationDetector,
  mcpPoisoningDetector,
  mcpLeastPrivilegeDetector,
} from "./ai-layer/index.js";

import type { Detector, DetectorContext, Finding, ScanContext, Severity } from "../core/types.js";

/**
 * Every detector registered by default. Phase 5 (Wave 1) appended 12
 * detector families to the original `secretsDetector` — 13 `Detector`
 * instances, covering all 17 REQUIREMENTS.md requirement ids (some single
 * detector files emit two ruleIds, e.g. `firebaseRulesDetector` covers both
 * AUTH-02 and STORAGE-01; `supabaseDetector` covers AUTH-03 and STORAGE-02;
 * `configDebugDetector` covers CONFIG-01 and CONFIG-02). Phase 6 (Plan
 * 06-04) appends the four CAT-11 (AI Layer) detectors —
 * `promptInjectionDetector` (AILAYER-01), `exfiltrationDetector`
 * (AILAYER-02), `mcpPoisoningDetector` (AILAYER-03), and
 * `mcpLeastPrivilegeDetector` (AILAYER-04) — bringing the total to 17
 * `Detector` instances.
 */
export const DEFAULT_DETECTORS: Detector[] = [
  secretsDetector,
  committedEnvDetector,
  clientExposureDetector,
  configDebugDetector,
  corsDetector,
  cspDetector,
  stripeDetector,
  legalDetector,
  firebaseRulesDetector,
  supabaseDetector,
  routeAuthDetector,
  xssDetector,
  osvDetector,
  promptInjectionDetector,
  exfiltrationDetector,
  mcpPoisoningDetector,
  mcpLeastPrivilegeDetector,
];

/** Escapes every regex metacharacter in `char` except `*` and `{`/`}`/`,`, which `globToRegex` handles itself. */
function escapeRegexChar(char: string): string {
  return ".+^${}()|[]\\".includes(char) ? `\\${char}` : char;
}

/**
 * Tokenizes a glob fragment into `**` / `**\/` / `*` / single-character runs,
 * left to right. Used by `globFragmentToRegexBody` via `String.matchAll`
 * instead of manual index-based character access — avoids any
 * dynamic-bracket-indexing pattern on the input string entirely.
 */
const GLOB_TOKEN_RE = /\*\*\/?|\*|./gs;

/**
 * Converts a single non-brace glob fragment into the body of a `RegExp`
 * (no anchors). `**` becomes `.*` (the `**\/?` token form also swallows one
 * trailing `/`, so `**\/foo` matches a root-level `foo` too); bare `*`
 * becomes `[^/]*` so it never matches across a path separator; every other
 * character is regex-escaped if it is a metacharacter.
 */
function globFragmentToRegexBody(fragment: string): string {
  let body = "";
  for (const token of fragment.matchAll(GLOB_TOKEN_RE)) {
    const text = token[0];
    if (text === "**" || text === "**/") {
      body += ".*";
    } else if (text === "*") {
      body += "[^/]*";
    } else {
      body += escapeRegexChar(text);
    }
  }
  return body;
}

/** Splits `{a,b,c}` alternatives literal text on its top-level commas. */
const BRACE_GROUP_RE = /^(.*)\{([^{}]+)\}(.*)$/s;

/**
 * Converts a glob pattern (optionally containing exactly one top-level
 * `{a,b,c}` brace-alternation group) into an anchored `RegExp` matching a
 * full relative path. Brace alternation is expanded by recursing once per
 * alternative and joining the resulting bodies with `|`.
 *
 * Both `RegExp` constructions below build their pattern text from
 * `detector.config.globs` — code-defined, trusted glob strings declared by
 * this project's own detectors, never from scanned-repo file content — so
 * the dynamic-construction warning below is a deliberate, justified
 * exception, following the same scoped-disable precedent already used in
 * src/core/ingest/file-walker.ts for non-literal `fs` paths.
 */
function globToRegex(glob: string): RegExp {
  const braceMatch = glob.match(BRACE_GROUP_RE);
  if (braceMatch) {
    const [, prefix, alternatives, suffix] = braceMatch;
    const branches = (alternatives ?? "")
      .split(",")
      .map((alt) => globFragmentToRegexBody(`${prefix ?? ""}${alt}${suffix ?? ""}`));
    // eslint-disable-next-line security/detect-non-literal-regexp -- pattern text built from this project's own trusted detector.config.globs, never scanned-repo content
    return new RegExp(`^(?:${branches.join("|")})$`);
  }

  // eslint-disable-next-line security/detect-non-literal-regexp -- pattern text built from this project's own trusted detector.config.globs, never scanned-repo content
  return new RegExp(`^${globFragmentToRegexBody(glob)}$`);
}

/**
 * Returns true when `filePath` matches at least one pattern in `globs`.
 * `filePath` is expected to be a repo-relative path with forward slashes
 * (matching `ScanContext.fileSet`'s key shape).
 */
export function matchesGlob(filePath: string, globs: string[]): boolean {
  return globs.some((glob) => globToRegex(glob).test(filePath));
}

/** Severity ordering for the final sort — higher rank sorts first (most severe first). */
const SEVERITY_RANK: Record<Severity, number> = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  INFO: 1,
};

/** Sorts `findings` by severity descending, then file ascending, then line ascending — deterministic output. */
function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    const severityDelta = SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity];
    if (severityDelta !== 0) {
      return severityDelta;
    }
    const fileDelta = a.file.localeCompare(b.file);
    if (fileDelta !== 0) {
      return fileDelta;
    }
    return a.line - b.line;
  });
}

/** Builds the per-file `DetectorContext` a single `detector.detect()` call receives. */
function buildDetectorContext(ctx: ScanContext, filePath: string, content: string): DetectorContext {
  return {
    filePath,
    content,
    ast: ctx.astCache.get(filePath),
    stackHints: ctx.stackHints,
    fileSet: ctx.fileSet,
    ...(ctx.options.offline === true ? { offline: true } : {}),
  };
}

/**
 * Fans `detectors` out across every file in `ctx.fileSet`, calling
 * `detector.detect()` once per (detector, matching-file) pair after
 * glob-pre-filtering on `detector.config.globs`. Awaits the entire flattened
 * set of calls via `Promise.allSettled` so one throwing detector — a
 * violation of its own no-throw contract — cannot abort the run; only the
 * fulfilled results are flattened into the returned array. The result is
 * sorted by severity (descending), then file, then line for deterministic
 * output across runs.
 */
export async function runDetectors(
  ctx: ScanContext,
  detectors: Detector[] = DEFAULT_DETECTORS,
): Promise<Finding[]> {
  const calls: Array<Promise<Finding[]>> = [];

  for (const detector of detectors) {
    for (const [filePath, content] of ctx.fileSet) {
      if (!matchesGlob(filePath, detector.config.globs)) {
        continue;
      }
      const detectorContext = buildDetectorContext(ctx, filePath, content);
      calls.push(detector.detect(detectorContext));
    }
  }

  const settled = await Promise.allSettled(calls);

  const findings: Finding[] = [];
  for (const result of settled) {
    if (result.status === "fulfilled") {
      findings.push(...result.value);
    }
    // Rejected promises are dropped — the Detector contract forbids
    // throwing, so this is purely the defensive backstop required by
    // ARCHITECTURE.md Pattern 2; a well-behaved detector never lands here.
  }

  return sortFindings(findings);
}

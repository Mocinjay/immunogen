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
 * Execution model: files are processed by a small pool of workers
 * (FILE_CONCURRENCY). For each file the registry selects the applicable
 * detectors (glob match + `requiresStack`), parses the file ONCE if any of
 * them declares `usesAst`, awaits that file's `detect()` calls via
 * `Promise.allSettled` (a throwing detector contributes zero findings instead
 * of aborting the run), and then drops the AST. At most FILE_CONCURRENCY
 * trees are alive at a time, so memory stays flat regardless of repo size.
 *
 * Results are collected per file index and flattened in file order before
 * the final sort, so output is deterministic despite the concurrency. This
 * module performs no terminal output and never terminates the host process —
 * it is pure data-in/data-out (library-first invariant).
 */
import { secretsDetector, committedEnvDetector } from "./secrets/index.js";
import { clientExposureDetector } from "./client-exposure/index.js";
import { configDebugDetector } from "./config/index.js";
import { corsDetector, cspDetector } from "./cors-headers/index.js";
import { stripeDetector } from "./payment/index.js";
import { legalDetector } from "./legal/index.js";
import { firebaseRulesDetector, supabaseDetector, supabaseRlsDetector } from "./storage/index.js";
import { pyGoRouteAuthDetector, routeAuthDetector, serverRouteAuthDetector } from "./auth/index.js";
import { dangerousCodeDetector, pyGoCodeDetector, xssDetector } from "./injection/index.js";
import { osvDetector } from "./deps/index.js";
import { rateLimitDetector } from "./abuse/index.js";
import {
  promptInjectionDetector,
  exfiltrationDetector,
  mcpPoisoningDetector,
  mcpLeastPrivilegeDetector,
} from "./ai-layer/index.js";

import { isParseable, parseSource } from "../core/parse/ast-cache.js";

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
  supabaseRlsDetector,
  routeAuthDetector,
  serverRouteAuthDetector,
  pyGoRouteAuthDetector,
  xssDetector,
  dangerousCodeDetector,
  pyGoCodeDetector,
  rateLimitDetector,
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

/** Compiled glob cache — glob strings come only from detector configs, so the set is small and bounded. */
const compiledGlobs = new Map<string, RegExp>();

/** Returns the compiled `RegExp` for `glob`, compiling it at most once per process. */
function compiledGlob(glob: string): RegExp {
  let regex = compiledGlobs.get(glob);
  if (regex === undefined) {
    regex = globToRegex(glob);
    compiledGlobs.set(glob, regex);
  }
  return regex;
}

/**
 * Returns true when `filePath` matches at least one pattern in `globs`.
 * `filePath` is expected to be a repo-relative path with forward slashes
 * (matching `ScanContext.fileSet`'s key shape).
 */
export function matchesGlob(filePath: string, globs: string[]): boolean {
  return globs.some((glob) => compiledGlob(glob).test(filePath));
}

/** Severity ordering for the final sort — higher rank sorts first (most severe first). */
const SEVERITY_RANK: Record<Severity, number> = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  INFO: 1,
};

/** Locale-independent string ordering, so output order never depends on the host's ICU locale. */
function compareOrdinal(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

/**
 * Sorts `findings` by severity descending, then file, then line. The sort is
 * stable, so ties keep their (deterministic) collection order: file order,
 * then detector registration order.
 */
function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    const severityDelta = SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity];
    if (severityDelta !== 0) {
      return severityDelta;
    }
    const fileDelta = compareOrdinal(a.file, b.file);
    if (fileDelta !== 0) {
      return fileDelta;
    }
    return a.line - b.line;
  });
}

/** Files processed concurrently. Bounds live ASTs and in-flight network calls (OSV) at the same time. */
const FILE_CONCURRENCY = 16;

/** Stable ruleId of the OSV offline-degradation sentinel, which is a per-scan fact, not a per-manifest one. */
const DEP_OFFLINE_RULE_ID = "DEP-OFFLINE";

/** True when `detector` applies to this scan's stack (no `requiresStack`, or at least one listed framework detected). */
function appliesToStack(detector: Detector, ctx: ScanContext): boolean {
  const required = detector.config.requiresStack;
  return required === undefined || required.some((framework) => ctx.stackHints.frameworks.has(framework));
}

/** Runs every applicable detector on one file, parsing it once if any of them reads the AST. */
async function detectFile(
  ctx: ScanContext,
  detectors: readonly Detector[],
  filePath: string,
  content: string,
): Promise<Finding[]> {
  const applicable = detectors.filter((detector) => matchesGlob(filePath, detector.config.globs));
  if (applicable.length === 0) {
    return [];
  }

  let ast: unknown;
  if (applicable.some((detector) => detector.config.usesAst === true) && isParseable(filePath)) {
    const outcome = parseSource(filePath, content);
    ast = outcome.ast;
    if (outcome.diagnostic !== undefined) {
      ctx.diagnostics.push(outcome.diagnostic);
    }
  }

  const base: Omit<DetectorContext, "ast"> = {
    filePath,
    content,
    stackHints: ctx.stackHints,
    fileSet: ctx.fileSet,
    ...(ctx.options.offline === true ? { offline: true } : {}),
  };

  const settled = await Promise.allSettled(
    applicable.map((detector) =>
      // Only AST detectors receive the tree; everything else stays text-only.
      detector.detect(detector.config.usesAst === true && ast !== undefined ? { ...base, ast } : base),
    ),
  );

  const findings: Finding[] = [];
  for (const result of settled) {
    // Rejected promises are dropped — the Detector contract forbids
    // throwing, so this is purely the defensive backstop.
    if (result.status === "fulfilled") {
      findings.push(...result.value);
    }
  }
  return findings;
}

/** Identity of a finding for deduplication: two detectors (or two passes) reporting the same thing count once. */
function findingKey(finding: Finding): string {
  return [finding.ruleId, finding.file, String(finding.line), finding.message, finding.matchedText ?? ""].join("\u0000");
}

/** Drops exact duplicates and keeps a single DEP-OFFLINE sentinel per scan. */
function dedupeFindings(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  let sawOfflineSentinel = false;
  const kept: Finding[] = [];
  for (const finding of findings) {
    if (finding.ruleId === DEP_OFFLINE_RULE_ID) {
      if (sawOfflineSentinel) {
        continue;
      }
      sawOfflineSentinel = true;
    }
    const key = findingKey(finding);
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    kept.push(finding);
  }
  return kept;
}

/**
 * Runs `detectors` over every file in `ctx.fileSet` (see the module comment
 * for the execution model), applies inline `immunogen-ignore` suppression
 * unless `ctx.options.noIgnore`, drops duplicate findings, and returns them
 * sorted by severity (descending), then file, then line. Parse failures are
 * appended to `ctx.diagnostics`. Never rejects.
 */
export async function runDetectors(
  ctx: ScanContext,
  detectors: Detector[] = DEFAULT_DETECTORS,
): Promise<Finding[]> {
  const active = detectors.filter((detector) => appliesToStack(detector, ctx));
  const files = [...ctx.fileSet];
  // Keyed by file index so results flatten in file order regardless of completion order.
  const perFile = new Map<number, Finding[]>();

  let next = 0;
  const worker = async (): Promise<void> => {
    while (next < files.length) {
      // Claim the next index synchronously — no await between read and increment.
      const index = next;
      next += 1;
      const entry = files.at(index);
      if (entry === undefined) {
        continue;
      }
      try {
        perFile.set(index, await detectFile(ctx, active, entry[0], entry[1]));
      } catch {
        // detectFile only throws if a detector throws synchronously; isolate it.
        perFile.set(index, []);
      }
    }
  };
  await Promise.all(Array.from({ length: Math.min(FILE_CONCURRENCY, files.length) }, worker));

  const findings = files.flatMap((_, index) => perFile.get(index) ?? []);
  const suppression = new SuppressionIndex(ctx.fileSet);
  const kept = ctx.options.noIgnore === true ? findings : findings.filter((finding) => !suppression.isSuppressed(finding));
  return sortFindings(dedupeFindings(kept));
}

/** Inline suppression marker, with any rule ids listed after it captured in group 1. */
const IGNORE_MARKER_RE = /immunogen-ignore\b([^\n]*)/;

/** A rule id token (`SEC-06`, `AUTH-01`, `DEP-OFFLINE`, `WEB-HDR`). */
const RULE_ID_TOKEN_RE = /\b[A-Z]+-[A-Z0-9-]*[A-Z0-9]\b/g;

/**
 * Inline `immunogen-ignore` lookups, splitting each file into lines at most
 * once per scan (a naive per-finding split is O(findings x file size)).
 */
class SuppressionIndex {
  private readonly linesByFile = new Map<string, string[] | null>();

  constructor(private readonly fileSet: ReadonlyMap<string, string>) {}

  private linesOf(file: string): string[] | null {
    let lines = this.linesByFile.get(file);
    if (lines === undefined) {
      const content = this.fileSet.get(file);
      lines = content === undefined || !content.includes("immunogen-ignore") ? null : content.split("\n");
      this.linesByFile.set(file, lines);
    }
    return lines;
  }

  /**
   * True when the finding's own line, or the line directly above it, carries
   * an `immunogen-ignore` comment that either lists no rule ids (suppress
   * everything there) or lists this finding's ruleId — e.g.
   * `// immunogen-ignore SEC-06` or `# immunogen-ignore AUTH-04, AUTH-05`.
   */
  isSuppressed(finding: Finding): boolean {
    const lines = this.linesOf(finding.file);
    if (lines === null || finding.line < 1) {
      return false;
    }
    const candidates = [lines.at(finding.line - 1)];
    if (finding.line >= 2) {
      candidates.push(lines.at(finding.line - 2));
    }
    return candidates.some((line) => {
      const marker = line?.match(IGNORE_MARKER_RE);
      if (marker === null || marker === undefined) {
        return false;
      }
      const ruleIds: string[] = (marker[1] ?? "").match(RULE_ID_TOKEN_RE) ?? [];
      return ruleIds.length === 0 || ruleIds.includes(finding.ruleId);
    });
  }
}

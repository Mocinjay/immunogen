/**
 * osvDetector — CAT-5 DEP-01: OSV.dev dependency vulnerability detector.
 *
 * Reads every `package.json` in a scanned repo — the root manifest AND any
 * nested app/package manifest (`app/`, `apps/web/`, `packages/*`), since
 * AI-built projects routinely keep the real app in a subdirectory — but
 * never one under `node_modules/` or a test/fixture/mock/example directory
 * (never a
 * lockfile — PITFALLS.md Integration Gotchas: "parse only the lockfile's
 * top-level resolved versions, not the installed tree"; this detector
 * intentionally scopes to direct manifest-declared `dependencies` +
 * `devDependencies`, mirroring `stack-detector.ts`'s `readMergedDeps`
 * defensive parse pattern), batches them through `queryOsvBatch`
 * (`osv-client.ts`), and on ANY network failure falls back to the bundled
 * `FALLBACK_VULNERABLE_NPM` list (`osv-fallback.ts`).
 *
 * DEP-OFFLINE sentinel contract (the non-negotiable load-bearing trust
 * property — PITFALLS.md Pitfall 10, this plan's `<scaninclomplete_handoff>`
 * note):
 *
 *   Whenever the OSV query fails and this detector falls back to offline
 *   mode, it appends EXACTLY ONE additional Finding to whatever DEP-01
 *   findings the fallback check produced — even when the fallback check
 *   produces zero hits. That sentinel Finding always has:
 *     ruleId:      "DEP-OFFLINE"
 *     category:    "deps"
 *     detectorName: "osv"
 *     severity:    "INFO"
 *     confidence:  "LOW"
 *     message:     "OSV.dev unreachable; dependency scan ran in offline
 *                    fallback mode (results may be incomplete)."
 *
 *   This is how offline degradation stays VISIBLE in every output format
 *   immediately, without this Wave-1 plan needing to touch
 *   `ScanResult.scanIncomplete` (that field's plumbing — detecting this
 *   ruleId's presence in the aggregated finding set and setting
 *   `scanIncomplete = true` — is owned by the wiring plan, 05-08, which
 *   touches registry.ts/index.ts and must stay decoupled from this Wave-1
 *   detector file to avoid a file conflict). 05-08 should grep the final
 *   `Finding[]` for `ruleId === "DEP-OFFLINE"` and promote it.
 *
 * No-throw contract (src/core/types.ts `Detector.detect`): the entire body
 * runs inside a try/catch returning whatever findings were accumulated so
 * far (or `[]`) on any unexpected error — `detect()` NEVER rejects, even if
 * `queryOsvBatch` throws synchronously instead of returning a rejected
 * promise, and even if `ctx.content` is not valid JSON.
 *
 * Strict offline mode (`ScanOptions.offline` / `--offline`, surfaced as
 * `DetectorContext.offline`): the OSV.dev query is skipped entirely and the
 * fallback branch runs directly — same DEP-OFFLINE sentinel, so an offline
 * scan is still never reported as a complete dependency check.
 *
 * ENG-05: this module only `JSON.parse`s `ctx.content` — it never
 * `require()`s, `eval`s, or executes the scanned package.json as code.
 */
import { checkFallback, type FallbackEntry } from "./osv-fallback.js";
import { queryOsvBatch } from "./osv-client.js";

import type { Confidence, Detector, DetectorContext, Finding, Severity } from "../../core/types.js";
import type { OsvQuery } from "./osv-client.js";

/** Stable ruleId for every vulnerability finding this detector emits. */
const DEP_RULE_ID = "DEP-01";

/** Stable ruleId for the offline-degradation sentinel (see module header — the 05-08 handoff contract). */
const DEP_OFFLINE_RULE_ID = "DEP-OFFLINE";

/** Fixed message for the DEP-OFFLINE sentinel — verbatim per the scaninclomplete_handoff contract. */
const DEP_OFFLINE_MESSAGE =
  "OSV.dev unreachable; dependency scan ran in offline fallback mode (results may be incomplete).";

/** Directory segments whose package.json is test scaffolding, not a shipped manifest (mirrors the secrets detector's FP allowlist). */
const SKIPPED_MANIFEST_SEGMENTS = new Set(["node_modules", "__tests__", "fixtures", "mocks", "examples"]);

/** True when `filePath` is a real `package.json` manifest this detector should check. */
function isScannableManifest(filePath: string): boolean {
  const segments = filePath.split("/");
  return segments.at(-1) === "package.json" && !segments.some((segment) => SKIPPED_MANIFEST_SEGMENTS.has(segment));
}

/** A single direct dependency parsed out of package.json, ready for either the OSV or fallback path. */
interface ParsedDependency {
  name: string;
  /** The raw version specifier as written in package.json (may be a range, "latest", etc.). */
  rawVersion: string;
}

/** package.json dependency/devDependency record shape, defensively typed (mirrors stack-detector.ts). */
type DepRecord = Record<string, unknown>;

/** Minimal package.json shape this module cares about. */
interface ParsedPackageJson {
  dependencies?: DepRecord;
  devDependencies?: DepRecord;
}

/**
 * Specifiers that cannot be meaningfully version-compared against an OSV
 * result or the fallback floor — skipped before either path runs (the plan
 * action's explicit instruction: "skip workspace/`*`/`latest`/file:
 * specifiers that cannot be version-compared"). Workspace and `file:`
 * specifiers are detected by PREFIX (`workspace:`, `file:`, `link:`,
 * `git+`, `git:`), since each carries an arbitrary suffix.
 */
const UNCOMPARABLE_PREFIXES = ["workspace:", "file:", "link:", "git+", "git:"];
const UNCOMPARABLE_EXACT = new Set(["*", "latest"]);

/** True when `rawVersion` is a specifier this detector cannot version-compare (workspace/file/git/latest/*). */
function isUncomparableSpecifier(rawVersion: string): boolean {
  const trimmed = rawVersion.trim();
  if (UNCOMPARABLE_EXACT.has(trimmed)) {
    return true;
  }
  return UNCOMPARABLE_PREFIXES.some((prefix) => trimmed.startsWith(prefix));
}

/**
 * Parses `content` as package.json (defensively — mirrors
 * stack-detector.ts's `readMergedDeps`: missing/malformed content yields an
 * empty dependency list rather than throwing) and returns the DIRECT
 * `dependencies` + `devDependencies` as a flat list, excluding any
 * specifier this detector cannot version-compare.
 */
function parseDirectDependencies(content: string): ParsedDependency[] {
  let parsed: ParsedPackageJson;
  try {
    parsed = JSON.parse(content) as ParsedPackageJson;
  } catch {
    return [];
  }

  const merged: DepRecord = {
    ...parsed.dependencies,
    ...parsed.devDependencies,
  };

  const result: ParsedDependency[] = [];
  for (const [name, rawValue] of Object.entries(merged)) {
    if (typeof rawValue !== "string") {
      continue;
    }
    if (isUncomparableSpecifier(rawValue)) {
      continue;
    }
    result.push({ name, rawVersion: rawValue });
  }
  return result;
}

/** Strips a single leading range operator the same way osv-fallback.ts does, for use against the OSV path too. */
function cleanVersionSpecifier(rawVersion: string): string {
  const operators = [">=", "<=", "^", "~", "=", ">", "<", "v"];
  const trimmed = rawVersion.trim();
  for (const operator of operators) {
    if (trimmed.startsWith(operator)) {
      return trimmed.slice(operator.length);
    }
  }
  return trimmed;
}

/** Finds the 1-indexed line in `content` where `dependencyName` is first declared as a JSON key (best-effort; falls back to line 1). */
function findDependencyLine(content: string, dependencyName: string): number {
  const lines = content.split("\n");
  const needle = `"${dependencyName}"`;
  const index = lines.findIndex((line) => line.includes(needle));
  return index === -1 ? 1 : index + 1;
}

/**
 * Maps an OSV/GHSA/CVE advisory id to a Severity. OSV.dev's querybatch
 * response (the lightweight `id`-only shape this detector requests) does
 * not include a CVSS/severity field per-vuln in the batch response, so
 * every OSV-sourced hit is conservatively reported as HIGH — a known
 * vulnerability with an assigned advisory id is, at minimum, a real risk
 * worth surfacing; a developer can read the linked advisory for the exact
 * CVSS score. (Fallback-path hits use the curated severity from
 * `FALLBACK_VULNERABLE_NPM` instead, which IS pre-classified.)
 */
const OSV_HIT_SEVERITY: Severity = "HIGH";
const OSV_HIT_CONFIDENCE: Confidence = "HIGH";

/** Confidence for a fallback-list hit — same curated-list provenance as the bundled severity, so HIGH confidence applies uniformly. */
const FALLBACK_HIT_CONFIDENCE: Confidence = "HIGH";

/** How many advisory ids a grouped DEP-01 message lists before summarizing the rest as "+N more". */
const MAX_LISTED_ADVISORIES = 3;

/**
 * Builds the ONE DEP-01 Finding for a dependency with OSV-sourced hits
 * (severity not pre-classified by the lightweight batch response). All of a
 * package's advisories are grouped into a single finding: one upgrade fixes
 * them all, and a finding per advisory let a single outdated framework
 * (20+ advisories for an old `next`) flood the report and zero out the
 * Ship Score on its own.
 */
function buildOsvFinding(filePath: string, dependency: ParsedDependency, content: string, vulnIds: string[]): Finding {
  const listed = vulnIds.slice(0, MAX_LISTED_ADVISORIES).join(", ");
  const more = vulnIds.length > MAX_LISTED_ADVISORIES ? `, +${String(vulnIds.length - MAX_LISTED_ADVISORIES)} more` : "";
  const advisories = vulnIds.length === 1 ? `OSV advisory ${listed}` : `${String(vulnIds.length)} OSV advisories: ${listed}${more}`;
  return {
    ruleId: DEP_RULE_ID,
    category: "deps",
    detectorName: "osv",
    file: filePath,
    line: findDependencyLine(content, dependency.name),
    severity: OSV_HIT_SEVERITY,
    confidence: OSV_HIT_CONFIDENCE,
    message: `Vulnerable dependency: ${dependency.name}@${dependency.rawVersion} (${advisories}).`,
    remediation: `Upgrade ${dependency.name} to a version that resolves ${vulnIds.length === 1 ? "this advisory" : "these advisories"} — check https://osv.dev/list?ecosystem=npm&q=${encodeURIComponent(dependency.name)} for the fixed version ranges.`,
  };
}

/** Builds the DEP-01 Finding for a fallback-list hit (pre-classified severity + title from the curated entry). */
function buildFallbackFinding(
  filePath: string,
  dependency: ParsedDependency,
  content: string,
  hit: Pick<FallbackEntry, "advisoryId" | "severity" | "title">,
): Finding {
  return {
    ruleId: DEP_RULE_ID,
    category: "deps",
    detectorName: "osv",
    file: filePath,
    line: findDependencyLine(content, dependency.name),
    severity: hit.severity,
    confidence: FALLBACK_HIT_CONFIDENCE,
    message: `Vulnerable dependency: ${dependency.name}@${dependency.rawVersion} (${hit.title}; advisory ${hit.advisoryId}).`,
    remediation: `Upgrade ${dependency.name} above the vulnerable range — see advisory ${hit.advisoryId} for the exact fixed version.`,
  };
}

/** Builds the DEP-OFFLINE sentinel Finding (see module header — the scaninclomplete_handoff contract for 05-08). */
function buildOfflineSentinel(filePath: string): Finding {
  return {
    ruleId: DEP_OFFLINE_RULE_ID,
    category: "deps",
    detectorName: "osv",
    file: filePath,
    line: 1,
    severity: "INFO",
    confidence: "LOW",
    message: DEP_OFFLINE_MESSAGE,
    remediation:
      "Re-run the scan with network access to api.osv.dev for a complete dependency vulnerability check; the offline fallback only covers a small curated list of known-critical packages.",
  };
}

/**
 * Runs every parsed dependency through `checkFallback` and returns the
 * resulting DEP-01 findings — used on the offline-degradation branch. Runs
 * even when the eventual hit count is zero, because the caller ALWAYS
 * appends the DEP-OFFLINE sentinel afterward regardless of this list's
 * length (offline must never be a silent clean pass).
 */
function runFallbackCheck(filePath: string, dependencies: ParsedDependency[], content: string): Finding[] {
  const findings: Finding[] = [];
  for (const dependency of dependencies) {
    const cleanedVersion = cleanVersionSpecifier(dependency.rawVersion);
    const hit = checkFallback(dependency.name, cleanedVersion);
    if (hit !== undefined) {
      findings.push(buildFallbackFinding(filePath, dependency, content, hit));
    }
  }
  return findings;
}

export const osvDetector: Detector = {
  config: {
    name: "osv",
    category: "deps",
    globs: ["package.json", "**/package.json"],
    requiresNetwork: true,
  },

  async detect(ctx: DetectorContext): Promise<Finding[]> {
    try {
      if (!isScannableManifest(ctx.filePath)) {
        return [];
      }

      const dependencies = parseDirectDependencies(ctx.content);
      if (dependencies.length === 0) {
        return [];
      }

      // Privacy contract (threat T-05-07-01): the OSV query payload is
      // reduced to ONLY {name, version} here — nothing else from the
      // parsed package.json (scripts, author, etc.) is ever passed to
      // queryOsvBatch, which itself only accepts this exact shape.
      const queries: OsvQuery[] = dependencies.map((dependency) => ({
        name: dependency.name,
        version: cleanVersionSpecifier(dependency.rawVersion),
      }));

      try {
        if (ctx.offline === true) {
          // Strict offline mode: never touch the network; take the same
          // visible fallback path an OSV outage takes.
          throw new Error("offline mode: OSV.dev query skipped");
        }
        const results = await queryOsvBatch(queries);
        const findings: Finding[] = [];

        results.forEach((result, index) => {
          // `.at(index)` (not bracket indexing) over `results`, which
          // `queryOsvBatch` is contracted to return aligned 1:1 with
          // `queries`/`dependencies` — sidesteps
          // security/detect-object-injection entirely rather than
          // asserting the index is safe.
          const dependency = dependencies.at(index);
          if (dependency === undefined) {
            return;
          }
          const vulnIds = [...new Set((result.vulns ?? []).map((vuln) => vuln.id))];
          if (vulnIds.length > 0) {
            findings.push(buildOsvFinding(ctx.filePath, dependency, ctx.content, vulnIds));
          }
        });

        return findings;
      } catch {
        // ANY OSV failure (a typed OsvUnavailableError from osv-client.ts,
        // OR any other unexpected throw/rejection) triggers the offline
        // fallback branch uniformly — never silently treated as "zero
        // vulnerabilities found" (PITFALLS.md Pitfall 10). This catch
        // deliberately does not branch on the error's type or message: no
        // failure mode is special-cased back into a clean pass.
        const fallbackFindings = runFallbackCheck(ctx.filePath, dependencies, ctx.content);
        // The DEP-OFFLINE sentinel is appended UNCONDITIONALLY here, even
        // when fallbackFindings.length === 0 — this is the non-negotiable
        // "offline is never a silent clean pass" requirement.
        return [...fallbackFindings, buildOfflineSentinel(ctx.filePath)];
      }
    } catch {
      // No-throw contract (src/core/types.ts Detector.detect): an
      // unexpected error anywhere above (e.g. a malformed ctx.content that
      // survives JSON.parse but breaks downstream) resolves to [], never
      // rejects.
      return [];
    }
  },
};

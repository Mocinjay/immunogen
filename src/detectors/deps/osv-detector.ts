/**
 * osvDetector — CAT-5 DEP-01: OSV.dev dependency vulnerability detector.
 *
 * Reads every dependency manifest and lockfile in a scanned repo — the root
 * AND any nested app/package (`app/`, `apps/web/`, `packages/*`), since
 * AI-built projects routinely keep the real app in a subdirectory — but
 * never one under `node_modules/` or a test/fixture/mock/example directory.
 * When a lockfile resolves a manifest, its exact (including transitive)
 * versions are checked; otherwise the manifest's declared versions are.
 * Dependencies are batched through `queryOsvBatch`
 * (`osv-client.ts`), and on ANY network failure falls back to the bundled
 * `FALLBACK_VULNERABLE_NPM` list (`osv-fallback.ts`).
 *
 * DEP-OFFLINE sentinel contract (the load-bearing trust property — an
 * outage must never read as "no vulnerabilities"):
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
import { fetchVulnSeverities, queryOsvBatch } from "./osv-client.js";
import { worstSeverity } from "./osv-severity.js";
import { lockfileParserFor, NPM_LOCKFILES, PYTHON_LOCKFILES } from "../../core/ingest/lockfiles.js";
import { manifestParserFor, type Ecosystem } from "../../core/ingest/manifests.js";

import type { Confidence, Detector, DetectorContext, Finding, Severity } from "../../core/types.js";
import type { OsvQuery } from "./osv-client.js";

/** Stable ruleId for every vulnerability finding this detector emits. */
const DEP_RULE_ID = "DEP-01";

/** Stable ruleId for the offline-degradation sentinel (see module header — the 05-08 handoff contract). */
const DEP_OFFLINE_RULE_ID = "DEP-OFFLINE";

/** Fixed message for the DEP-OFFLINE sentinel (see the module header). */
const DEP_OFFLINE_MESSAGE =
  "OSV.dev unreachable; dependency scan ran in offline fallback mode (results may be incomplete).";

/** Directory segments whose package.json is test scaffolding, not a shipped manifest (mirrors the secrets detector's FP allowlist). */
const SKIPPED_MANIFEST_SEGMENTS = new Set(["node_modules", "__tests__", "fixtures", "mocks", "examples"]);

/** True when `filePath` is a real dependency manifest or lockfile this detector should check. */
function isScannableManifest(filePath: string): boolean {
  const segments = filePath.split("/");
  const isManifest =
    segments.at(-1) === "package.json" ||
    manifestParserFor(filePath) !== undefined ||
    lockfileParserFor(filePath) !== undefined;
  return isManifest && !segments.some((segment) => SKIPPED_MANIFEST_SEGMENTS.has(segment));
}

/** Directory part of a repo-relative path ("" at the root). */
function dirOf(filePath: string): string {
  const slash = filePath.lastIndexOf("/");
  return slash === -1 ? "" : filePath.slice(0, slash);
}

/**
 * The lockfile that resolves `manifestPath`'s dependencies — same
 * ecosystem, in the manifest's directory or any ancestor (a monorepo's
 * root lockfile covers every workspace package.json). When one exists, it
 * is the source of truth: the lockfile's own detect() call checks the
 * exact installed versions, transitive ones included.
 */
function governingLockfile(manifestPath: string, fileSet: ReadonlyMap<string, string>): string | undefined {
  const basename = manifestPath.split("/").at(-1) ?? "";
  const candidates =
    basename === "package.json" ? NPM_LOCKFILES : basename === "pyproject.toml" || basename === "Pipfile" ? PYTHON_LOCKFILES : [];
  let dir: string | undefined = dirOf(manifestPath);
  while (dir !== undefined) {
    for (const lockfile of candidates) {
      const candidate = dir === "" ? lockfile : `${dir}/${lockfile}`;
      if (fileSet.has(candidate)) {
        return candidate;
      }
    }
    dir = dir === "" ? undefined : dirOf(dir);
  }
  return undefined;
}

/** A single direct dependency parsed out of a manifest, ready for either the OSV or fallback path. */
interface ParsedDependency {
  ecosystem: Ecosystem;
  name: string;
  /** The version specifier as written (may be a range for npm), shown in messages. */
  rawVersion: string;
  /** The version sent to OSV. */
  queryVersion: string;
  /** 1-indexed manifest line of the declaration. */
  line: number;
  /** File the finding should point at, when not the file being scanned (a direct dependency found via its lockfile). */
  file?: string;
  /** Resolved from a lockfile but not declared in the sibling manifest. */
  transitive?: boolean;
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
  for (const [declaredName, rawValue] of Object.entries(merged)) {
    if (typeof rawValue !== "string") {
      continue;
    }
    // `"alias": "npm:real-package@^1.2.3"` installs real-package.
    const alias = parseNpmAlias(rawValue);
    const name = alias?.name ?? declaredName;
    const specifier = alias?.range ?? rawValue;
    if (isUncomparableSpecifier(specifier)) {
      continue;
    }
    const queryVersion = cleanVersionSpecifier(specifier);
    if (queryVersion === undefined) {
      continue;
    }
    result.push({
      ecosystem: "npm",
      name,
      rawVersion: rawValue,
      queryVersion,
      line: findDependencyLine(content, declaredName),
    });
  }
  return result;
}

/** Direct dependency names (with their declaration lines) of the manifest sitting next to a lockfile. */
function siblingManifestDependencies(lockfilePath: string, fileSet: ReadonlyMap<string, string>): { file: string; lines: Map<string, number> } | undefined {
  const dir = dirOf(lockfilePath);
  const prefix = dir === "" ? "" : `${dir}/`;
  const isNpm = NPM_LOCKFILES.includes(lockfilePath.split("/").at(-1) ?? "");
  for (const basename of isNpm ? ["package.json"] : ["pyproject.toml", "Pipfile"]) {
    const file = `${prefix}${basename}`;
    const content = fileSet.get(file);
    if (content === undefined) {
      continue;
    }
    const lines = new Map<string, number>();
    if (isNpm) {
      try {
        const parsed = JSON.parse(content) as ParsedPackageJson;
        for (const name of Object.keys({ ...parsed.dependencies, ...parsed.devDependencies })) {
          lines.set(name, findDependencyLine(content, name));
        }
      } catch {
        // Malformed manifest — every locked package reports against the lockfile.
      }
    } else {
      for (const dependency of manifestParserFor(file)?.(content) ?? []) {
        lines.set(dependency.name, dependency.line);
      }
    }
    return { file, lines };
  }
  return undefined;
}

/**
 * Every exact version resolved by a lockfile. Packages the sibling manifest
 * declares directly report against that manifest's line (the line a
 * developer edits); everything else is marked transitive and reports
 * against its lockfile entry.
 */
function parseLockfileDependencies(lockfilePath: string, content: string, fileSet: ReadonlyMap<string, string>): ParsedDependency[] {
  const parse = lockfileParserFor(lockfilePath);
  if (parse === undefined) {
    return [];
  }
  const manifest = siblingManifestDependencies(lockfilePath, fileSet);
  return parse(content).map((locked) => {
    const manifestLine = manifest?.lines.get(locked.name);
    const base = {
      ecosystem: locked.ecosystem,
      name: locked.name,
      rawVersion: locked.version,
      queryVersion: locked.version,
    };
    return manifest !== undefined && manifestLine !== undefined
      ? { ...base, line: manifestLine, file: manifest.file }
      : { ...base, line: locked.line, transitive: true };
  });
}

/**
 * Parses a Python or Go manifest into the dependencies OSV can check —
 * only exactly-pinned versions (a range cannot be matched to advisories).
 */
function parseOtherEcosystemDependencies(filePath: string, content: string): ParsedDependency[] {
  const parse = manifestParserFor(filePath);
  if (parse === undefined) {
    return [];
  }
  const result: ParsedDependency[] = [];
  for (const dependency of parse(content)) {
    if (dependency.version !== undefined) {
      result.push({
        ecosystem: dependency.ecosystem,
        name: dependency.name,
        rawVersion: dependency.version,
        queryVersion: dependency.version,
        line: dependency.line,
      });
    }
  }
  return result;
}

/** Splits an `npm:<name>@<range>` alias specifier (scoped names included). */
function parseNpmAlias(rawVersion: string): { name: string; range: string } | undefined {
  const trimmed = rawVersion.trim();
  if (!trimmed.startsWith("npm:")) {
    return undefined;
  }
  const spec = trimmed.slice("npm:".length);
  const at = spec.indexOf("@", 1);
  return at === -1 ? { name: spec, range: "*" } : { name: spec.slice(0, at), range: spec.slice(at + 1) };
}

/**
 * The version a range is checked at: the first concrete version it names
 * (its lower bound — `^1.2.3`, `>=1.2.3 <2`, `1.2.x`, `~1.2` give `1.2.3` /
 * `1.2.0`), padded to three components. Without a lockfile this is the best
 * available approximation of what is installed. Returns undefined for
 * specifiers with no registry version: URLs and `scheme:` specifiers
 * (`github:`, `git+https:`), `owner/repo` shorthands (a semver range never
 * contains `/`), and dist-tags (`next`, `beta`). Parsed with plain string
 * operations — the input is untrusted repo content, so no backtracking regex.
 */
function cleanVersionSpecifier(rawVersion: string): string | undefined {
  const trimmed = rawVersion.trim();
  if (/^[a-z][a-z+]*:/i.test(trimmed) || trimmed.includes("/")) {
    return undefined;
  }
  const start = trimmed.search(/\d/);
  if (start === -1) {
    return undefined;
  }
  const token = trimmed.slice(start).split(/[\s|,<>=^~]/, 1)[0] ?? "";
  const withoutBuild = token.split("+", 1)[0] ?? "";
  const dash = withoutBuild.indexOf("-");
  const core = dash === -1 ? withoutBuild : withoutBuild.slice(0, dash);
  const prerelease = dash === -1 ? "" : withoutBuild.slice(dash);
  const parts = core.split(".").slice(0, 3).map((part) => (/^\d+$/.test(part) ? part : "0"));
  while (parts.length < 3) {
    parts.push("0");
  }
  return `${parts.join(".")}${prerelease}`;
}

/** Finds the 1-indexed line in `content` where `dependencyName` is first declared as a JSON key (best-effort; falls back to line 1). */
function findDependencyLine(content: string, dependencyName: string): number {
  const lines = content.split("\n");
  const needle = `"${dependencyName}"`;
  const index = lines.findIndex((line) => line.includes(needle));
  return index === -1 ? 1 : index + 1;
}

/**
 * Default Severity for an OSV-sourced hit whose real rating is unknown.
 * OSV.dev's querybatch response carries advisory ids only; each finding is
 * rated by the worst of its advisories' full records (`fetchVulnSeverities`
 * + osv-severity.ts: GitHub's database severity, else the CVSS v3 base
 * score). When no record can be fetched or rated, the hit stays HIGH — a
 * known vulnerability with an assigned advisory id is, at minimum, a real
 * risk worth surfacing. (Fallback-path hits use the curated severity from
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
function buildOsvFinding(
  filePath: string,
  dependency: ParsedDependency,
  vulnIds: string[],
  severities: ReadonlyMap<string, Severity>,
): Finding {
  // Most severe advisories first, so the listed ids are the ones that matter.
  const rank = (id: string): number => ["LOW", "MEDIUM", "HIGH", "CRITICAL"].indexOf(severities.get(id) ?? "");
  const ordered = [...vulnIds].sort((left, right) => rank(right) - rank(left));
  const worst = worstSeverity(vulnIds.flatMap((id) => severities.get(id) ?? []));
  const listed = ordered.slice(0, MAX_LISTED_ADVISORIES).join(", ");
  const more = vulnIds.length > MAX_LISTED_ADVISORIES ? `, +${String(vulnIds.length - MAX_LISTED_ADVISORIES)} more` : "";
  const advisories =
    vulnIds.length === 1
      ? `${worst === undefined ? "" : `${worst} `}OSV advisory ${listed}`
      : `${String(vulnIds.length)} OSV advisories${worst === undefined ? "" : `, highest ${worst}`}: ${listed}${more}`;
  return {
    ruleId: DEP_RULE_ID,
    category: "deps",
    detectorName: "osv",
    file: dependency.file ?? filePath,
    line: dependency.line,
    severity: worst ?? OSV_HIT_SEVERITY,
    confidence: OSV_HIT_CONFIDENCE,
    message: dependency.transitive === true
      ? `Vulnerable transitive dependency: ${dependency.name}@${dependency.rawVersion} (${advisories}) — installed by another package, resolved in this lockfile.`
      : `Vulnerable dependency: ${dependency.name}@${dependency.rawVersion} (${advisories}).`,
    remediation:
      dependency.transitive === true
        ? `Update the package that depends on ${dependency.name}, or force a patched version with npm "overrides" / pnpm "pnpm.overrides" / yarn "resolutions" (or a direct pin in Python) — check https://osv.dev/list?ecosystem=${dependency.ecosystem}&q=${encodeURIComponent(dependency.name)} for the fixed version ranges.`
        : `Upgrade ${dependency.name} to a version that resolves ${vulnIds.length === 1 ? "this advisory" : "these advisories"} — check https://osv.dev/list?ecosystem=${dependency.ecosystem}&q=${encodeURIComponent(dependency.name)} for the fixed version ranges.`,
  };
}

/** Builds the DEP-01 Finding for a fallback-list hit (pre-classified severity + title from the curated entry). */
function buildFallbackFinding(
  filePath: string,
  dependency: ParsedDependency,
  hit: Pick<FallbackEntry, "advisoryId" | "severity" | "title">,
): Finding {
  return {
    ruleId: DEP_RULE_ID,
    category: "deps",
    detectorName: "osv",
    file: dependency.file ?? filePath,
    line: dependency.line,
    severity: hit.severity,
    confidence: FALLBACK_HIT_CONFIDENCE,
    message: `Vulnerable dependency: ${dependency.name}@${dependency.rawVersion} (${hit.title}; advisory ${hit.advisoryId}).`,
    remediation: `Upgrade ${dependency.name} above the vulnerable range — see advisory ${hit.advisoryId} for the exact fixed version.`,
  };
}

/** Builds the DEP-OFFLINE sentinel Finding (see the module header). */
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
function runFallbackCheck(filePath: string, dependencies: ParsedDependency[]): Finding[] {
  const findings: Finding[] = [];
  for (const dependency of dependencies) {
    // The bundled offline list is npm-only.
    if (dependency.ecosystem !== "npm") {
      continue;
    }
    const hit = checkFallback(dependency.name, dependency.queryVersion);
    if (hit !== undefined) {
      findings.push(buildFallbackFinding(filePath, dependency, hit));
    }
  }
  return findings;
}

export const osvDetector: Detector = {
  config: {
    name: "osv",
    category: "deps",
    globs: [
      "package.json",
      "**/package.json",
      "**/requirements*.txt",
      "**/pyproject.toml",
      "**/Pipfile",
      "**/go.mod",
      "**/package-lock.json",
      "**/npm-shrinkwrap.json",
      "**/pnpm-lock.yaml",
      "**/yarn.lock",
      "**/bun.lock",
      "**/poetry.lock",
      "**/uv.lock",
      "**/Pipfile.lock",
    ],
    requiresNetwork: true,
  },

  async detect(ctx: DetectorContext): Promise<Finding[]> {
    try {
      if (!isScannableManifest(ctx.filePath)) {
        return [];
      }

      if (governingLockfile(ctx.filePath, ctx.fileSet) !== undefined) {
        // The lockfile's own detect() call checks the exact installed versions.
        return [];
      }

      const dependencies =
        lockfileParserFor(ctx.filePath) !== undefined
          ? parseLockfileDependencies(ctx.filePath, ctx.content, ctx.fileSet)
          : ctx.filePath.endsWith("package.json")
            ? parseDirectDependencies(ctx.content)
            : parseOtherEcosystemDependencies(ctx.filePath, ctx.content);
      if (dependencies.length === 0) {
        return [];
      }

      // Privacy contract: the OSV query payload is
      // reduced to ONLY {name, version, ecosystem} here — nothing else from
      // the parsed manifest (scripts, author, etc.) is ever passed to
      // queryOsvBatch, which itself only accepts this exact shape.
      const queries: OsvQuery[] = dependencies.map((dependency) => ({
        name: dependency.name,
        version: dependency.queryVersion,
        ecosystem: dependency.ecosystem,
      }));

      try {
        if (ctx.offline === true) {
          // Strict offline mode: never touch the network; take the same
          // visible fallback path an OSV outage takes.
          throw new Error("offline mode: OSV.dev query skipped");
        }
        const results = await queryOsvBatch(queries);
        const hits: Array<{ dependency: ParsedDependency; vulnIds: string[] }> = [];

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
            hits.push({ dependency, vulnIds });
          }
        });

        // Real ratings are best-effort: an unreachable or partial lookup
        // keeps the conservative HIGH default rather than failing the scan.
        let severities: ReadonlyMap<string, Severity> = new Map();
        try {
          severities = await fetchVulnSeverities(hits.flatMap((hit) => hit.vulnIds));
        } catch {
          // Leave every advisory at the default rating.
        }

        return hits.map((hit) => buildOsvFinding(ctx.filePath, hit.dependency, hit.vulnIds, severities));
      } catch {
        // ANY OSV failure (a typed OsvUnavailableError from osv-client.ts,
        // OR any other unexpected throw/rejection) triggers the offline
        // fallback branch uniformly — never silently treated as "zero
        // vulnerabilities found". This catch
        // deliberately does not branch on the error's type or message: no
        // failure mode is special-cased back into a clean pass.
        const fallbackFindings = runFallbackCheck(ctx.filePath, dependencies);
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

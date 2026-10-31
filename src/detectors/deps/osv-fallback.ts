/**
 * osv-fallback — bundled offline "known critical" npm version list (DEP-01).
 *
 * A baseline check that still works when OSV.dev is unreachable: a small
 * static "known critical" list of the most prevalent vulnerable versions
 * seen in vibe-coded apps (lodash < 4.17.21, minimist < 1.2.6,
 * axios < 1.6.0, etc.)". This module IS that curated list, plus a
 * dependency-free comparator (`checkFallback`) that the offline branch of
 * `osv-detector.ts` calls per dependency when the network query fails.
 *
 * `FALLBACK_VULNERABLE_NPM` entries are sourced from well-known public npm
 * security advisories (GHSA/CVE ids) for packages widely pulled in by AI
 * coding agents (lodash, minimist, axios, and other high-prevalence
 * transitive/direct deps). This is a deliberately small, hand-curated
 * baseline — NOT a replacement for OSV.dev's full database — so it stays
 * dependency-free and trivially auditable.
 *
 * `checkFallback` is intentionally NOT a general semver range resolver: it
 * strips at most one leading range operator and requires the remaining
 * string to parse as exactly three dot-separated non-negative integers
 * (major.minor.patch). Anything else (a caret/tilde RANGE rather than a
 * pinned version, "latest", a workspace specifier, garbage) returns
 * `undefined` rather than guessing — a wrong "no hit" here is recoverable
 * (the OSV path is still attempted first in normal operation), but a wrong
 * "hit" on an unparseable string would be a false positive. No `semver`
 * package dependency is introduced (a compact comparator suffices).
 */
import type { Severity } from "../../core/types.js";

/** One bundled offline advisory entry: a package name + the version floor below which it is vulnerable. */
export interface FallbackEntry {
  /** npm package name, exact match (case-sensitive, as published). */
  name: string;
  /** The fixed version — `name` versions strictly BELOW this are flagged. */
  vulnerableBelow: string;
  /**
   * Fixes published on older release lines (backports). A version on the
   * same major.minor line as one of these, at or above it, is patched even
   * though it sorts below `vulnerableBelow` (e.g. semver 5.7.2).
   */
  backportFixes?: readonly string[];
  /** Public advisory identifier (GHSA or CVE) for the representative vulnerability. */
  advisoryId: string;
  severity: Severity;
  /** Short human-readable description of the vulnerability class. */
  title: string;
}

/**
 * Curated baseline of high-prevalence vulnerable npm package versions seen
 * in AI-coding-agent-generated ("vibe-coded") apps. Each entry's
 * `vulnerableBelow` is the package's officially fixed version per its public
 * advisory; `advisoryId` is the representative GHSA/CVE id for that fix.
 * Sourced from widely-reported npm advisories for packages frequently pulled in by
 * scaffolding tools and AI agents.
 */
export const FALLBACK_VULNERABLE_NPM: readonly FallbackEntry[] = [
  {
    name: "lodash",
    vulnerableBelow: "4.17.21",
    advisoryId: "GHSA-35jh-r3h4-6jhm",
    severity: "HIGH",
    title: "Command injection via template/zipObjectDeep prototype pollution",
  },
  {
    name: "minimist",
    vulnerableBelow: "1.2.6",
    backportFixes: ["0.2.4"],
    advisoryId: "GHSA-xvch-5gv4-984h",
    severity: "CRITICAL",
    title: "Prototype pollution via constructor/proto keys",
  },
  {
    name: "axios",
    vulnerableBelow: "1.6.0",
    advisoryId: "GHSA-wf5p-g6vw-rhxx",
    severity: "MEDIUM",
    title: "Server-side request forgery via absolute-URL redirect handling",
  },
  {
    name: "node-fetch",
    vulnerableBelow: "2.6.7",
    advisoryId: "GHSA-r683-j2x4-v87g",
    severity: "HIGH",
    title: "Exposure of sensitive information via Authorization header forwarded on redirect",
  },
  {
    name: "semver",
    vulnerableBelow: "7.5.2",
    backportFixes: ["6.3.1", "5.7.2"],
    advisoryId: "GHSA-c2qf-rxjj-qqgw",
    severity: "HIGH",
    title: "Regular expression denial of service in range parsing",
  },
  {
    name: "ws",
    vulnerableBelow: "8.17.1",
    backportFixes: ["7.5.10", "6.2.3", "5.2.4"],
    advisoryId: "GHSA-3h5v-q93c-6h6q",
    severity: "HIGH",
    title: "Denial of service via excessive number of HTTP headers",
  },
  {
    name: "qs",
    vulnerableBelow: "6.10.3",
    backportFixes: ["6.9.7", "6.8.3", "6.7.3", "6.6.1", "6.5.3", "6.4.1", "6.3.3", "6.2.4"],
    advisoryId: "GHSA-hrpp-h998-j3pp",
    severity: "MEDIUM",
    title: "Prototype pollution via crafted query string",
  },
  {
    name: "json5",
    vulnerableBelow: "2.2.2",
    backportFixes: ["1.0.2"],
    advisoryId: "GHSA-9c47-m6qq-7p4h",
    severity: "HIGH",
    title: "Prototype pollution in JSON5.parse",
  },
  {
    name: "ansi-regex",
    vulnerableBelow: "5.0.1",
    backportFixes: ["4.1.1", "3.0.1"],
    advisoryId: "GHSA-93q8-gq69-wqmw",
    severity: "MEDIUM",
    title: "Regular expression denial of service",
  },
  {
    name: "follow-redirects",
    vulnerableBelow: "1.15.4",
    advisoryId: "GHSA-cxjh-pqwp-8mfp",
    severity: "MEDIUM",
    title: "Exposure of sensitive information via the Proxy-Authorization header on redirect",
  },
  {
    name: "tough-cookie",
    vulnerableBelow: "4.1.3",
    advisoryId: "GHSA-72xf-g2v4-qvf3",
    severity: "MEDIUM",
    title: "Prototype pollution via crafted Set-Cookie header",
  },
  {
    name: "express",
    vulnerableBelow: "4.19.2",
    advisoryId: "GHSA-rv95-896h-c2vc",
    severity: "MEDIUM",
    title: "Open redirect via malformed URL in res.location/res.redirect",
  },
  {
    name: "ejs",
    vulnerableBelow: "3.1.10",
    advisoryId: "GHSA-ghr5-ch3p-vcr6",
    severity: "CRITICAL",
    title: "Remote code execution via crafted template options",
  },
  {
    name: "jsonwebtoken",
    vulnerableBelow: "9.0.0",
    advisoryId: "GHSA-8cf7-32gw-wr33",
    severity: "HIGH",
    title: "Insecure default algorithm allows signature verification bypass",
  },
  {
    name: "moment",
    vulnerableBelow: "2.29.4",
    advisoryId: "GHSA-wc69-rhjr-hc9g",
    severity: "HIGH",
    title: "Path traversal via locale string in moment.locale()",
  },
  {
    name: "request",
    vulnerableBelow: "2.88.2",
    advisoryId: "GHSA-p8p7-x288-28g6",
    severity: "MEDIUM",
    title: "Insufficiently random string used for HTTP form-data boundary",
  },
  {
    name: "yargs-parser",
    vulnerableBelow: "13.1.2",
    advisoryId: "GHSA-p9pc-299p-vxgp",
    severity: "MEDIUM",
    title: "Prototype pollution via crafted command-line argument",
  },
  {
    name: "trim-newlines",
    vulnerableBelow: "3.0.1",
    advisoryId: "GHSA-7p7h-4mm5-852v",
    severity: "MEDIUM",
    title: "Regular expression denial of service",
  },
  {
    name: "got",
    vulnerableBelow: "11.8.5",
    advisoryId: "GHSA-pfrx-2q88-qq97",
    severity: "MEDIUM",
    title: "Redirect to a UNIX socket allows bypassing host allowlists",
  },
  {
    name: "minimatch",
    vulnerableBelow: "3.0.5",
    advisoryId: "GHSA-f8q6-p94x-37v3",
    severity: "HIGH",
    title: "Regular expression denial of service",
  },
  {
    name: "underscore",
    vulnerableBelow: "1.12.1",
    advisoryId: "GHSA-cf4h-3jhx-xvhq",
    severity: "CRITICAL",
    title: "Arbitrary code execution via template function",
  },
  {
    name: "validator",
    vulnerableBelow: "13.7.0",
    advisoryId: "GHSA-qgmg-gppg-76g5",
    severity: "MEDIUM",
    title: "Regular expression denial of service in isEmail",
  },
  {
    name: "xml2js",
    vulnerableBelow: "0.5.0",
    advisoryId: "GHSA-776f-qx25-q3cc",
    severity: "MEDIUM",
    title: "Prototype pollution via crafted XML attribute names",
  },
  {
    name: "next",
    vulnerableBelow: "14.1.1",
    advisoryId: "GHSA-gp8f-8m3g-qvj9",
    severity: "MEDIUM",
    title: "Denial of service via crafted Server Actions request body",
  },
  {
    name: "vite",
    vulnerableBelow: "5.0.13",
    backportFixes: ["4.5.2", "3.2.8", "2.9.17"],
    advisoryId: "GHSA-9cwx-2883-4wfx",
    severity: "MEDIUM",
    title: "Arbitrary file read via dev server fs.deny bypass",
  },
] as const;

/**
 * Strips a single leading range/comparison operator (in order of longest
 * match first, so `>=` is not partially stripped as `>`) and a leading `v`
 * version-prefix character. Only ONE operator is stripped — `checkFallback`
 * is not a range resolver, so a true range like `>=1.0.0 <2.0.0` is left
 * unparseable on purpose (falls through to the "no hit" return below).
 */
function stripLeadingRangeOperator(version: string): string {
  const operators = [">=", "<=", "^", "~", "=", ">", "<", "v"];
  for (const operator of operators) {
    if (version.startsWith(operator)) {
      return version.slice(operator.length);
    }
  }
  return version;
}

/** A version's [major, minor, patch] as integers, or `undefined` if `version` is not exactly three numeric dot-separated parts. */
function parseVersionParts(version: string): [number, number, number] | undefined {
  const cleaned = stripLeadingRangeOperator(version.trim());
  const parts = cleaned.split(".");
  if (parts.length !== 3) {
    return undefined;
  }

  const numericParts = parts.map((part) => Number(part));
  if (numericParts.some((part) => !Number.isInteger(part) || part < 0)) {
    return undefined;
  }

  // `numericParts.length === 3` is guaranteed by the `parts.length !== 3`
  // check above, so this destructure is exhaustive — no `noUncheckedIndexedAccess`
  // `undefined` branch to handle.
  const [major, minor, patch] = numericParts as [number, number, number];
  return [major, minor, patch];
}

/**
 * Compares two parsed [major, minor, patch] tuples. Returns negative if `a`
 * < `b`, zero if equal, positive if `a` > `b` — standard three-way compare,
 * compared component by component (major first). Destructures both tuples
 * up front rather than looping with a numeric index, sidestepping any
 * dynamic-bracket-indexing pattern entirely (matches entropy-detector.ts's
 * `.entries()` convention of preferring destructure/iteration over
 * index access).
 */
function compareVersionParts(a: [number, number, number], b: [number, number, number]): number {
  const [aMajor, aMinor, aPatch] = a;
  const [bMajor, bMinor, bPatch] = b;

  if (aMajor !== bMajor) {
    return aMajor - bMajor;
  }
  if (aMinor !== bMinor) {
    return aMinor - bMinor;
  }
  return aPatch - bPatch;
}

/** True when `version` sits on the major.minor line of one of `backportFixes`, at or above that backported fix. */
function isPatchedBackport(version: [number, number, number], backportFixes: readonly string[]): boolean {
  const [major, minor] = version;
  return backportFixes.some((fix) => {
    const parsedFix = parseVersionParts(fix);
    return (
      parsedFix !== undefined &&
      parsedFix[0] === major &&
      parsedFix[1] === minor &&
      compareVersionParts(version, parsedFix) >= 0
    );
  });
}

/**
 * Looks up `name`@`version` against the bundled `FALLBACK_VULNERABLE_NPM`
 * list. Returns the matching advisory fields when `version` parses to
 * exactly three numeric parts AND is strictly below that entry's
 * `vulnerableBelow` floor (and is not a patched backport release); returns
 * `undefined` for an unlisted package, a version at/above the fix, or any
 * version string that cannot be parsed (malformed, a true range, "latest",
 * etc. — see module header). Never throws.
 */
export function checkFallback(
  name: string,
  version: string,
): { advisoryId: string; severity: Severity; title: string } | undefined {
  const entry = FALLBACK_VULNERABLE_NPM.find((candidate) => candidate.name === name);
  if (entry === undefined) {
    return undefined;
  }

  const parsedVersion = parseVersionParts(version);
  if (parsedVersion === undefined) {
    return undefined;
  }

  const parsedFloor = parseVersionParts(entry.vulnerableBelow);
  if (parsedFloor === undefined) {
    // Defensive: every bundled entry's `vulnerableBelow` is hand-authored as
    // a valid x.y.z literal, so this branch is unreachable in practice —
    // guarded anyway so a future malformed entry degrades to "no hit"
    // rather than throwing.
    return undefined;
  }

  if (compareVersionParts(parsedVersion, parsedFloor) >= 0) {
    return undefined;
  }

  if (isPatchedBackport(parsedVersion, entry.backportFixes ?? [])) {
    return undefined;
  }

  return { advisoryId: entry.advisoryId, severity: entry.severity, title: entry.title };
}

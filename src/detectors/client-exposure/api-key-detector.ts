/**
 * clientExposureDetector — text-only CAT-2 (Client-Bundle Key Exposure)
 * detector, BUNDLE-01: a `NEXT_PUBLIC_`/`VITE_` prefix on an env var whose
 * NAME (the portion after the prefix) contains a secret-family keyword
 * (SECRET/KEY/TOKEN/PASSWORD/SERVICE_ROLE).
 *
 * Both Next.js and Vite document these prefixes as an explicit "inline this
 * value into the client bundle" instruction (see
 * .planning/research/PITFALLS.md Pitfall 1 / FEATURES.md CAT-2): the prefix
 * itself is not the bug — pairing it with a secret-named variable is. A
 * secret-named env var behind the prefix gets baked verbatim into the
 * publicly-downloadable browser bundle.
 *
 * Two reference forms are matched per line:
 *   1. The bare identifier `NEXT_PUBLIC_[A-Z0-9_]+` / `VITE_[A-Z0-9_]+`
 *      anywhere on the line (covers `process.env.NEXT_PUBLIC_X`, a raw
 *      `.env` assignment line, a destructure, etc).
 *   2. The Vite-specific access form `import.meta.env.VITE_X` — already
 *      covered by (1)'s bare `VITE_` match since the identifier itself still
 *      appears on the line, so no separate regex is required; documented
 *      here for clarity since the plan calls it out explicitly.
 *
 * CRITICAL FP exclusion (PITFALLS.md Pitfall 1 / FEATURES.md "False Positive
 * Management Strategy" CAT-2 row): Stripe's own documented public key is
 * named `..._PUBLISHABLE_KEY`. That name contains the substring "KEY" and
 * would otherwise match the secret-keyword filter — an explicit
 * PUBLISHABLE exclusion prevents this headline false positive.
 *
 * FP allowlist (PITFALLS.md Pitfall 1): `detect()` opens with the same
 * path-segment + basename check used across this codebase's other text
 * detectors (`__tests__`/`fixtures`/`mocks`/`examples` segments, or a
 * `.test.`/`.stories.` basename) — matching paths short-circuit to `[]`.
 *
 * ENG-05 (text-only invariant): reads `ctx.content` as a plain string only;
 * never imports a parser, never evaluates/requires/spawns from scanned
 * content.
 *
 * No-throw contract (src/core/types.ts `Detector.detect`): the entire body
 * runs inside a try/catch returning `[]` on any failure.
 *
 * Information-disclosure mitigation (T-05-02-01): `Finding.matchedText` is
 * always the variable NAME only — never the secret's runtime value (which
 * this static scanner never even reads, since it only sees the identifier
 * referencing `process.env`/`import.meta.env`, not its resolved value).
 */
import type { Confidence, Detector, DetectorContext, Finding, Severity } from "../../core/types.js";

/** Matches a bare `NEXT_PUBLIC_<NAME>` or `VITE_<NAME>` identifier anywhere on a line. */
const PUBLIC_PREFIX_VAR_RE = /\b(?:NEXT_PUBLIC|VITE)_[A-Z0-9_]+\b/g;

/**
 * Case-insensitive secret-family keywords (FEATURES.md CAT-2 BUNDLE-01 row).
 * Checked against the suffix portion of the matched identifier (the part
 * after the `NEXT_PUBLIC_`/`VITE_` prefix), not the whole identifier — so a
 * prefix containing one of these substrings cannot itself trigger a match.
 */
const SECRET_KEYWORDS = ["SECRET", "KEY", "TOKEN", "PASSWORD", "SERVICE_ROLE"];

/**
 * Documented public/non-secret token that, despite containing "KEY",
 * must NOT fire (Stripe's `..._PUBLISHABLE_KEY` convention — the headline
 * false positive called out in PITFALLS.md Pitfall 1).
 */
const PUBLISHABLE_EXCLUSION = "PUBLISHABLE";

/** Path segments that suppress every finding in this file (FP allowlist — PITFALLS.md Pitfall 1). */
const FP_ALLOWLIST_SEGMENTS = new Set(["__tests__", "fixtures", "mocks", "examples"]);

const RULE_ID = "BUNDLE-01";
const SEVERITY: Severity = "CRITICAL";
const CONFIDENCE: Confidence = "HIGH";
const DETECTOR_NAME = "client-exposure";

/**
 * True when `filePath` falls inside a test/fixture/mock/example directory,
 * or its basename marks it as a test or story file (`.test.` / `.stories.`).
 * Mirrors src/detectors/secrets/entropy-detector.ts `isAllowlistedPath`.
 */
function isAllowlistedPath(filePath: string): boolean {
  const segments = filePath.split("/");
  if (segments.some((segment) => FP_ALLOWLIST_SEGMENTS.has(segment))) {
    return true;
  }
  const basename = segments.at(-1) ?? "";
  return basename.includes(".test.") || basename.includes(".stories.");
}

/**
 * Splits a matched `NEXT_PUBLIC_<NAME>`/`VITE_<NAME>` identifier into its
 * prefix and the suffix the secret-keyword filter must check. Returns
 * `undefined` if the identifier somehow has no underscore separator after
 * the prefix (should not happen given PUBLIC_PREFIX_VAR_RE's shape, but
 * guarded defensively per the no-throw contract).
 */
function splitPrefixAndSuffix(identifier: string): { suffix: string } | undefined {
  if (identifier.startsWith("NEXT_PUBLIC_")) {
    return { suffix: identifier.slice("NEXT_PUBLIC_".length) };
  }
  if (identifier.startsWith("VITE_")) {
    return { suffix: identifier.slice("VITE_".length) };
  }
  return undefined;
}

/**
 * True when `suffix` (the env-var name minus its public prefix) contains a
 * secret-family keyword AND is not covered by the publishable-key
 * exclusion. `suffix` is already uppercase by construction (the regex only
 * matches `[A-Z0-9_]+`), matching the documented uppercase env-var
 * convention — no case-folding needed on this side, but the keyword table
 * itself is treated as the canonical (uppercase) form being checked.
 */
function isSecretNamed(suffix: string): boolean {
  if (suffix.includes(PUBLISHABLE_EXCLUSION)) {
    return false;
  }
  return SECRET_KEYWORDS.some((keyword) => suffix.includes(keyword));
}

export const clientExposureDetector: Detector = {
  config: {
    name: "client-exposure",
    category: "client-exposure",
    globs: ["**/*.{ts,tsx,js,jsx,mjs,cjs}", "**/.env*"],
  },

  // Not declared `async` — this is a text-only, synchronous regex pass; the
  // Detector interface still requires returning `Promise<Finding[]>`.
  detect(ctx: DetectorContext): Promise<Finding[]> {
    try {
      // FP allowlist (PITFALLS.md Pitfall 1): suppress every finding for
      // test/fixture/mock/example/story paths.
      if (isAllowlistedPath(ctx.filePath)) {
        return Promise.resolve([]);
      }

      const findings: Finding[] = [];
      const lines = ctx.content.split("\n");

      // `.entries()` (not bracket indexing) avoids a dynamic-index access
      // pattern entirely — sidesteps security/detect-object-injection.
      for (const [index, line] of lines.entries()) {
        const lineNumber = index + 1; // 1-indexed per src/core/types.ts Finding.line

        for (const match of line.matchAll(PUBLIC_PREFIX_VAR_RE)) {
          const identifier = match[0];
          const split = splitPrefixAndSuffix(identifier);
          if (split === undefined) {
            continue;
          }
          if (!isSecretNamed(split.suffix)) {
            continue;
          }

          findings.push({
            ruleId: RULE_ID,
            category: "client-exposure",
            detectorName: DETECTOR_NAME,
            file: ctx.filePath,
            line: lineNumber,
            severity: SEVERITY,
            confidence: CONFIDENCE,
            message: `Secret-named environment variable '${identifier}' is exposed to the client via its public prefix and will be inlined into the browser bundle.`,
            remediation:
              "Rename this variable without the public prefix (drop NEXT_PUBLIC_/VITE_) so it stays server-only, move it to a server-only env var, and rotate the value — it has likely already shipped to the browser bundle.",
            matchedText: identifier,
          });
        }
      }

      return Promise.resolve(findings);
    } catch {
      // No-throw contract (src/core/types.ts Detector.detect): a malformed
      // or unexpected ctx.content must resolve to [], never reject.
      return Promise.resolve([]);
    }
  },
};

/**
 * corsDetector — CAT-7 (CORS / Security Headers) detector, CORS-01.
 *
 * This is a FILE-level co-occurrence check, not a per-line independent scan:
 * a wildcard `Access-Control-Allow-Origin: *` header is the legitimate public
 * API case on its own (.planning/research/FEATURES.md CAT-7 FP table: "Public
 * APIs legitimately use `*`; downgrade to MEDIUM if no credentials header
 * present" — here, "downgrade" means "do not fire at all", since the FORBIDDEN
 * combination is the trigger, not the wildcard alone). Only when BOTH
 * signals — a wildcard-origin header AND an allow-credentials-true header —
 * are present anywhere in the same file does CORS-01 fire, once, at the
 * wildcard-origin header's line. This keeps false positives near zero: the
 * combination is forbidden by the CORS spec itself (browsers reject it, but
 * misconfigured servers still send it), so co-occurrence is a near-certain
 * signal rather than a heuristic.
 *
 * FP allowlist (.planning/research/PITFALLS.md Pitfall 1): `detect()` opens
 * with a path-segment check against `__tests__`, `fixtures`, `mocks`,
 * `examples`, plus a `.test.`/`.stories.` basename check — matching paths
 * short-circuit to `[]` before the scan runs, mirroring
 * src/detectors/secrets/entropy-detector.ts's `isAllowlistedPath`.
 *
 * ENG-05 (text-only invariant): this module reads `ctx.content` as a plain
 * string. It never reads `ctx.ast`, never imports a parser, and never
 * evaluates, requires, or spawns a subprocess from scanned content.
 *
 * No-throw contract (src/core/types.ts `Detector.detect`): the entire body
 * of `detect()` runs inside a try/catch returning `[]` on any failure, so
 * malformed/empty `ctx.content` can never propagate a rejection.
 */
import type { Detector, DetectorContext, Finding } from "../../core/types.js";

/** Path segments that suppress every finding in this file (FP allowlist — PITFALLS.md Pitfall 1). */
const FP_ALLOWLIST_SEGMENTS = new Set(["__tests__", "fixtures", "mocks", "examples"]);

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
 * Matches an `Access-Control-Allow-Origin` header (case-insensitive header
 * name) assigned a quoted `*` value, across three call styles: HTTP-header
 * literal (`'Access-Control-Allow-Origin': '*'`), `setHeader('Name', 'val')`
 * second-argument style, and JS bracket-index access
 * (`headers['access-control-allow-origin'] = '*'`). The `['"\]]?` class
 * after the header name tolerates an optional closing quote AND/OR bracket
 * char (bracket-index access closes with `']`, not a single quote), and
 * `\s*[,:=]\s*` tolerates arbitrary whitespace around the separator before
 * the quoted value. NO global flag — this pattern is only ever used with
 * `.test()` for a one-shot per-line presence check, never `matchAll`. A
 * global-flagged regex used with `.test()` is stateful (`lastIndex`
 * persists on the shared module-level instance across calls), which
 * silently skips matches on later calls; omitting `g` keeps every `.test()`
 * call independent.
 */
const WILDCARD_ORIGIN_RE = /access-control-allow-origin['"]?\]?\s*[,:=]\s*['"`]\*['"`]/i;

/**
 * Matches an `Access-Control-Allow-Credentials` header (case-insensitive)
 * assigned a quoted `true` value (any quote style, any of the three call
 * styles documented on WILDCARD_ORIGIN_RE above). NO global flag — same
 * `.test()`-statefulness rationale as WILDCARD_ORIGIN_RE above.
 */
const ALLOW_CREDENTIALS_TRUE_RE = /access-control-allow-credentials['"]?\]?\s*[,:=]\s*['"`]true['"`]/i;

export const corsDetector: Detector = {
  config: {
    name: "cors",
    category: "cors-headers",
    globs: ["**/*.{ts,tsx,js,jsx,mjs,cjs,json}"],
  },

  // Not declared `async` — no network/disk wait in this text-only detector;
  // the body is plain synchronous work wrapped in `Promise.resolve()`.
  detect(ctx: DetectorContext): Promise<Finding[]> {
    try {
      // FP allowlist (PITFALLS.md Pitfall 1): suppress every finding for
      // test/fixture/mock/example/story paths.
      if (isAllowlistedPath(ctx.filePath)) {
        return Promise.resolve([]);
      }

      const lines = ctx.content.split("\n");

      // First pass: find the line of the FIRST wildcard-origin header match
      // (if any) — this is the Finding's reported line per the plan's
      // behavior spec ("line = the line of the wildcard-origin header").
      let wildcardOriginLine: number | undefined;
      for (const [index, line] of lines.entries()) {
        if (WILDCARD_ORIGIN_RE.test(line)) {
          wildcardOriginLine = index + 1; // 1-indexed per src/core/types.ts Finding.line
          break;
        }
      }

      if (wildcardOriginLine === undefined) {
        // Signal (a) absent — neither signal alone fires CORS-01.
        return Promise.resolve([]);
      }

      // Second pass: does ANY line in the file carry the allow-credentials
      // true header? This is a whole-file co-occurrence check, not scoped to
      // a single line — the two headers commonly appear on adjacent but
      // separate statements/lines.
      const hasCredentialsTrue = lines.some((line) => ALLOW_CREDENTIALS_TRUE_RE.test(line));

      if (!hasCredentialsTrue) {
        // Signal (b) absent — wildcard-without-credentials is the legitimate
        // public-API case (FEATURES.md CAT-7 FP mitigation). Do not fire.
        return Promise.resolve([]);
      }

      const finding: Finding = {
        ruleId: "CORS-01",
        category: "cors-headers",
        detectorName: "cors",
        file: ctx.filePath,
        line: wildcardOriginLine,
        severity: "CRITICAL",
        confidence: "HIGH",
        message:
          "Access-Control-Allow-Origin '*' combined with Access-Control-Allow-Credentials 'true' is forbidden by the CORS spec and enables cross-origin credential theft.",
        remediation:
          "Replace the wildcard '*' origin with an explicit allowlisted origin (or a dynamic origin-allowlist check) whenever Access-Control-Allow-Credentials is enabled.",
      };

      return Promise.resolve([finding]);
    } catch {
      // No-throw contract (src/core/types.ts Detector.detect): a malformed
      // or unexpected ctx.content must resolve to [], never reject.
      return Promise.resolve([]);
    }
  },
};

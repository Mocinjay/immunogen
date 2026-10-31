/**
 * cspDetector — CAT-7 (CORS / Security Headers) detector, HDR-01.
 *
 * This is an ABSENCE check, not a pattern match: a Next.js `next.config.*`
 * file that never mentions the `Content-Security-Policy` header anywhere in
 * its text — whether inside a `headers()` export or missing a `headers()`
 * export entirely — is reported. Per
 * .planning/research/FEATURES.md CAT-7's HEADER-01 row and
 * .planning/research/PITFALLS.md Pitfall 1, absence evidence is
 * low-certainty by nature (the CSP could legitimately be set elsewhere —
 * custom middleware, a reverse proxy, platform-level headers — so the file
 * alone cannot prove its absence with certainty). The finding is therefore
 * always MEDIUM severity / LOW confidence, never CRITICAL.
 *
 * STACK GATE (T-05-03-01 — see plan threat register): a missing or
 * incorrect "nextjs" stack hint must silently disable this detector rather
 * than over-report on non-Next.js repos. The gate runs first in detect(),
 * checking `ctx.stackHints.frameworks.has("nextjs")` directly. The registry
 * also enforces `DetectorConfig.requiresStack`; the in-code gate keeps direct
 * callers of detect() equally safe.
 *
 * FP allowlist (.planning/research/PITFALLS.md Pitfall 1): `detect()`
 * checks a path-segment guard against `__tests__`, `fixtures`, `mocks`,
 * `examples`, plus a `.test.`/`.stories.` basename check — matching paths
 * short-circuit to `[]`, mirroring
 * src/detectors/secrets/entropy-detector.ts's `isAllowlistedPath`. This
 * runs after the stack gate (cheapest check first) but before the content
 * scan.
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
import { isTestOrFixturePath } from "../shared/test-paths.js";

/** Case-insensitive substring check for the literal header name `Content-Security-Policy`. */
const CSP_MARKER_RE = /content-security-policy/i;

export const cspDetector: Detector = {
  config: {
    name: "csp",
    category: "cors-headers",
    globs: ["next.config.js", "next.config.ts", "next.config.mjs", "next.config.cjs"],
    // Declarative — read by future registry wiring (05-08). The registry
    // does not yet honor this field, so the gate below ALSO runs in code.
    requiresStack: ["nextjs"],
  },

  // Not declared `async` — no network/disk wait in this text-only detector;
  // the body is plain synchronous work wrapped in `Promise.resolve()`.
  detect(ctx: DetectorContext): Promise<Finding[]> {
    try {
      // STACK GATE FIRST: mirrors config.requiresStack (enforced by the
      // registry) for direct callers of detect().
      if (!ctx.stackHints.frameworks.has("nextjs")) {
        return Promise.resolve([]);
      }

      // FP allowlist (PITFALLS.md Pitfall 1): suppress every finding for
      // test/fixture/mock/example/story paths.
      if (isTestOrFixturePath(ctx.filePath)) {
        return Promise.resolve([]);
      }

      if (CSP_MARKER_RE.test(ctx.content)) {
        // CSP is configured somewhere in this file — nothing to report.
        return Promise.resolve([]);
      }

      const finding: Finding = {
        ruleId: "HDR-01",
        category: "cors-headers",
        detectorName: "csp",
        file: ctx.filePath,
        line: 1,
        severity: "MEDIUM",
        confidence: "LOW",
        message: "No Content-Security-Policy configured in the Next.js headers.",
        remediation:
          "Add a headers() export to next.config.js/ts that returns a Content-Security-Policy header for every route (see https://nextjs.org/docs/app/api-reference/config/next-config-js/headers and https://nextjs.org/docs/app/building-your-application/configuring/content-security-policy).",
      };

      return Promise.resolve([finding]);
    } catch {
      // No-throw contract (src/core/types.ts Detector.detect): a malformed
      // or unexpected ctx.content must resolve to [], never reject.
      return Promise.resolve([]);
    }
  },
};

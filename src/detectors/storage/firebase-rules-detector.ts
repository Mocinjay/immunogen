/**
 * firebaseRulesDetector — CAT-3 (Auth) + CAT-8 (Storage) detector, ONE
 * detector emitting two ruleIds: AUTH-02 and STORAGE-01.
 *
 * Both requirements collapse into the same exact string match per
 * .planning/research/FEATURES.md: a Firebase Firestore/Database/Storage
 * rules file containing the unambiguous `allow ...: if true` directive
 * grants public read/write to every document or object it covers — this is
 * the root cause behind CVE-2025-48757-class AI-app breaches. FEATURES.md
 * names this row "AUTH-04" (CAT-3) / "STORAGE-01" (CAT-8); this plan's own
 * requirements field and acceptance criteria use "AUTH-02" for the CAT-3
 * side, matching the 05-02/05-03 precedent that the plan's literal naming
 * is authoritative over FEATURES.md's row label.
 *
 * Which ruleId fires is decided by file basename, not directory: a
 * `storage.rules` file emits STORAGE-01/category "storage"; any other rules
 * file (`firestore.rules`, `database.rules.json`, or another `*.rules`
 * file) emits AUTH-02/category "auth". Both share severity CRITICAL,
 * confidence HIGH — per PITFALLS.md Pitfall 1's confidence-discipline rule,
 * absence-evidence findings are never CRITICAL, but THIS is not absence
 * evidence: `if true` is a literal, unambiguous condition present in the
 * scanned text, so CRITICAL/HIGH is correct here (contrast with the
 * Supabase detector's absence-based AUTH-03/STORAGE-02, which must never
 * reach CRITICAL).
 *
 * STACK GATE (ctx.stackHints.hasFirebase, src/core/ingest/stack-detector.ts):
 * checked FIRST, before any other logic — mirrors
 * src/detectors/payment/stripe-detector.ts's hasStripe gate. The gate lives
 * inside detect() itself (not the registry) per this plan's contract;
 * config.requiresStack is declarative metadata for the registry-wiring plan
 * (05-08).
 *
 * FP allowlist (.planning/research/PITFALLS.md Pitfall 1): `detect()` also
 * opens with the same path-segment check against `__tests__`, `fixtures`,
 * `mocks`, `examples`, plus a `.test.`/`.stories.` basename check, mirroring
 * src/detectors/secrets/entropy-detector.ts's `isAllowlistedPath`.
 *
 * ENG-05 (text-only invariant): this module reads `ctx.content` as a plain
 * string. It never reads `ctx.ast`, never imports a parser, and never
 * evaluates, requires, or spawns a subprocess from scanned content.
 *
 * No-throw contract (src/core/types.ts `Detector.detect`): the entire body
 * of `detect()` runs inside a try/catch returning `[]` on any failure, so a
 * malformed/empty `ctx.content` can never propagate a rejection.
 */
import type { Category, Detector, DetectorContext, Finding } from "../../core/types.js";

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
 * Matches an `allow` directive whose condition is literally `if true`,
 * tolerant of which operations are listed (`allow read`, `allow write`,
 * `allow read, write`, etc.) and of flexible whitespace around the colon
 * and the `if true` clause. NO global flag — this pattern is only ever
 * used with `.test()` for a one-shot per-line presence check inside a
 * line loop, never `matchAll`. A global-flagged regex used with `.test()`
 * is stateful (`lastIndex` persists on the shared module-level instance
 * across calls), which silently skips matches on later lines — the exact
 * gotcha documented on src/detectors/cors-headers/cors-detector.ts's
 * WILDCARD_ORIGIN_RE and src/detectors/payment/stripe-detector.ts's
 * STRIPE_IMPORT_RE.
 */
const ALLOW_IF_TRUE_RE = /allow\s+[\w,\s]+:\s*if\s+true\s*;/i;

/**
 * True when `basename` (the file's own last path segment) is exactly
 * `storage.rules` — the only basename that routes to STORAGE-01 instead of
 * AUTH-02. Case-sensitive: Firebase's CLI always emits this exact lowercase
 * filename, so an exact match avoids accidentally reclassifying an
 * unrelated `*Storage.rules`-style file a hostile repo might construct.
 */
function isStorageRulesFile(filePath: string): boolean {
  const segments = filePath.split("/");
  const basename = segments.at(-1) ?? "";
  return basename === "storage.rules";
}

export const firebaseRulesDetector: Detector = {
  config: {
    name: "firebase-rules",
    category: "storage",
    globs: ["**/firestore.rules", "**/storage.rules", "**/database.rules.json", "**/*.rules"],
    requiresStack: ["firebase"],
  },

  // Not declared `async` — no network/disk wait in this text-only detector;
  // the body is plain synchronous work wrapped in `Promise.resolve()`.
  detect(ctx: DetectorContext): Promise<Finding[]> {
    try {
      // STACK GATE FIRST (per this plan's contract): a repo with no Firebase
      // dependency/config never runs the rest of the scan.
      if (!ctx.stackHints.hasFirebase) {
        return Promise.resolve([]);
      }

      // FP allowlist (PITFALLS.md Pitfall 1): suppress every finding for
      // test/fixture/mock/example/story paths.
      if (isAllowlistedPath(ctx.filePath)) {
        return Promise.resolve([]);
      }

      const findings: Finding[] = [];
      const lines = ctx.content.split("\n");
      const emitsStorageRule = isStorageRulesFile(ctx.filePath);
      const ruleId = emitsStorageRule ? "STORAGE-01" : "AUTH-02";
      const category: Category = emitsStorageRule ? "storage" : "auth";

      // `.entries()` (not bracket indexing) avoids a dynamic-index access
      // pattern entirely — sidesteps security/detect-object-injection.
      for (const [index, line] of lines.entries()) {
        if (!ALLOW_IF_TRUE_RE.test(line)) {
          continue;
        }

        findings.push({
          ruleId,
          category,
          detectorName: "firebase-rules",
          file: ctx.filePath,
          line: index + 1, // 1-indexed per src/core/types.ts Finding.line
          severity: "CRITICAL",
          confidence: "HIGH",
          message: "Firebase rule grants public read/write access (allow ...: if true).",
          remediation:
            "Replace 'if true' with an auth/ownership condition, e.g. 'if request.auth != null' plus a uid/ownership check on the matched document or object.",
          matchedText: line.trim(),
        });
      }

      return Promise.resolve(findings);
    } catch {
      // No-throw contract (src/core/types.ts Detector.detect): a malformed
      // or unexpected ctx.content must resolve to [], never reject.
      return Promise.resolve([]);
    }
  },
};

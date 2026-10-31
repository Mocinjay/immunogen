/**
 * firebaseRulesDetector — CAT-3 (Auth) + CAT-8 (Storage) detector, ONE
 * detector emitting two ruleIds: AUTH-02 and STORAGE-01.
 *
 * Both rules collapse into the same exact string match: a Firebase Firestore/Database/Storage
 * rules file containing the unambiguous `allow ...: if true` directive
 * grants public read/write to every document or object it covers — this is
 * the root cause behind CVE-2025-48757-class AI-app breaches.
 *
 * Which ruleId fires is decided by file basename, not directory: a
 * `storage.rules` file emits STORAGE-01/category "storage"; any other rules
 * file (`firestore.rules`, `database.rules.json`, or another `*.rules`
 * file) emits AUTH-02/category "auth". Both share severity CRITICAL,
 * confidence HIGH — absence-evidence findings are never CRITICAL, but THIS is not absence
 * evidence: `if true` is a literal, unambiguous condition present in the
 * scanned text, so CRITICAL/HIGH is correct here (contrast with the
 * Supabase detector's absence-based AUTH-03/STORAGE-02, which must never
 * reach CRITICAL).
 *
 * Beyond the literal `if true`, three more shapes AI tools ship constantly:
 *   - Firestore/Storage "test mode" — `allow read, write: if request.time <
 *     timestamp.date(...)` — the Firebase console's own starter rule: wide
 *     open to the world until that date (CRITICAL/HIGH, same ruleIds).
 *   - Realtime Database `database.rules.json` with `".read": true` or
 *     `".write": true` (CRITICAL/HIGH, AUTH-02).
 *   - `allow read, write: if request.auth != null` on a recursive wildcard
 *     (`match /{document=**}`) — any signed-up user can read and overwrite
 *     every other user's data (HIGH/HIGH, same ruleIds).
 *
 * STACK GATE (ctx.stackHints.hasFirebase, src/core/ingest/stack-detector.ts):
 * applies to generic `*.rules` files only — `firestore.rules`,
 * `storage.rules`, and `database.rules.json` are Firebase by name, so they
 * are always checked (a rules file can ship without the web SDK in the root
 * package.json, e.g. a mobile app or a backend-only repo). Checked FIRST,
 * before any other logic — mirrors
 * src/detectors/payment/stripe-detector.ts's hasStripe gate. The gate lives
 * inside detect() itself rather than in config.requiresStack, because it is
 * deliberately broader than "Firebase dependency detected".
 *
 * FP allowlist: `detect()` also
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
import type { Category, Detector, DetectorContext, Finding, Severity } from "../../core/types.js";
import { isTestOrFixturePath } from "../shared/test-paths.js";

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

/** The Firebase console's "test mode" starter rule: open to everyone until a fixed date. */
const TEST_MODE_RE = /allow\s+[\w,\s]+:\s*if\s+request\.time\s*<\s*timestamp\.date\s*\(/i;

/** A rule whose ONLY condition is "signed in" — no ownership check. */
const ANY_SIGNED_IN_RE = /allow\s+[\w,\s]+:\s*if\s+request\.auth\s*!=\s*null\s*;/i;

/** A recursive wildcard match (`match /{document=**}` / `match /{allPaths=**}`). */
const RECURSIVE_MATCH_RE = /match\s+\/\{\w+=\*\*\}/;

/** Realtime Database rule granting public read or write. */
const RTDB_PUBLIC_RE = /"\.(?:read|write)"\s*:\s*(?:true|"true")/;

/** Rules-file basenames that are Firebase by name alone (exempt from the stack gate). */
const FIREBASE_RULES_BASENAMES = new Set(["firestore.rules", "storage.rules", "database.rules.json"]);

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
    // No requiresStack: firestore.rules / storage.rules / database.rules.json
    // are Firebase by name and are checked even without a Firebase dependency
    // (see the STACK GATE note above); the in-code gate handles *.rules.
    globs: ["**/firestore.rules", "**/storage.rules", "**/database.rules.json", "**/*.rules"],
  },

  // Not declared `async` — no network/disk wait in this text-only detector;
  // the body is plain synchronous work wrapped in `Promise.resolve()`.
  detect(ctx: DetectorContext): Promise<Finding[]> {
    try {
      // STACK GATE FIRST: a generic `*.rules`
      // file in a repo with no Firebase dependency/config is not Firebase.
      const basename = ctx.filePath.split("/").at(-1) ?? "";
      if (!ctx.stackHints.hasFirebase && !FIREBASE_RULES_BASENAMES.has(basename)) {
        return Promise.resolve([]);
      }

      // FP allowlist: suppress every finding for
      // test/fixture/mock/example/story paths.
      if (isTestOrFixturePath(ctx.filePath)) {
        return Promise.resolve([]);
      }

      const findings: Finding[] = [];
      const lines = ctx.content.split("\n");
      const emitsStorageRule = isStorageRulesFile(ctx.filePath);
      const ruleId = emitsStorageRule ? "STORAGE-01" : "AUTH-02";
      const category: Category = emitsStorageRule ? "storage" : "auth";
      const push = (index: number, line: string, severity: Severity, message: string, remediation: string): void => {
        findings.push({
          ruleId,
          category,
          detectorName: "firebase-rules",
          file: ctx.filePath,
          line: index + 1, // 1-indexed per src/core/types.ts Finding.line
          severity,
          confidence: "HIGH",
          message,
          remediation,
          matchedText: line.trim(),
        });
      };

      // Brace depth of the innermost open recursive-wildcard match block
      // (`match /{document=**} {`), or undefined when outside one.
      let depth = 0;
      let recursiveMatchDepth: number | undefined;

      // `.entries()` (not bracket indexing) avoids a dynamic-index access
      // pattern entirely — sidesteps security/detect-object-injection.
      for (const [index, line] of lines.entries()) {
        if (RECURSIVE_MATCH_RE.test(line) && recursiveMatchDepth === undefined) {
          recursiveMatchDepth = depth;
        }
        depth += (line.match(/\{/g) ?? []).length - (line.match(/\}/g) ?? []).length;
        if (recursiveMatchDepth !== undefined && depth <= recursiveMatchDepth) {
          recursiveMatchDepth = undefined;
        }

        if (ALLOW_IF_TRUE_RE.test(line) || RTDB_PUBLIC_RE.test(line)) {
          push(
            index,
            line,
            "CRITICAL",
            "Firebase rule grants public read/write access (allow ...: if true).",
            "Replace 'if true' with an auth/ownership condition, e.g. 'if request.auth != null' plus a uid/ownership check on the matched document or object.",
          );
        } else if (TEST_MODE_RE.test(line)) {
          push(
            index,
            line,
            "CRITICAL",
            "Firebase test-mode rule grants public read/write until a fixed date (if request.time < timestamp.date(...)) — anyone can read and overwrite all data until then.",
            "Replace the test-mode rule with per-collection rules that check request.auth.uid against the document owner before launch.",
          );
        } else if (recursiveMatchDepth !== undefined && ANY_SIGNED_IN_RE.test(line)) {
          push(
            index,
            line,
            "HIGH",
            "Firebase rule lets ANY signed-in user read/write every document (if request.auth != null on a recursive wildcard) — users can read and overwrite each other's data.",
            "Scope rules per collection and compare request.auth.uid with the document's owner field (e.g. resource.data.userId == request.auth.uid).",
          );
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

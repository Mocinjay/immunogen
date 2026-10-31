/**
 * legalDetector — CAT-9 (Legal/Compliance) detector, LEGAL-01.
 *
 * Informational absence check: no privacy-policy or terms-of-service route
 * or static file anywhere in the repo. Rated MEDIUM/LOW (never CRITICAL —
 * per .planning/research/PITFALLS.md, absence-of-evidence findings must
 * stay informational, not alarming) because the check has real FP risk
 * (internal tooling with no public users legitimately has neither) — see
 * .planning/research/FEATURES.md CAT-9 LEGAL-01 row: "FP if app is internal
 * tooling with no public users; note as 'required if collecting user data'".
 *
 * WHOLE-REPO FIRES-ONCE PATTERN (see this plan's <whole_repo_detector_note>):
 * the detector registry calls detect() once per matching file, but this is a
 * whole-repo absence check that must fire exactly once total, not once per
 * file. The fix: declare `globs: ["package.json"]` so detect() is invoked on
 * exactly one deterministic anchor file (every scanned repo has exactly one
 * package.json at root), then read the FULL `ctx.fileSet` map — not just
 * `ctx.content`/`ctx.filePath` — to make the repo-wide decision. This is the
 * same anchor-on-a-guaranteed-singleton-file, decide-from-fileSet pattern
 * the registry-wiring plan (05-08) will reuse for any other whole-repo
 * detector.
 *
 * APP GATE: only a repo whose stack shows a user-facing app (a web or mobile
 * framework, Supabase/Firebase, or Stripe) can "collect user data" — a
 * library, CLI, or config repo never gets LEGAL-01.
 *
 * ENG-05 (text-only invariant): this module reads `ctx.fileSet` keys as
 * plain strings. It never reads `ctx.ast`, never imports a parser, and
 * never evaluates, requires, or spawns a subprocess from scanned content.
 *
 * No-throw contract (src/core/types.ts `Detector.detect`): the entire body
 * of `detect()` runs inside a try/catch returning `[]` on any failure, so a
 * malformed/empty `ctx.fileSet` can never propagate a rejection.
 */
import type { Detector, DetectorContext, Finding } from "../../core/types.js";

/**
 * Path-component vocabulary that counts as privacy/terms compliance
 * evidence. Matched against individual path segments AND basenames
 * (without extension) so `app/privacy/page.tsx` (segment `privacy`),
 * `pages/terms.tsx` (basename `terms`), and `public/privacy-policy.html`
 * (basename `privacy-policy`) all count as present, per
 * .planning/research/FEATURES.md CAT-9 LEGAL-01's named vocabulary.
 */
const PRIVACY_TERMS_VOCABULARY = new Set([
  "privacy",
  "privacy-policy",
  "privacy_policy",
  "terms",
  "terms-of-service",
  "terms_of_service",
  "tos",
]);

/**
 * Strips a trailing file extension from `basename` (the part after the
 * last `.`, if any) so `privacy-policy.html` and `terms.tsx` compare
 * against PRIVACY_TERMS_VOCABULARY the same way their bare segment form
 * would (`privacy-policy`, `terms`).
 */
function stripExtension(basename: string): string {
  const lastDot = basename.lastIndexOf(".");
  if (lastDot <= 0) {
    // No extension, or a dotfile with nothing before the dot (e.g. ".env")
    // — return as-is rather than truncating to an empty string.
    return basename;
  }
  return basename.slice(0, lastDot);
}

/**
 * True when `path` (a single fileSet key) has any path segment, or its
 * extension-stripped basename, matching the PRIVACY_TERMS_VOCABULARY —
 * counts route directories (`app/privacy/page.tsx`), route files
 * (`pages/terms.tsx`), and static files (`public/privacy-policy.html`)
 * uniformly.
 */
function pathHasPrivacyOrTermsEvidence(path: string): boolean {
  const lower = path.toLowerCase();
  const segments = lower.split("/");
  if (segments.some((segment) => PRIVACY_TERMS_VOCABULARY.has(segment))) {
    return true;
  }
  const basename = segments.at(-1) ?? "";
  const basenameNoExt = stripExtension(basename);
  return PRIVACY_TERMS_VOCABULARY.has(basenameNoExt);
}

/** Stack hints that mark a user-facing app (see APP GATE above). */
const APP_FRAMEWORKS = [
  "nextjs",
  "vite",
  "express",
  "fastify",
  "hono",
  "koa",
  "react-native",
  "supabase",
  "firebase",
  "fastapi",
  "flask",
  "django",
  "gin",
  "echo",
  "chi",
  "fiber",
];

/**
 * Root manifests that can anchor this whole-repo check, in priority order:
 * the first one present is the single anchor, so a repo with both a
 * package.json and a pyproject.toml still gets exactly one finding.
 */
const ANCHOR_MANIFESTS = ["package.json", "pyproject.toml", "requirements.txt", "go.mod"];

export const legalDetector: Detector = {
  config: {
    name: "legal",
    category: "legal",
    // Fires-once anchor (see file header): root manifests only, and detect()
    // returns early for every one but the highest-priority manifest present
    // (ANCHOR_MANIFESTS), so this whole-repo absence check runs once total.
    globs: ANCHOR_MANIFESTS,
  },

  // Not declared `async` — no network/disk wait in this text-only detector;
  // the body is plain synchronous work wrapped in `Promise.resolve()`.
  detect(ctx: DetectorContext): Promise<Finding[]> {
    try {
      const anchor = ANCHOR_MANIFESTS.find((manifest) => ctx.fileSet.has(manifest)) ?? ctx.filePath;
      if (ctx.filePath !== anchor) {
        return Promise.resolve([]);
      }

      const { frameworks, hasStripe } = ctx.stackHints;
      const isUserFacingApp = hasStripe || APP_FRAMEWORKS.some((framework) => frameworks.has(framework));
      if (!isUserFacingApp) {
        return Promise.resolve([]);
      }

      // Whole-repo decision: scan every key in ctx.fileSet (not just this
      // anchor file's own content/path) for privacy/terms evidence.
      for (const path of ctx.fileSet.keys()) {
        if (pathHasPrivacyOrTermsEvidence(path)) {
          // Compliance page or file exists somewhere in the repo — clean.
          return Promise.resolve([]);
        }
      }

      const finding: Finding = {
        ruleId: "LEGAL-01",
        category: "legal",
        detectorName: "legal",
        file: ctx.filePath,
        line: 1,
        severity: "MEDIUM",
        confidence: "LOW",
        message: "No privacy-policy or terms page found; required if the app collects user data.",
        remediation: "Add a /privacy and /terms route or static page if the app collects personal data.",
      };

      return Promise.resolve([finding]);
    } catch {
      // No-throw contract (src/core/types.ts Detector.detect): a malformed
      // or unexpected ctx.fileSet must resolve to [], never reject.
      return Promise.resolve([]);
    }
  },
};

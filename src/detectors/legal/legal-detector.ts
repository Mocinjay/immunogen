/**
 * legalDetector — CAT-9 (Legal/Compliance) detector, LEGAL-01.
 *
 * Informational absence check: no privacy-policy or terms-of-service route
 * or static file anywhere in the repo. Rated MEDIUM/LOW (never CRITICAL —
 * absence-of-evidence findings stay informational, not alarming) because the
 * check has real FP risk: internal tooling with no public users
 * legitimately has neither, so the finding is worded as "required if
 * collecting user data".
 *
 * WHOLE-REPO FIRES-ONCE PATTERN:
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
 * (basename `privacy-policy`) all count as present.
 */
const PRIVACY_TERMS_VOCABULARY = new Set([
  "privacy",
  "privacypolicy",
  "terms",
  "termsofservice",
  "termsofuse",
  "termsandconditions",
  "tos",
  "legal",
]);

/**
 * Lowercases and drops separators, so `PrivacyPolicy`, `privacy-policy`,
 * `privacy_policy` and `Terms-Of-Service` all compare equal to the
 * vocabulary above (Lovable / Bolt generate PascalCase page components).
 */
function normalizeName(name: string): string {
  return name.toLowerCase().replace(/[^a-z0-9]/g, "");
}

function stripExtension(basename: string): string {
  const lastDot = basename.lastIndexOf(".");
  if (lastDot <= 0) {
    // No extension, or a dotfile with nothing before the dot (e.g. ".env")
    // — return as-is rather than truncating to an empty string.
    return basename;
  }
  return basename.slice(0, lastDot);
}

function pathHasPrivacyOrTermsEvidence(path: string): boolean {
  const segments = path.split("/");
  const basename = segments.at(-1) ?? "";
  return [...segments.slice(0, -1), stripExtension(basename)].some((segment) =>
    PRIVACY_TERMS_VOCABULARY.has(normalizeName(segment)),
  );
}

/** A route path or link to a privacy / terms page in source (`<Route path="/privacy">`, `href="/terms"`, a hosted policy URL). */
const LEGAL_ROUTE_RE = /\/(?:privacy|terms|legal|tos)[\w-]{0,30}["'`/?#]/i;

/** Source files whose text may route or link to a legal page. */
const ROUTE_SOURCE_RE = /\.(?:[cm]?[jt]sx?|vue|svelte|astro|html?)$/;

function contentHasLegalRoute(fileSet: ReadonlyMap<string, string>): boolean {
  for (const [path, content] of fileSet) {
    if (ROUTE_SOURCE_RE.test(path) && LEGAL_ROUTE_RE.test(content)) {
      return true;
    }
  }
  return false;
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

      // Whole-repo decision: a privacy/terms page file anywhere, or a route
      // or link to one in source, is evidence (not just this anchor file).
      for (const path of ctx.fileSet.keys()) {
        if (pathHasPrivacyOrTermsEvidence(path)) {
          // Compliance page or file exists somewhere in the repo — clean.
          return Promise.resolve([]);
        }
      }
      if (contentHasLegalRoute(ctx.fileSet)) {
        return Promise.resolve([]);
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

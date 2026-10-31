/**
 * supabaseDetector — CAT-3 (Auth) + CAT-8 (Storage) detector, ONE detector
 * emitting two ruleIds: AUTH-03 and STORAGE-02. Both are Supabase
 * absence/structural signals — neither one observes a literal bug in the
 * scanned text, only the ABSENCE of corroborating evidence elsewhere in the
 * repo — so both are calibrated LOW/MEDIUM confidence and NEVER CRITICAL
 * (contrast with src/detectors/storage/firebase-rules-detector.ts's
 * AUTH-02/STORAGE-01, where the exact `if true` string IS unambiguous and
 * correctly CRITICAL).
 *
 * AUTH-03 (RLS absence — HIGH severity, LOW confidence, "verify manually"):
 * a Supabase anon-client table
 * query (`supabase.from(...).select/insert/update/delete`) with no
 * corresponding RLS policy file anywhere in `supabase/migrations/` or
 * `supabase/schema.sql` is the single most common root cause of the
 * CVE-2025-48757-class AI-app breach (the anon key — the only key most
 * AI-generated frontends ever see — can read/write every row in a table
 * with no RLS policy enabled). This is absence evidence, and policies may
 * live in OTHER migration files — so the policy check MUST be
 * computed once across the WHOLE repo's `ctx.fileSet`, not just the current
 * file, before deciding to fire (mirrors src/detectors/legal/legal-detector.ts's
 * whole-repo-fact pattern, but this detector keeps its per-file glob/anchor
 * since the query SITE — not a fixed singleton file — is what's reported).
 *
 * STORAGE-02 (public bucket no policy — MEDIUM severity, LOW/MEDIUM
 * confidence, "verify access policy"): a public bucket is "not inherently wrong (CDN assets) but combined with no policy
 * is high-risk" — so this, too, is calibrated below CRITICAL and reuses the
 * same repo-wide policy-evidence computation.
 *
 * STACK GATE (ctx.stackHints.hasSupabase, src/core/ingest/stack-detector.ts):
 * checked FIRST, mirrors src/detectors/payment/stripe-detector.ts's
 * hasStripe gate. The registry enforces config.requiresStack ("supabase");
 * the in-code gate repeats it for direct callers of detect().
 *
 * FP allowlist: `detect()` also
 * opens with the same path-segment check against `__tests__`, `fixtures`,
 * `mocks`, `examples`, plus a `.test.`/`.stories.` basename check, mirroring
 * src/detectors/secrets/entropy-detector.ts's `isAllowlistedPath`.
 *
 * ENG-05 (text-only invariant): this module reads `ctx.content` and
 * `ctx.fileSet` values as plain strings. It never reads `ctx.ast`, never
 * imports a parser, and never evaluates, requires, or spawns a subprocess
 * from scanned content.
 *
 * No-throw contract (src/core/types.ts `Detector.detect`): the entire body
 * of `detect()` runs inside a try/catch returning `[]` on any failure, so a
 * malformed/empty `ctx.content`/`ctx.fileSet` can never propagate a
 * rejection.
 */
import type { Detector, DetectorContext, Finding } from "../../core/types.js";
import { isTestOrFixturePath } from "../shared/test-paths.js";

/**
 * Matches a Supabase anon-client table query: `supabase.from(...)`
 * immediately followed (possibly across a `.then`/await chain on the same
 * line) by one of the four CRUD method calls. NO global flag — used only
 * with `.test()` for a one-shot per-line presence check inside a line loop,
 * never `matchAll`; same stateful-`lastIndex` gotcha documented on
 * src/detectors/payment/stripe-detector.ts's STRIPE_IMPORT_RE.
 */
const SUPABASE_QUERY_RE = /supabase\s*\.\s*from\s*\([^)]*\)\s*\.\s*(?:select|insert|update|delete)\s*\(/;

/**
 * Matches `supabase.storage.createBucket(<name>, { ... public: true ... })`,
 * tolerant of spacing and single/double/backtick quoting of the bucket
 * name and of additional options before/after `public: true` in the options
 * object. NO global flag — same one-shot `.test()` rationale as
 * SUPABASE_QUERY_RE above.
 */
const PUBLIC_CREATE_BUCKET_RE =
  /supabase\s*\.\s*storage\s*\.\s*createBucket\s*\(\s*(?:'[^']*'|"[^"]*"|`[^`]*`)\s*,\s*\{[^}]*public\s*:\s*true[^}]*\}\s*\)/;

/**
 * Substring vocabulary that, found case-insensitively anywhere in a
 * `supabase/migrations/*.sql` or `supabase/schema.sql` file's content,
 * counts as RLS-policy evidence — covers both enabling RLS on a table and
 * defining an actual policy. Shared by both AUTH-03 and STORAGE-02: a
 * storage policy is itself a `create policy` statement (Supabase storage
 * policies live in `storage.objects`/`storage.buckets`, defined the same
 * way as table policies), so one evidence check serves both ruleIds.
 */
const POLICY_EVIDENCE_MARKERS = ["create policy", "enable row level security"];

/** True when `path` is a Supabase migration/schema file this detector treats as policy-evidence-eligible. */
function isPolicyEvidenceFile(path: string): boolean {
  const lower = path.toLowerCase();
  if (lower === "supabase/schema.sql") {
    return true;
  }
  return lower.startsWith("supabase/migrations/") && lower.endsWith(".sql");
}

/** True when `content` (case-insensitive) contains any POLICY_EVIDENCE_MARKERS substring. */
function hasPolicyMarker(content: string): boolean {
  const lower = content.toLowerCase();
  return POLICY_EVIDENCE_MARKERS.some((marker) => lower.includes(marker));
}

/**
 * Computes whether ANY RLS/storage-policy evidence exists anywhere in the
 * repo: a `supabase/migrations/*.sql` or `supabase/schema.sql` file whose
 * content contains `create policy` or `enable row level security`
 * (case-insensitive). Policy presence is a repo-wide fact, so this is
 * computed once from the full `ctx.fileSet`, not per-line/per-file —
 * mirrors src/detectors/legal/legal-detector.ts's whole-repo fileSet scan.
 */
function repoHasPolicyEvidence(fileSet: ReadonlyMap<string, string>): boolean {
  for (const [path, content] of fileSet) {
    if (isPolicyEvidenceFile(path) && hasPolicyMarker(content)) {
      return true;
    }
  }
  return false;
}

export const supabaseDetector: Detector = {
  config: {
    name: "supabase",
    category: "auth",
    globs: ["**/*.{ts,tsx,js,jsx,mjs,cjs}"],
    requiresStack: ["supabase"],
  },

  // Not declared `async` — no network/disk wait in this text-only detector;
  // the body is plain synchronous work wrapped in `Promise.resolve()`.
  detect(ctx: DetectorContext): Promise<Finding[]> {
    try {
      // STACK GATE FIRST: a repo with no Supabase
      // dependency/config never runs the rest of the scan.
      if (!ctx.stackHints.hasSupabase) {
        return Promise.resolve([]);
      }

      // FP allowlist: suppress every finding for
      // test/fixture/mock/example/story paths.
      if (isTestOrFixturePath(ctx.filePath)) {
        return Promise.resolve([]);
      }

      const findings: Finding[] = [];
      const lines = ctx.content.split("\n");
      // Policy presence is a repo-wide fact — compute it once per detect()
      // call, not once per matched line.
      const hasPolicyEvidence = repoHasPolicyEvidence(ctx.fileSet);

      // `.entries()` (not bracket indexing) avoids a dynamic-index access
      // pattern entirely — sidesteps security/detect-object-injection.
      for (const [index, line] of lines.entries()) {
        const lineNumber = index + 1; // 1-indexed per src/core/types.ts Finding.line

        // AUTH-03: anon-client query with NO RLS-policy evidence anywhere
        // in the repo. NEVER CRITICAL — absence evidence — HIGH severity but LOW confidence, explicitly worded
        // "verify manually" so the report reads as a flag, not a verdict.
        if (!hasPolicyEvidence && SUPABASE_QUERY_RE.test(line)) {
          findings.push({
            ruleId: "AUTH-03",
            category: "auth",
            detectorName: "supabase",
            file: ctx.filePath,
            line: lineNumber,
            severity: "HIGH",
            confidence: "LOW",
            message:
              "Supabase anon-client query with no RLS policy file found anywhere in the repo — verify manually that Row Level Security is enabled.",
            remediation:
              "Enable Row Level Security on this table and add a policy migration under supabase/migrations/ (or supabase/schema.sql) restricting access to the intended owner/role.",
            matchedText: line.trim(),
          });
        }

        // STORAGE-02: public bucket created with NO storage-policy evidence
        // anywhere in the repo. NEVER CRITICAL — same absence-evidence
        // discipline — MEDIUM severity, LOW confidence, "verify access
        // policy" wording.
        if (!hasPolicyEvidence && PUBLIC_CREATE_BUCKET_RE.test(line)) {
          findings.push({
            ruleId: "STORAGE-02",
            category: "storage",
            detectorName: "supabase",
            file: ctx.filePath,
            line: lineNumber,
            severity: "MEDIUM",
            confidence: "LOW",
            message:
              "Public Supabase bucket created with no storage policy found anywhere in the repo — verify access policy.",
            remediation:
              "Add a storage RLS policy restricting object access (e.g. owner-only writes), or set the bucket to private if public access is not intended.",
            matchedText: line.trim(),
          });
        }
      }

      return Promise.resolve(findings);
    } catch {
      // No-throw contract (src/core/types.ts Detector.detect): a malformed
      // or unexpected ctx.content/ctx.fileSet must resolve to [], never
      // reject.
      return Promise.resolve([]);
    }
  },
};

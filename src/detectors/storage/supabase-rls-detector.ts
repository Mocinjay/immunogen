/**
 * supabaseRlsDetector — CAT-3 Supabase Row Level Security detector, reading
 * the project's SQL migrations (`supabase/migrations/*.sql`,
 * `supabase/schema.sql`, or any `.sql` file in a Supabase project).
 *
 * Supabase exposes every table in the `public` schema through its REST API
 * to anyone holding the project's anon key — and the anon key ships inside
 * every web and mobile client by design. Row Level Security is the ONLY
 * thing standing between that key and the data. The most reproduced
 * AI-built-app breach (CVE-2025-48757, 170+ exposed Lovable apps) is exactly
 * a table without RLS, or a policy that lets everyone through.
 *
 *   AUTH-04 (CRITICAL/HIGH): a `public` table created in the migrations with
 *   no `alter table ... enable row level security` for it in ANY migration,
 *   or a migration that explicitly disables RLS.
 *
 *   AUTH-05: a permissive policy that lets writes through unconditionally —
 *   `using (true)` / `with check (true)` on `for all|insert|update|delete`.
 *   CRITICAL when it applies to everyone (`to public` / `to anon` / no `to`
 *   clause), HIGH when it applies to `authenticated` (any signed-up user can
 *   modify every row). Read-only `for select using (true)` is left alone —
 *   public read is a common, deliberate choice.
 *
 * Unlike the repo-wide AUTH-03 heuristic in supabase-detector.ts (which only
 * asks "is there ANY policy file?"), this detector checks each table and
 * each policy individually, so one well-protected table can no longer hide
 * an unprotected one next to it.
 *
 * Text-only (ENG-05): reads SQL as plain strings; never runs it.
 *
 * No-throw contract (src/core/types.ts Detector.detect): the whole body runs
 * inside a try/catch returning `[]` on any failure.
 */
import type { Detector, DetectorContext, Finding, Severity } from "../../core/types.js";
import { isInTestDirectory } from "../shared/test-paths.js";

/** A possibly schema-qualified, possibly double-quoted SQL identifier. */
const IDENT = String.raw`(?:"[^"]+"|[\w$]+)(?:\s*\.\s*(?:"[^"]+"|[\w$]+))?`;

/* eslint-disable security/detect-non-literal-regexp -- built from the fixed IDENT fragment above, never from scanned content */
const CREATE_TABLE_RE = new RegExp(
  String.raw`^\s*create\s+(?:unlogged\s+)?table\s+(?:if\s+not\s+exists\s+)?(${IDENT})`,
  "i",
);
const ENABLE_RLS_RE = new RegExp(
  String.raw`alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?(${IDENT})\s+enable\s+row\s+level\s+security`,
  "gi",
);
const DISABLE_RLS_RE = new RegExp(
  String.raw`^\s*alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?(${IDENT})\s+disable\s+row\s+level\s+security`,
  "i",
);
const CREATE_POLICY_RE = new RegExp(String.raw`^\s*create\s+policy\s+(?:"[^"]+"|[\w$]+)\s+on\s+(${IDENT})([\s\S]*)$`, "i");
/* eslint-enable security/detect-non-literal-regexp */

/** `for <command>` clause of a CREATE POLICY (defaults to ALL when absent). */
const POLICY_COMMAND_RE = /\bfor\s+(all|select|insert|update|delete)\b/i;

/** `to <role>[, <role>...]` clause of a CREATE POLICY (defaults to PUBLIC when absent). */
const POLICY_ROLES_RE = /\bto\s+([\w\s,"]+?)(?=\s+(?:using|with)\b|\s*$)/i;

/** An unconditional `using (true)` / `with check (true)` predicate. */
const ALWAYS_TRUE_PREDICATE_RE = /\b(?:using|with\s+check)\s*\(\s*true\s*\)/i;

/** True when `filePath` is a SQL file that belongs to a Supabase project. */
function isSupabaseSqlFile(filePath: string, hasSupabase: boolean): boolean {
  if (!filePath.toLowerCase().endsWith(".sql")) {
    return false;
  }
  return hasSupabase || filePath.split("/").includes("supabase");
}

/**
 * Normalizes a table identifier to its unquoted, lowercase, schema-free
 * name, or `undefined` when it lives outside the API-exposed `public`
 * schema (`auth.users`, `storage.objects`, a `private` schema, ...).
 */
function publicTableName(raw: string): string | undefined {
  const parts = raw.split(".").map((part) => part.trim().replace(/^"|"$/g, ""));
  if (parts.length === 2 && parts[0]?.toLowerCase() !== "public") {
    return undefined;
  }
  const name = parts.at(-1);
  return name === undefined || name === "" ? undefined : name.toLowerCase();
}

/**
 * Blanks out SQL comments and dollar-quoted bodies (function/DO blocks) so
 * their text cannot be mistaken for statements, while preserving every
 * newline — statement offsets still map back to real line numbers.
 */
function maskNonStatementText(sql: string): string {
  const keepNewlines = (text: string): string => text.replace(/[^\n]/g, " ");
  return sql
    .replace(/\$([\w]*)\$[\s\S]*?\$\1\$/g, keepNewlines)
    .replace(/\/\*[\s\S]*?\*\//g, keepNewlines)
    .replace(/--[^\n]*/g, keepNewlines);
}

/** One `;`-terminated statement with the 1-indexed line its first keyword sits on. */
interface Statement {
  text: string;
  line: number;
}

/** Splits masked SQL into statements, tracking each statement's starting line. */
function splitStatements(sql: string): Statement[] {
  const statements: Statement[] = [];
  let offset = 0;
  for (const chunk of sql.split(";")) {
    const leading = chunk.length - chunk.trimStart().length;
    const startLine = sql.slice(0, offset + leading).split("\n").length;
    if (chunk.trim() !== "") {
      statements.push({ text: chunk, line: startLine });
    }
    offset += chunk.length + 1;
  }
  return statements;
}

/** Every public table that has RLS enabled by any SQL file in the repo. */
function tablesWithRlsEnabled(fileSet: ReadonlyMap<string, string>): Set<string> {
  const enabled = new Set<string>();
  for (const [path, content] of fileSet) {
    if (!path.toLowerCase().endsWith(".sql")) {
      continue;
    }
    for (const match of maskNonStatementText(content).matchAll(ENABLE_RLS_RE)) {
      const name = publicTableName(match[1] ?? "");
      if (name !== undefined) {
        enabled.add(name);
      }
    }
  }
  return enabled;
}

/** Builds the AUTH-05 finding for a policy statement that lets writes through unconditionally, or `undefined`. */
function permissivePolicyFinding(filePath: string, statement: Statement, table: string, rest: string): Finding | undefined {
  if (/\bas\s+restrictive\b/i.test(rest) || !ALWAYS_TRUE_PREDICATE_RE.test(rest)) {
    return undefined;
  }
  const command = (rest.match(POLICY_COMMAND_RE)?.[1] ?? "all").toLowerCase();
  if (command === "select") {
    return undefined;
  }
  const roles = (rest.match(POLICY_ROLES_RE)?.[1] ?? "public")
    .split(",")
    .map((role) => role.trim().replace(/^"|"$/g, "").toLowerCase());
  if (roles.every((role) => role === "service_role")) {
    return undefined;
  }
  const everyone = roles.some((role) => role === "public" || role === "anon");
  const severity: Severity = everyone ? "CRITICAL" : "HIGH";
  const who = everyone ? "anyone with the anon key" : "any signed-in user";
  return {
    ruleId: "AUTH-05",
    category: "auth",
    detectorName: "supabase-rls",
    file: filePath,
    line: statement.line,
    severity,
    confidence: "HIGH",
    message: `RLS policy on public.${table} allows ${command.toUpperCase()} with an always-true condition — ${who} can modify every row.`,
    remediation: `Replace the true condition with an ownership check, e.g. using (auth.uid() = user_id) with check (auth.uid() = user_id), and scope the policy to the roles that need it.`,
    matchedText: statement.text.trim().slice(0, 120),
  };
}

export const supabaseRlsDetector: Detector = {
  config: {
    name: "supabase-rls",
    category: "auth",
    globs: ["**/*.sql"],
  },

  // Not declared `async` — plain synchronous text work wrapped in Promise.resolve().
  detect(ctx: DetectorContext): Promise<Finding[]> {
    try {
      if (isInTestDirectory(ctx.filePath) || !isSupabaseSqlFile(ctx.filePath, ctx.stackHints.hasSupabase)) {
        return Promise.resolve([]);
      }

      const findings: Finding[] = [];
      const rlsEnabled = tablesWithRlsEnabled(ctx.fileSet);

      for (const statement of splitStatements(maskNonStatementText(ctx.content))) {
        const created = statement.text.match(CREATE_TABLE_RE);
        if (created !== null) {
          const table = publicTableName(created[1] ?? "");
          if (table !== undefined && !rlsEnabled.has(table)) {
            findings.push({
              ruleId: "AUTH-04",
              category: "auth",
              detectorName: "supabase-rls",
              file: ctx.filePath,
              line: statement.line,
              severity: "CRITICAL",
              confidence: "HIGH",
              message: `Table public.${table} is created without Row Level Security — anyone with the anon key (shipped in every client) can read and write every row through the Supabase API.`,
              remediation: `Add "alter table public.${table} enable row level security;" plus policies that scope rows to their owner (e.g. using (auth.uid() = user_id)).`,
              matchedText: table,
            });
          }
          continue;
        }

        const disabled = statement.text.match(DISABLE_RLS_RE);
        if (disabled !== null) {
          const table = publicTableName(disabled[1] ?? "");
          if (table !== undefined) {
            findings.push({
              ruleId: "AUTH-04",
              category: "auth",
              detectorName: "supabase-rls",
              file: ctx.filePath,
              line: statement.line,
              severity: "CRITICAL",
              confidence: "HIGH",
              message: `Row Level Security is explicitly disabled on public.${table} — anyone with the anon key can read and write every row.`,
              remediation: `Remove the disable statement, re-enable RLS on public.${table}, and add owner-scoped policies.`,
              matchedText: table,
            });
          }
          continue;
        }

        const policy = statement.text.match(CREATE_POLICY_RE);
        if (policy !== null) {
          const table = publicTableName(policy[1] ?? "");
          const finding =
            table === undefined ? undefined : permissivePolicyFinding(ctx.filePath, statement, table, policy[2] ?? "");
          if (finding !== undefined) {
            findings.push(finding);
          }
        }
      }

      return Promise.resolve(findings);
    } catch {
      // No-throw contract (src/core/types.ts Detector.detect).
      return Promise.resolve([]);
    }
  },
};

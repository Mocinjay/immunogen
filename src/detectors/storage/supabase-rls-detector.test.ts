import { describe, expect, it } from "vitest";

import { supabaseRlsDetector } from "./supabase-rls-detector.js";

import type { DetectorContext, StackHints } from "../../core/types.js";

const SUPABASE_STACK_HINTS: StackHints = {
  frameworks: new Set(["supabase"]),
  hasSupabase: true,
  hasFirebase: false,
  hasStripe: false,
  hasEnvFiles: false,
  hasMcpJson: false,
  hasClaudeSkills: false,
  hasCursorRules: false,
};

const MIGRATION = "supabase/migrations/0001_init.sql";

/** Builds a context for `files[filePath]`, with every entry of `files` in the shared fileSet. */
function makeContext(
  files: Record<string, string>,
  filePath = MIGRATION,
  stackHints: StackHints = SUPABASE_STACK_HINTS,
): DetectorContext {
  const fileSet = new Map(Object.entries(files));
  return {
    filePath,
    content: fileSet.get(filePath) ?? "",
    stackHints,
    fileSet,
  };
}

async function summarize(files: Record<string, string>, filePath = MIGRATION): Promise<string[]> {
  const findings = await supabaseRlsDetector.detect(makeContext(files, filePath));
  return findings.map((finding) => `${finding.ruleId} ${finding.severity} L${String(finding.line)} ${finding.matchedText ?? ""}`);
}

describe("supabaseRlsDetector — AUTH-04 tables without RLS", () => {
  it("flags a public table with no enable-RLS statement, at the create line", async () => {
    const sql = [
      "create table public.profiles (id uuid primary key);",
      "alter table public.profiles enable row level security;",
      "",
      "create table if not exists messages (",
      "  id bigint primary key",
      ");",
    ].join("\n");

    expect(await summarize({ [MIGRATION]: sql })).toEqual(["AUTH-04 CRITICAL L4 messages"]);
  });

  it("accepts RLS enabled in a LATER migration file", async () => {
    const files = {
      [MIGRATION]: 'create table "Orders" (id int);',
      "supabase/migrations/0002_rls.sql": 'alter table only public."Orders" enable row level security;',
    };

    expect(await summarize(files)).toEqual([]);
  });

  it("ignores tables outside the public schema and text inside comments or function bodies", async () => {
    const sql = [
      "create table private.audit (id int);",
      "-- create table public.commented_out (id int);",
      "/* create table public.block_commented (id int); */",
      "create function f() returns void as $$ begin create table public.tmp (id int); end; $$ language plpgsql;",
    ].join("\n");

    expect(await summarize({ [MIGRATION]: sql })).toEqual([]);
  });

  it("flags an explicit disable row level security", async () => {
    const sql = "alter table public.profiles disable row level security;";

    expect(await summarize({ [MIGRATION]: sql })).toEqual(["AUTH-04 CRITICAL L1 profiles"]);
  });

  it("does not run on non-Supabase SQL (no Supabase stack, no supabase/ directory)", async () => {
    const files = { "db/schema.sql": "create table users (id int);" };
    const ctx = makeContext(files, "db/schema.sql", { ...SUPABASE_STACK_HINTS, hasSupabase: false });

    expect(await supabaseRlsDetector.detect(ctx)).toEqual([]);
  });
});

describe("supabaseRlsDetector — AUTH-05 always-true write policies", () => {
  const withRls = (policy: string): string =>
    ["create table public.orders (id int);", "alter table public.orders enable row level security;", policy].join("\n");

  it("flags FOR ALL USING (true) with no role clause as CRITICAL", async () => {
    const files = { [MIGRATION]: withRls('create policy "anyone" on public.orders for all using (true) with check (true);') };

    expect(await summarize(files)).toEqual([expect.stringMatching(/^AUTH-05 CRITICAL L3/)]);
  });

  it("flags an INSERT WITH CHECK (true) for anon as CRITICAL", async () => {
    const files = { [MIGRATION]: withRls("create policy p on orders for insert to anon with check (true);") };

    expect(await summarize(files)).toEqual([expect.stringMatching(/^AUTH-05 CRITICAL/)]);
  });

  it("flags an UPDATE USING (true) for authenticated as HIGH", async () => {
    const files = { [MIGRATION]: withRls("create policy p on orders for update to authenticated using (true);") };

    expect(await summarize(files)).toEqual([expect.stringMatching(/^AUTH-05 HIGH/)]);
  });

  it("does NOT flag public read, owner-scoped writes, restrictive, or service_role-only policies", async () => {
    const policies = [
      "create policy r on orders for select using (true);",
      "create policy w on orders for update to authenticated using (auth.uid() = user_id);",
      "create policy x on orders as restrictive for all using (true);",
      "create policy s on orders for all to service_role using (true) with check (true);",
    ].join("\n");

    expect(await summarize({ [MIGRATION]: withRls(policies) })).toEqual([]);
  });
});

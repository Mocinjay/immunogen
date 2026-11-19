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

describe("supabaseRlsDetector — bulk protection (dynamic SQL, event triggers, revoked grants)", () => {
  const INIT = "supabase/migrations/0001_init.sql";
  const LOCKDOWN = "supabase/migrations/0009_lockdown.sql";
  const LATER = "supabase/migrations/0010_more.sql";
  const createTables = "create table public.users (id uuid primary key);\ncreate table public.orders (id uuid primary key);\n";
  const loop = [
    "do $$",
    "declare rel record;",
    "begin",
    "  for rel in select c.oid::regclass as ident from pg_class c join pg_namespace n on n.oid = c.relnamespace",
    "    where n.nspname = 'public' and c.relkind in ('r','p') and not c.relrowsecurity",
    "  loop",
    "    execute format('alter table %s enable row level security', rel.ident);",
    "  end loop;",
    "end",
    "$$;",
  ].join("\n");

  it("does not report tables created before a migration that enables RLS on every table in a loop", async () => {
    const files = { [INIT]: createTables, [LOCKDOWN]: loop };
    expect(await summarize(files, INIT)).toEqual([]);
  });

  it("records one INFO finding (no score cost) at the loop, counting the tables that rely on it", async () => {
    const files = { [INIT]: createTables, [LOCKDOWN]: loop };
    const findings = await supabaseRlsDetector.detect(makeContext(files, LOCKDOWN));
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ ruleId: "AUTH-04", severity: "INFO", line: 1 });
    expect(findings[0]?.message).toContain("2 public table(s)");
  });

  it("still reports a table created AFTER a one-off loop — the loop never saw it", async () => {
    const files = { [INIT]: createTables, [LOCKDOWN]: loop, [LATER]: "create table public.invoices (id uuid);\n" };
    expect(await summarize(files, LATER)).toEqual(["AUTH-04 CRITICAL L1 invoices"]);
  });

  it("treats an event trigger that enables RLS as covering future tables too", async () => {
    const trigger = [
      "create or replace function rls_auto_enable() returns event_trigger language plpgsql as $fn$",
      "declare cmd record;",
      "begin",
      "  for cmd in select * from pg_event_trigger_ddl_commands() where command_tag = 'CREATE TABLE' loop",
      "    execute format('alter table %s enable row level security', cmd.object_identity);",
      "  end loop;",
      "end $fn$;",
      "create event trigger ensure_rls on ddl_command_end execute function rls_auto_enable();",
    ].join("\n");
    const files = { [INIT]: trigger, [LATER]: "create table public.invoices (id uuid);\n" };
    expect(await summarize(files, LATER)).toEqual([]);
  });

  it("treats revoking every table privilege from anon (plus default privileges) as covering all tables", async () => {
    const revoke = [
      "revoke all on all tables in schema public from anon, authenticated;",
      "alter default privileges in schema public revoke all on tables from anon, authenticated;",
    ].join("\n");
    const files = { [INIT]: revoke, [LATER]: "create table public.invoices (id uuid);\n" };
    expect(await summarize(files, LATER)).toEqual([]);
  });

  it("counts a literal enable inside a DO block as a normal static enable", async () => {
    const files = {
      [INIT]: "create table public.users (id uuid);\ndo $$ begin alter table public.users enable row level security; end $$;\n",
    };
    expect(await summarize(files, INIT)).toEqual([]);
  });
});

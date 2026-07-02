import { describe, expect, it } from "vitest";

import { supabaseDetector } from "./supabase-detector.js";

import type { DetectorContext, StackHints } from "../../core/types.js";

/** StackHints with Supabase present — the gate this detector reads. */
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

/** StackHints with no Supabase — proves the stack gate (Test 5). */
const NO_SUPABASE_STACK_HINTS: StackHints = {
  ...SUPABASE_STACK_HINTS,
  frameworks: new Set(),
  hasSupabase: false,
};

/** A migration file whose content contains real RLS policy evidence. */
const POLICY_MIGRATION_CONTENT =
  "alter table users enable row level security;\ncreate policy \"Users can view own data\" on users for select using (auth.uid() = id);\n";

/**
 * Builds a DetectorContext literal for `content` at the given `filePath`,
 * without the ingestion layer. `extraFiles` lets a test populate
 * ctx.fileSet with additional repo-wide evidence (e.g. migration files)
 * beyond the single file under scan.
 */
function makeContext(
  content: string,
  filePath: string,
  options: { stackHints?: StackHints; extraFiles?: Record<string, string> } = {},
): DetectorContext {
  const fileSet = new Map<string, string>(Object.entries(options.extraFiles ?? {}));
  fileSet.set(filePath, content);
  return {
    filePath,
    content,
    stackHints: options.stackHints ?? SUPABASE_STACK_HINTS,
    fileSet,
  };
}

describe("supabaseDetector — AUTH-03 (RLS absence, LOW 'verify manually')", () => {
  it("flags a Supabase anon-client query with no RLS policy evidence anywhere in the repo as AUTH-03 HIGH/LOW", async () => {
    const ctx = makeContext(
      'const { data } = await supabase.from("users").select("*");',
      "src/lib/queries.ts",
    );

    const findings = await supabaseDetector.detect(ctx);

    const authFindings = findings.filter((finding) => finding.ruleId === "AUTH-03");
    expect(authFindings).toHaveLength(1);
    expect(authFindings[0]).toMatchObject({
      ruleId: "AUTH-03",
      category: "auth",
      severity: "HIGH",
      confidence: "LOW",
      file: "src/lib/queries.ts",
      line: 1,
    });
    expect(authFindings[0]?.message).toContain("verify manually");
  });

  it("does NOT flag AUTH-03 when a supabase/migrations/*.sql policy file is present in ctx.fileSet (policy evidence)", async () => {
    const ctx = makeContext(
      'const { data } = await supabase.from("users").select("*");',
      "src/lib/queries.ts",
      { extraFiles: { "supabase/migrations/0001_policies.sql": POLICY_MIGRATION_CONTENT } },
    );

    const findings = await supabaseDetector.detect(ctx);

    expect(findings.filter((finding) => finding.ruleId === "AUTH-03")).toHaveLength(0);
  });
});

describe("supabaseDetector — STORAGE-02 (public bucket no policy, MEDIUM 'verify access policy')", () => {
  it("flags a public createBucket call with no storage policy as STORAGE-02 MEDIUM", async () => {
    const ctx = makeContext(
      'await supabase.storage.createBucket("avatars", { public: true });',
      "src/lib/storage.ts",
    );

    const findings = await supabaseDetector.detect(ctx);

    const storageFindings = findings.filter((finding) => finding.ruleId === "STORAGE-02");
    expect(storageFindings).toHaveLength(1);
    expect(storageFindings[0]).toMatchObject({
      ruleId: "STORAGE-02",
      category: "storage",
      severity: "MEDIUM",
      file: "src/lib/storage.ts",
      line: 1,
    });
    expect(["LOW", "MEDIUM"]).toContain(storageFindings[0]?.confidence);
    expect(storageFindings[0]?.message).toContain("verify access policy");
  });

  it("does NOT flag STORAGE-02 for a private bucket (public: false)", async () => {
    const ctx = makeContext(
      'await supabase.storage.createBucket("avatars", { public: false });',
      "src/lib/storage.ts",
    );

    const findings = await supabaseDetector.detect(ctx);

    expect(findings.filter((finding) => finding.ruleId === "STORAGE-02")).toHaveLength(0);
  });
});

describe("supabaseDetector — clean cases", () => {
  it("does NOT flag any finding when stackHints.hasSupabase is false (stack gate)", async () => {
    const ctx = makeContext(
      'const { data } = await supabase.from("users").select("*");\nawait supabase.storage.createBucket("avatars", { public: true });',
      "src/lib/queries.ts",
      { stackHints: NO_SUPABASE_STACK_HINTS },
    );

    const findings = await supabaseDetector.detect(ctx);

    expect(findings).toHaveLength(0);
  });

  it("does NOT flag any finding inside a __tests__/fixtures path (FP allowlist guard)", async () => {
    const ctx = makeContext(
      'const { data } = await supabase.from("users").select("*");\nawait supabase.storage.createBucket("avatars", { public: true });',
      "src/__tests__/fixtures/queries.ts",
    );

    const findings = await supabaseDetector.detect(ctx);

    expect(findings).toHaveLength(0);
  });
});

describe("supabaseDetector — config", () => {
  it("declares name 'supabase' and category 'auth'", () => {
    expect(supabaseDetector.config.name).toBe("supabase");
    expect(supabaseDetector.config.category).toBe("auth");
  });

  it("declares requiresStack including 'supabase'", () => {
    expect(supabaseDetector.config.requiresStack).toContain("supabase");
  });
});

describe("supabaseDetector — no-throw contract", () => {
  it("resolves to [] for empty content", async () => {
    const ctx = makeContext("", "src/lib/queries.ts");

    const findings = await supabaseDetector.detect(ctx);

    expect(findings).toEqual([]);
  });
});

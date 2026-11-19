import { describe, expect, it } from "vitest";

import { committedEnvDetector } from "./committed-env-detector.js";

import type { DetectorContext, StackHints } from "../../core/types.js";

/** Minimal StackHints fixture — committedEnvDetector reads ctx.filePath and ctx.fileSet only. */
const STACK_HINTS: StackHints = {
  frameworks: new Set(),
  hasSupabase: false,
  hasFirebase: false,
  hasStripe: false,
  hasEnvFiles: false,
  hasMcpJson: false,
  hasClaudeSkills: false,
  hasCursorRules: false,
};

/**
 * Builds a DetectorContext for `filePath`, with `fileSet` populated from
 * `files` (repo-relative path -> raw text), mirroring the registry's
 * once-per-matching-file call shape (registry.ts `buildDetectorContext`).
 * `content` is read via the same Map's `.get()` (not bracket indexing, to
 * avoid security/detect-object-injection) when present, "" otherwise —
 * committedEnvDetector never reads ctx.content, only ctx.filePath/fileSet.
 */
function makeContext(filePath: string, files: Record<string, string>): DetectorContext {
  const fileSet = new Map(Object.entries(files));
  return {
    filePath,
    content: fileSet.get(filePath) ?? "",
    stackHints: STACK_HINTS,
    fileSet,
  };
}

describe("committedEnvDetector — vulnerable cases", () => {
  it("flags a committed .env file as SEC-05 CRITICAL/HIGH at line 1", async () => {
    const ctx = makeContext(".env", { ".env": "SECRET=abc123" });

    const findings = await committedEnvDetector.detect(ctx);

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      ruleId: "SEC-05",
      category: "secrets",
      severity: "CRITICAL",
      confidence: "HIGH",
      file: ".env",
      line: 1,
    });
  });

  it("flags .env.local as SEC-05", async () => {
    const ctx = makeContext(".env.local", { ".env.local": "SECRET=abc123" });

    const findings = await committedEnvDetector.detect(ctx);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.ruleId).toBe("SEC-05");
  });

  it("flags .env.production as SEC-05", async () => {
    const ctx = makeContext(".env.production", { ".env.production": "SECRET=abc123" });

    const findings = await committedEnvDetector.detect(ctx);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.ruleId).toBe("SEC-05");
  });
});

describe("committedEnvDetector — clean cases (template files)", () => {
  it("does NOT flag .env.example", async () => {
    const ctx = makeContext(".env.example", { ".env.example": "SECRET=" });

    const findings = await committedEnvDetector.detect(ctx);

    expect(findings).toHaveLength(0);
  });

  it("does NOT flag .env.sample", async () => {
    const ctx = makeContext(".env.sample", { ".env.sample": "SECRET=" });

    const findings = await committedEnvDetector.detect(ctx);

    expect(findings).toHaveLength(0);
  });

  it("does NOT flag .env.example or .env.sample even when both are present together with no other env file", async () => {
    const files = { ".env.example": "SECRET=", ".env.sample": "SECRET=" };

    const exampleFindings = await committedEnvDetector.detect(makeContext(".env.example", files));
    const sampleFindings = await committedEnvDetector.detect(makeContext(".env.sample", files));

    expect(exampleFindings).toHaveLength(0);
    expect(sampleFindings).toHaveLength(0);
  });
});

describe("committedEnvDetector — clean cases (FP allowlist paths)", () => {
  it("does NOT flag a .env file under fixtures/", async () => {
    const ctx = makeContext("fixtures/.env", { "fixtures/.env": "SECRET=abc123" });

    const findings = await committedEnvDetector.detect(ctx);

    expect(findings).toHaveLength(0);
  });

  it("does NOT flag a .env file under __tests__/", async () => {
    const ctx = makeContext("__tests__/.env", { "__tests__/.env": "SECRET=abc123" });

    const findings = await committedEnvDetector.detect(ctx);

    expect(findings).toHaveLength(0);
  });
});

describe("committedEnvDetector — gitignore is decided by the walker, not here", () => {
  it("flags any env file it receives, even one a root .gitignore lists (git may still track it)", async () => {
    const files = { ".env": "SECRET=abc123", ".gitignore": "node_modules\n.env\ndist\n" };
    const ctx = makeContext(".env", files);

    const findings = await committedEnvDetector.detect(ctx);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.ruleId).toBe("SEC-05");
  });
});

describe("committedEnvDetector — no-throw contract", () => {
  it("resolves to [] for a non-env file path (should never be called by the registry, but must not throw)", async () => {
    const ctx = makeContext("src/config.ts", { "src/config.ts": "export const x = 1;" });

    const findings = await committedEnvDetector.detect(ctx);

    expect(findings).toEqual([]);
  });
});

describe("committedEnvDetector — config", () => {
  it("declares category secrets and globs targeting .env files", () => {
    expect(committedEnvDetector.config.name).toBe("committed-env");
    expect(committedEnvDetector.config.category).toBe("secrets");
    expect(committedEnvDetector.config.globs.some((glob) => glob.includes(".env"))).toBe(true);
  });
});

describe("committedEnvDetector — rated by content", () => {
  async function detectEnv(filePath: string, content: string) {
    return committedEnvDetector.detect(makeContext(filePath, { [filePath]: content }));
  }

  it("is INFO for a Vite .env.production holding only public values (committing defaults is documented practice)", async () => {
    const findings = await detectEnv(".env.production", "VITE_API_URL=https://api.example.com\nVITE_APP_NAME=demo\nPORT=3000\n");
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ ruleId: "SEC-05", severity: "INFO" });
  });

  it("is INFO for public-by-design Supabase / Stripe keys", async () => {
    const content = [
      "NEXT_PUBLIC_SUPABASE_URL=https://abcdefghijkl.supabase.co",
      "NEXT_PUBLIC_SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYW5vbiJ9.c2lnbmF0dXJl",
      "STRIPE_PUBLISHABLE_KEY=pk_live_51Qm8vRt2LpX7nWc4ZyKd9HjB",
      "NEXTAUTH_URL=http://localhost:3000",
    ].join("\n");
    expect((await detectEnv(".env", content))[0]?.severity).toBe("INFO");
  });

  it("is LOW for a committed .env.local even without secrets", async () => {
    expect((await detectEnv(".env.local", "DEBUG=true\n"))[0]?.severity).toBe("LOW");
  });

  it("is CRITICAL and names (never echoes) the secret variables", async () => {
    const content = [
      "VITE_API_URL=https://api.example.com",
      "export JWT_SECRET='Qm8vRt2LpX7nWc4Z'",
      "DATABASE_URL=postgresql://postgres:Hq7vRt2pLx9w@db.abcdefghijkl.supabase.co:5432/postgres",
    ].join("\n");
    const [finding] = await detectEnv(".env", content);
    expect(finding).toMatchObject({ severity: "CRITICAL", line: 2 });
    expect(finding?.message).toContain("JWT_SECRET, DATABASE_URL");
    expect(finding?.message).not.toContain("Qm8vRt2LpX7nWc4Z");
  });

  it("is CRITICAL for a provider-key value under any name", async () => {
    expect((await detectEnv(".env", "PAYMENTS=sk_live_51Qm8vRt2LpX7nWc4ZyKd9HjB"))[0]?.severity).toBe("CRITICAL");
  });

  it("ignores placeholders, references, local database URLs and secret-named client vars (BUNDLE-01 owns those)", async () => {
    const content = [
      "OPENAI_API_KEY=your-openai-key",
      "STRIPE_SECRET_KEY=",
      "API_TOKEN=${CI_TOKEN}",
      "DATABASE_URL=postgres://postgres:postgres@localhost:5432/dev",
      "NEXT_PUBLIC_MAPS_KEY=AIzaSyB7q2Xc9LmN4pR8tV1wZ3kD6fH0jG5sQeT",
    ].join("\n");
    expect((await detectEnv(".env", content))[0]?.severity).toBe("INFO");
  });
});

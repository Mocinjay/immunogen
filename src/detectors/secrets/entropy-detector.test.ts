import { describe, expect, it } from "vitest";

import { secretsDetector } from "./entropy-detector.js";

import type { DetectorContext, StackHints } from "../../core/types.js";

/** Minimal StackHints fixture — secretsDetector reads ctx.content only, never ctx.stackHints. */
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

/** Builds a DetectorContext literal for `content` at the given `filePath`, without the ingestion layer. */
function makeContext(content: string, filePath = "src/config.ts"): DetectorContext {
  return {
    filePath,
    content,
    stackHints: STACK_HINTS,
    fileSet: new Map(),
  };
}

// Exact-format provider secrets used across multiple assertions below.
const STRIPE_KEY = "sk_live_4eC39HqLyjWDarjtT1zdp7dc";
const AWS_KEY = "AKIAABCD1234EFGH5678"; // AKIA + exactly 16 chars in [0-9A-Z]
// sk- + exactly 48 alnum chars, built deterministically so the length is provably correct.
const OPENAI_KEY_BODY = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUV";
const OPENAI_KEY = `sk-${OPENAI_KEY_BODY.slice(0, 48)}`;

describe("secretsDetector — provider-key regex (Pass A)", () => {
  it("flags a Stripe live secret key as SEC-01 CRITICAL/HIGH", async () => {
    const ctx = makeContext(`const stripeKey = "${STRIPE_KEY}";`);

    const findings = await secretsDetector.detect(ctx);

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      ruleId: "SEC-01",
      category: "secrets",
      severity: "CRITICAL",
      confidence: "HIGH",
      file: "src/config.ts",
      line: 1,
    });
  });

  it("flags an AWS access key ID as SEC-02 CRITICAL/HIGH", async () => {
    const ctx = makeContext(`const awsKey = "${AWS_KEY}";`);

    const findings = await secretsDetector.detect(ctx);

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      ruleId: "SEC-02",
      severity: "CRITICAL",
      confidence: "HIGH",
    });
  });

  it("flags an OpenAI API key as SEC-03 CRITICAL/HIGH", async () => {
    const ctx = makeContext(`const openaiKey = "${OPENAI_KEY}";`);

    const findings = await secretsDetector.detect(ctx);

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      ruleId: "SEC-03",
      severity: "CRITICAL",
      confidence: "HIGH",
    });
  });

  it("reports a 1-indexed line number matching the secret's actual line", async () => {
    const ctx = makeContext(`// line 1\n// line 2\nconst stripeKey = "${STRIPE_KEY}";\n`);

    const findings = await secretsDetector.detect(ctx);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.line).toBe(3);
  });
});

describe("secretsDetector — keyword-anchored entropy (Pass B)", () => {
  // 40-char, high-entropy (no repeated-char runs), keyword-anchored on its own line.
  const HIGH_ENTROPY_VALUE = "aB3xQ9zK2mN7pL5wR8tY4vU6sD1fG0hJ2kM8nQ4r";

  it("flags a keyword-anchored high-entropy literal as SEC-06 HIGH/MEDIUM", async () => {
    const ctx = makeContext(`const apiSecret = "${HIGH_ENTROPY_VALUE}";`);

    const findings = await secretsDetector.detect(ctx);

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      ruleId: "SEC-06",
      category: "secrets",
      severity: "HIGH",
      confidence: "MEDIUM",
      line: 1,
    });
  });

  it("does NOT flag a plain UUID (low entropy, no anchor keyword)", async () => {
    const ctx = makeContext('const id = "550e8400-e29b-41d4-a716-446655440000";');

    const findings = await secretsDetector.detect(ctx);

    expect(findings).toHaveLength(0);
  });

  it("does NOT flag a high-entropy string with no anchoring keyword on its line", async () => {
    const ctx = makeContext(`const value = "${HIGH_ENTROPY_VALUE}";`);

    const findings = await secretsDetector.detect(ctx);

    expect(findings).toHaveLength(0);
  });

  it("does NOT flag a low-entropy 40+ char string even when anchored by a keyword", async () => {
    const lowEntropyValue = "a".repeat(45);
    const ctx = makeContext(`const password = "${lowEntropyValue}";`);

    const findings = await secretsDetector.detect(ctx);

    expect(findings).toHaveLength(0);
  });
});

describe("secretsDetector — masking (T-04-02)", () => {
  it("masks matchedText to the first 4 characters of a provider-key secret", async () => {
    const ctx = makeContext(`const stripeKey = "${STRIPE_KEY}";`);

    const findings = await secretsDetector.detect(ctx);
    const finding = findings[0];

    expect(finding).toBeDefined();
    expect(finding?.matchedText).toBe("sk_l****");
    expect(finding?.matchedText).not.toBe(STRIPE_KEY);
  });

  it("never includes the full secret value in any serialized Finding field", async () => {
    const ctx = makeContext(`const stripeKey = "${STRIPE_KEY}";`);

    const findings = await secretsDetector.detect(ctx);
    const finding = findings[0];

    expect(finding).toBeDefined();
    expect(JSON.stringify(finding)).not.toContain(STRIPE_KEY);
  });

  it("masks the entropy-flagged secret too", async () => {
    const HIGH_ENTROPY_VALUE = "aB3xQ9zK2mN7pL5wR8tY4vU6sD1fG0hJ2kM8nQ4r";
    const ctx = makeContext(`const apiSecret = "${HIGH_ENTROPY_VALUE}";`);

    const findings = await secretsDetector.detect(ctx);
    const finding = findings[0];

    expect(finding).toBeDefined();
    expect(JSON.stringify(finding)).not.toContain(HIGH_ENTROPY_VALUE);
  });
});

describe("secretsDetector — no-throw contract", () => {
  it("resolves to [] for empty content", async () => {
    const ctx = makeContext("");

    const findings = await secretsDetector.detect(ctx);

    expect(findings).toEqual([]);
  });

  it("resolves to [] for malformed/binary-ish content without rejecting", async () => {
    // The replacement-character glyph (U+FFFD) is valid UTF-8 but not
    // anything a provider-key regex or entropy pass should ever match —
    // exercises the no-throw contract on odd-but-valid input.
    const ctx = makeContext(" � garbled content");

    await expect(secretsDetector.detect(ctx)).resolves.toEqual([]);
  });
});

describe("secretsDetector — config", () => {
  it("declares category secrets and a name of 'secrets'", () => {
    expect(secretsDetector.config.name).toBe("secrets");
    expect(secretsDetector.config.category).toBe("secrets");
  });

  it("declares text-targetable globs including .env files", () => {
    expect(secretsDetector.config.globs.some((glob) => glob.includes(".env"))).toBe(true);
  });
});

describe("secretsDetector — per-file entropy cap", () => {
  // Reuse the existing 40-char high-entropy fixture value, varying the
  // variable name per line so each line is a distinct anchor+entropy match.
  const HIGH_ENTROPY_VALUE = "aB3xQ9zK2mN7pL5wR8tY4vU6sD1fG0hJ2kM8nQ4r";

  function buildEntropyFloodLines(count: number): string {
    return Array.from(
      { length: count },
      (_, i) => `const key${i} = "${HIGH_ENTROPY_VALUE}";`,
    ).join("\n");
  }

  it("caps SEC-06 findings at MAX_ENTROPY_FINDINGS_PER_FILE (10) when 25 candidates are present in one file", async () => {
    const ctx = makeContext(buildEntropyFloodLines(25));

    const findings = await secretsDetector.detect(ctx);
    const entropyFindings = findings.filter((finding) => finding.ruleId === "SEC-06");

    expect(entropyFindings).toHaveLength(10);
  });

  it("still fires a provider-key finding (Pass A, uncapped) appearing after the SEC-06 cap is reached", async () => {
    const content = `${buildEntropyFloodLines(25)}\nconst stripeKey = "${STRIPE_KEY}";`;
    const ctx = makeContext(content);

    const findings = await secretsDetector.detect(ctx);
    const entropyFindings = findings.filter((finding) => finding.ruleId === "SEC-06");
    const providerFindings = findings.filter((finding) => finding.ruleId === "SEC-01");

    expect(entropyFindings).toHaveLength(10);
    expect(providerFindings).toHaveLength(1);
  });
});

describe("secretsDetector — Supabase service_role JWT (SEC-04)", () => {
  // Deterministic base64url JWT fixtures: header.payload.signature, three
  // segments joined by ".". Payload is a real JSON object base64url-encoded
  // (Buffer.from(json).toString("base64url")) — decoding the middle segment
  // reproduces the exact JSON text, so the substring check in the detector
  // has real, decodable input to match against (not a hand-typed string).
  const SERVICE_ROLE_JWT =
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJhdXRoZW50aWNhdGVkIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlzcyI6InN1cGFiYXNlIn0.dummysignaturevalue123";
  const ANON_JWT =
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJhdXRoZW50aWNhdGVkIiwicm9sZSI6ImFub24iLCJpc3MiOiJzdXBhYmFzZSJ9.dummysignaturevalue123";

  it("flags a JWT decoding to role=service_role as SEC-04 CRITICAL/HIGH at the correct line", async () => {
    const ctx = makeContext(`// line 1\nconst supabaseKey = "${SERVICE_ROLE_JWT}";`);

    const findings = await secretsDetector.detect(ctx);

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      ruleId: "SEC-04",
      category: "secrets",
      severity: "CRITICAL",
      confidence: "HIGH",
      line: 2,
    });
  });

  it("flags a SUPABASE_SERVICE_ROLE_KEY env-name assignment as SEC-04 CRITICAL (name-based signal, no JWT)", async () => {
    const ctx = makeContext('SUPABASE_SERVICE_ROLE_KEY=somevalueherethatisnotajwt', ".env");

    const findings = await secretsDetector.detect(ctx);

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      ruleId: "SEC-04",
      severity: "CRITICAL",
      confidence: "HIGH",
    });
  });

  it("does NOT flag a JWT decoding to role=anon as SEC-04 (clean)", async () => {
    // Plan behavior spec: "zero SEC-04 findings" — the anon JWT is still a
    // long, keyword-anchored, high-entropy literal, so SEC-06 (generic
    // entropy, Pass B) legitimately still fires on it unchanged; this test
    // asserts only that the SEC-04 (Supabase service_role) signal is absent.
    const ctx = makeContext(`const supabaseAnonKey = "${ANON_JWT}";`);

    const findings = await secretsDetector.detect(ctx);

    expect(findings.filter((finding) => finding.ruleId === "SEC-04")).toHaveLength(0);
  });

  it("does NOT flag a service_role JWT inside a __tests__/fixtures path (FP allowlist guard)", async () => {
    const ctx = makeContext(
      `const supabaseKey = "${SERVICE_ROLE_JWT}";`,
      "src/__tests__/fixtures/supabase-keys.ts",
    );

    const findings = await secretsDetector.detect(ctx);

    expect(findings).toHaveLength(0);
  });

  it("masks the matched JWT in matchedText and never leaks the full token", async () => {
    const ctx = makeContext(`const supabaseKey = "${SERVICE_ROLE_JWT}";`);

    const findings = await secretsDetector.detect(ctx);
    const finding = findings[0];

    expect(finding).toBeDefined();
    expect(finding?.matchedText).not.toBe(SERVICE_ROLE_JWT);
    expect(JSON.stringify(finding)).not.toContain(SERVICE_ROLE_JWT);
  });

  it("does NOT flag a Deno.env.get(\"SUPABASE_SERVICE_ROLE_KEY\") safe read (Supabase Edge Function pattern)", async () => {
    const ctx = makeContext('const key = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");');

    const findings = await secretsDetector.detect(ctx);

    expect(findings.filter((finding) => finding.ruleId === "SEC-04")).toHaveLength(0);
  });

  it("does NOT flag a process.env.SUPABASE_SERVICE_ROLE_KEY safe read", async () => {
    const ctx = makeContext("const key = process.env.SUPABASE_SERVICE_ROLE_KEY;");

    const findings = await secretsDetector.detect(ctx);

    expect(findings.filter((finding) => finding.ruleId === "SEC-04")).toHaveLength(0);
  });

  it("still flags a SUPABASE_SERVICE_ROLE_KEY=value assignment in a .env file (real leak, unchanged)", async () => {
    const ctx = makeContext("SUPABASE_SERVICE_ROLE_KEY=somevalueherethatisnotajwt", ".env");

    const findings = await secretsDetector.detect(ctx);

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ ruleId: "SEC-04", severity: "CRITICAL", confidence: "HIGH" });
  });
});

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
const OPENAI_KEY_BODY = "5P1nvecWboyuFTBSknR3aoIdxanrwVgK86HnyjnLogFBnd25";
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

describe("secretsDetector — masking", () => {
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

describe("secretsDetector — real-repo false positives (SEC-04 / SEC-06)", () => {
  const HIGH_ENTROPY_VALUE = "aB3xQ9zK2mN7pL5wR8tY4vU6sD1fG0hJ2kM8nQ4r";

  async function ruleIds(content: string, filePath?: string): Promise<string[]> {
    const findings = await secretsDetector.detect(makeContext(content, filePath));
    return findings.map((finding) => finding.ruleId);
  }

  it("skips package-manager lockfiles entirely (integrity hashes, registry URLs)", async () => {
    const lockLine =
      '"integrity": "sha512-06IyK09H3wi4cGbhDBwp5gUGo0IKtnYa8tyTiephirPCK6fbobVGiXMMI5zLQ4aKEYP3wZ3ArU44o+8KMrSG/Q==", "key": 1';

    expect(await ruleIds(lockLine, "app/package-lock.json")).toEqual([]);
    expect(await ruleIds(lockLine, "pnpm-lock.yaml")).toEqual([]);
  });

  it("does NOT flag an SRI integrity hash outside a lockfile", async () => {
    expect(
      await ruleIds('const integrityKey = "sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC";'),
    ).toEqual([]);
  });

  it("does NOT flag prose / UI copy that merely mentions a token", async () => {
    expect(
      await ruleIds("'TikTok is not configured — add a Content Posting API access token ' +"),
    ).toEqual([]);
  });

  it("does NOT flag a template literal interpolating a token variable", async () => {
    expect(
      await ruleIds(
        "`${GRAPH_READ}/${publishId}?fields=status,permalink_url&access_token=${this.auth.pageAccessToken}`,",
      ),
    ).toEqual([]);
  });

  it("does NOT flag a package name that happens to end in -key", async () => {
    expect(
      await ruleIds('"@babel/plugin-bugfix-firefox-class-in-computed-class-key": "^7.29.7",', "package.json"),
    ).toEqual([]);
  });

  it("does NOT flag a plain URL on a token line", async () => {
    expect(
      await ruleIds('const TOKEN_ENDPOINT = "https://login.microsoftonline.com/common/oauth2/v2.0/token";'),
    ).toEqual([]);
  });

  it("still flags a URL carrying a secret-named query parameter", async () => {
    expect(
      await ruleIds(`const apiKeyUrl = "https://api.example.com/v1/data?api_key=${HIGH_ENTROPY_VALUE}";`),
    ).toEqual(["SEC-06"]);
  });

  it("only anchors on whole identifier parts (keyboardType / monkey do not count)", async () => {
    expect(await ruleIds(`const keyboardType = "${HIGH_ENTROPY_VALUE}";`)).toEqual([]);
    expect(await ruleIds(`const monkey = "${HIGH_ENTROPY_VALUE}";`)).toEqual([]);
    expect(await ruleIds(`const API_KEY = "${HIGH_ENTROPY_VALUE}";`)).toEqual(["SEC-06"]);
    expect(await ruleIds(`headers["x-api-key"] = "${HIGH_ENTROPY_VALUE}";`)).toEqual(["SEC-06"]);
    expect(await ruleIds(`const accessToken = "${HIGH_ENTROPY_VALUE}";`)).toEqual(["SEC-06"]);
  });

  it("does NOT flag SUPABASE_SERVICE_ROLE_KEY mentioned in a comment or docs", async () => {
    expect(await ruleIds("// never ship SUPABASE_SERVICE_ROLE_KEY to the browser")).toEqual([]);
    expect(await ruleIds("Set `SUPABASE_SERVICE_ROLE_KEY` in your hosting dashboard.", "README.md")).toEqual([]);
  });

  it("does NOT flag SUPABASE_SERVICE_ROLE_KEY assigned from an expression or a placeholder", async () => {
    expect(await ruleIds("SUPABASE_SERVICE_ROLE_KEY=", ".env.example")).toEqual([]);
    expect(await ruleIds("SUPABASE_SERVICE_ROLE_KEY=your-service-role-key-here", ".env.example")).toEqual([]);
    expect(await ruleIds("SUPABASE_SERVICE_ROLE_KEY: ${{ secrets.SUPABASE_SERVICE_ROLE_KEY }}", "ci.yml")).toEqual([]);
    expect(await ruleIds("const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;")).toEqual([]);
    expect(await ruleIds("SUPABASE_SERVICE_ROLE_KEY: z.string().min(1),")).toEqual([]);
  });

  it("flags SUPABASE_SERVICE_ROLE_KEY assigned a hardcoded literal in code or JSON", async () => {
    expect(await ruleIds('const SUPABASE_SERVICE_ROLE_KEY = "somevalueherethatisnotajwt";')).toEqual(["SEC-04"]);
    expect(await ruleIds('{ "SUPABASE_SERVICE_ROLE_KEY": "somevalueherethatisnotajwt" }', "config.json")).toEqual([
      "SEC-04",
    ]);
  });
});

describe("secretsDetector — current provider key formats", () => {
  const BODY = "Dl09Jq7Nj1z3yXUwdeU5svM4RMyPQjzVrRSv_-ZOXhVmZKr18BE48OjJje6VMpyDAIbr29zfGm";

  it("flags OpenAI project / service-account / admin keys as SEC-03", async () => {
    for (const prefix of ["sk-proj-", "sk-svcacct-", "sk-admin-"]) {
      const findings = await secretsDetector.detect(makeContext(`OPENAI_API_KEY=${prefix}${BODY}`, ".env"));
      expect(findings.map((finding) => finding.ruleId)).toEqual(["SEC-03"]);
      expect(JSON.stringify(findings)).not.toContain(BODY);
    }
  });

  it("flags an Anthropic API key as SEC-07 CRITICAL/HIGH", async () => {
    const findings = await secretsDetector.detect(makeContext(`const anthropic = "sk-ant-api03-${BODY}";`));

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ ruleId: "SEC-07", severity: "CRITICAL", confidence: "HIGH" });
  });

  it("flags a Supabase sb_secret_ key once, even when assigned to SUPABASE_SERVICE_ROLE_KEY", async () => {
    const findings = await secretsDetector.detect(
      makeContext(`SUPABASE_SERVICE_ROLE_KEY=sb_secret_${BODY}`, ".env"),
    );

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ ruleId: "SEC-04", severity: "CRITICAL", confidence: "HIGH" });
  });
});

describe("secretsDetector — private keys and third-party tokens (SEC-08 / SEC-09)", () => {
  async function summarize(content: string, filePath?: string): Promise<string[]> {
    const findings = await secretsDetector.detect(makeContext(content, filePath));
    return findings.map((finding) => `${finding.ruleId} ${finding.severity} ${finding.message}`);
  }

  it("flags a PEM private key inside a committed service-account JSON as SEC-08 CRITICAL", async () => {
    const json =
      '{ "type": "service_account", "private_key": "-----BEGIN PRIVATE KEY-----\\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\\n-----END PRIVATE KEY-----\\n" }';

    expect(await summarize(json, "service-account.json")).toEqual([
      expect.stringMatching(/^SEC-08 CRITICAL Private key/),
    ]);
  });

  it("flags RSA / OPENSSH private key headers but never a public key", async () => {
    expect(await summarize("-----BEGIN RSA PRIVATE KEY-----", "id_rsa.txt")).toHaveLength(1);
    expect(await summarize("-----BEGIN OPENSSH PRIVATE KEY-----", "deploy.md")).toHaveLength(1);
    expect(await summarize("-----BEGIN PUBLIC KEY-----", "key.md")).toEqual([]);
  });

  it.each([
    ["GitHub", "ghp_3dwcgEqOIzyVSVmgZ1CkbZJc8Ed4kjlCHjvV", "CRITICAL"],
    ["Slack", "xoxb-6442569059-9735232264-TN1R4HOA0NOE", "CRITICAL"],
    ["Slack webhook", "https://hooks.slack.com/services/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", "HIGH"],
    ["Stripe webhook signing", "whsec_P4F66EsGoksly3JMuNVXLuhuYukVygQz", "HIGH"],
    ["Groq", `gsk_${"Ab1".repeat(17)}`, "CRITICAL"],
    ["Hugging Face", `hf_${"Ab1".repeat(12)}`, "CRITICAL"],
    ["Replicate", `r8_${"Ab1".repeat(13)}`, "CRITICAL"],
  ])("flags a hardcoded %s credential as SEC-09", async (provider, token, severity) => {
    const findings = await secretsDetector.detect(makeContext(`const value = "${token}";`));

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ ruleId: "SEC-09", severity });
    expect(findings[0]?.message).toContain(provider);
    expect(JSON.stringify(findings)).not.toContain(token);
  });

  it("flags a Stripe restricted live key (rk_live_) as SEC-01", async () => {
    expect(await summarize('const k = "rk_live_51lOh0VIvyekpeNDFSypeabSIO7kdf5I";')).toEqual([expect.stringMatching(/^SEC-01 CRITICAL/)]);
  });
});

describe("secretsDetector — Google and Resend keys (SEC-09)", () => {
  const GOOGLE_KEY = "AIzaSyA1b2C3d4E5f6G7h8I9j0KlMnOpQrStUvW";

  async function summarize(content: string, filePath?: string): Promise<string[]> {
    const findings = await secretsDetector.detect(makeContext(content, filePath));
    return findings.map((finding) => `${finding.ruleId} ${finding.severity} ${finding.message.slice(0, 32)}`);
  }

  it("flags a Gemini key as CRITICAL", async () => {
    const content = `import { GoogleGenerativeAI } from "@google/generative-ai";\nconst genAI = new GoogleGenerativeAI("${GOOGLE_KEY}");`;

    expect(await summarize(content, "app/api/chat/route.ts")).toEqual([expect.stringMatching(/^SEC-09 CRITICAL Hardcoded Google Gemini/)]);
  });

  it("flags a Google key with no client-config context as HIGH", async () => {
    expect(await summarize(`const YOUTUBE_DATA = 1;\n\n\n\n\n\n\n\n\n\nconst GOOGLE_KEY = "${GOOGLE_KEY}";`, "server/google.ts")).toEqual([
      expect.stringMatching(/^SEC-09 HIGH Hardcoded Google API key/),
    ]);
  });

  it("does NOT flag Firebase web config, Maps keys, or Firebase mobile config files", async () => {
    const firebase = [
      "const firebaseConfig = {",
      `  apiKey: "${GOOGLE_KEY}",`,
      '  authDomain: "demo.firebaseapp.com",',
      '  projectId: "demo",',
      "};",
    ].join("\n");

    expect(await summarize(firebase, "lib/firebase.ts")).toEqual([]);
    expect(await summarize(`const googleMapsApiKey = "${GOOGLE_KEY}";`, "lib/maps.ts")).toEqual([]);
    expect(await summarize(`{ "api_key": [{ "current_key": "${GOOGLE_KEY}" }] }`, "android/app/google-services.json")).toEqual([]);
  });

  it("flags a Resend API key as CRITICAL and never prints it", async () => {
    const key = "re_c1tpEyD8_NKFusih9vKVQknRAQfmFcWCv";
    const findings = await secretsDetector.detect(makeContext(`const resend = new Resend("${key}");`));

    expect(findings.map((finding) => `${finding.ruleId} ${finding.severity}`)).toEqual(["SEC-09 CRITICAL"]);
    expect(findings[0]?.message).toContain("Resend");
    expect(JSON.stringify(findings)).not.toContain(key);
  });

  it("does NOT mistake a snake_case identifier for a Resend key", async () => {
    expect(await summarize("const v = re_validate_userprofilesettingsform();")).toEqual([]);
  });
});

describe("secretsDetector — documentation placeholders are not secrets", () => {
  async function ruleIds(content: string, filePath?: string): Promise<string[]> {
    const findings = await secretsDetector.detect(makeContext(content, filePath));
    return findings.map((finding) => finding.ruleId);
  }

  it.each([
    ["a README setup line", "Set `STRIPE_SECRET_KEY=sk_live_YOUR_KEY_HERE` in .env.local", "README.md"],
    ["AWS's documented example key", 'aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"', "docs/setup.md"],
    ["a zero-filled key", 'const k = "sk_live_000000000000000000000000";', "src/config.ts"],
    ["Slack's example webhook", "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX", "README.md"],
    ["a placeholder OpenAI project key", "OPENAI_API_KEY=sk-proj-replace-me-with-your-own-project-key-0001", ".env.example"],
    ["a sequential fake Anthropic key", 'key: "sk-ant-api03-abcdefghijklmnopqrstuvwxyz"', "src/x.ts"],
  ])("does not flag %s", async (_label, content, filePath) => {
    expect(await ruleIds(content, filePath)).toEqual([]);
  });

  it("still flags a real-looking key in the same README", async () => {
    expect(await ruleIds("STRIPE_SECRET_KEY=sk_live_51Qm8vRt2LpX7nWc4ZyKd9HjBfGs3TaEu", "README.md")).toEqual(["SEC-01"]);
  });
});

describe("secretsDetector — database connection strings (SEC-10)", () => {
  async function summarize(content: string, filePath?: string): Promise<string[]> {
    const findings = await secretsDetector.detect(makeContext(content, filePath));
    return findings.map((finding) => `${finding.ruleId} ${finding.severity} ${finding.matchedText ?? ""}`);
  }

  it("flags a Supabase Postgres URL with a password as CRITICAL and masks the password", async () => {
    const result = await summarize(
      'export const pool = new Pool({ connectionString: "postgresql://postgres:Hq7vRt2pLx9w@db.abcdefghijkl.supabase.co:5432/postgres" });',
    );
    expect(result).toEqual(["SEC-10 CRITICAL postgresql://postgres:****@db.abcdefghijkl.supabase.co"]);
    expect(result.join("")).not.toContain("Hq7vRt2pLx9w");
  });

  it("flags a MongoDB Atlas SRV URL as CRITICAL", async () => {
    expect(await summarize('const uri = "mongodb+srv://admin:p4ssW0rdQ9@cluster0.ab1cd.mongodb.net/app";')).toEqual([
      "SEC-10 CRITICAL mongodb+srv://admin:****@cluster0.ab1cd.mongodb.net",
    ]);
  });

  it("flags a SQLAlchemy URL on an unknown remote host as HIGH", async () => {
    expect(await summarize('DATABASE_URL = "postgresql+psycopg2://app:Zk82mQwe1xR@db.mycompany.io/prod"', "app/settings.py")).toEqual([
      "SEC-10 HIGH postgresql://app:****@db.mycompany.io",
    ]);
  });

  it.each([
    ["localhost", 'const url = "postgres://postgres:Zk82mQwe1xR@localhost:5432/dev";'],
    ["a docker-compose service", "DATABASE_URL: postgresql://app:Zk82mQwe1xR@db:5432/app"],
    ["a template variable", "const url = `postgres://${user}:${password}@db.x.supabase.co/postgres`;"],
    ["a default password", 'const url = "postgres://postgres:postgres@db.prod.example.org/app";'],
    ["a placeholder password", "DATABASE_URL=postgresql://postgres:[YOUR-PASSWORD]@db.abcdefghijkl.supabase.co:5432/postgres"],
  ])("does not flag a connection string using %s", async (_label, content) => {
    expect(await summarize(content, "docker-compose.yml")).toEqual([]);
  });
});

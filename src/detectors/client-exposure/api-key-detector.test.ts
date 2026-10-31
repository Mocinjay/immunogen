import { describe, expect, it } from "vitest";

import { clientExposureDetector } from "./api-key-detector.js";

import type { DetectorContext, StackHints } from "../../core/types.js";

/** Minimal StackHints fixture — clientExposureDetector reads ctx.content only, never ctx.stackHints. */
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

describe("clientExposureDetector — BUNDLE-01 (NEXT_PUBLIC_/VITE_ on secret-named vars)", () => {
  it("flags NEXT_PUBLIC_STRIPE_SECRET_KEY as BUNDLE-01 CRITICAL/HIGH", async () => {
    const ctx = makeContext("const key = process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY;");

    const findings = await clientExposureDetector.detect(ctx);

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      ruleId: "BUNDLE-01",
      category: "client-exposure",
      severity: "CRITICAL",
      confidence: "HIGH",
      file: "src/config.ts",
      line: 1,
    });
  });

  it("flags VITE_API_TOKEN referenced via import.meta.env as BUNDLE-01 CRITICAL", async () => {
    const ctx = makeContext("const token = import.meta.env.VITE_API_TOKEN;");

    const findings = await clientExposureDetector.detect(ctx);

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      ruleId: "BUNDLE-01",
      category: "client-exposure",
      severity: "CRITICAL",
      confidence: "HIGH",
    });
  });

  it("flags NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY as BUNDLE-01 CRITICAL", async () => {
    const ctx = makeContext("const key = process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY;");

    const findings = await clientExposureDetector.detect(ctx);

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      ruleId: "BUNDLE-01",
      severity: "CRITICAL",
      confidence: "HIGH",
    });
  });

  it("does NOT flag legitimately-public NEXT_PUBLIC_ vars (no secret keyword or publishable exclusion)", async () => {
    const ctx = makeContext(
      [
        "const pk = process.env.NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY;",
        "const ph = process.env.NEXT_PUBLIC_POSTHOG_KEY;",
        "const url = process.env.NEXT_PUBLIC_API_URL;",
        "const name = process.env.NEXT_PUBLIC_SITE_NAME;",
      ].join("\n"),
    );

    const findings = await clientExposureDetector.detect(ctx);

    // At minimum NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY and NEXT_PUBLIC_API_URL
    // must yield zero findings (the plan's explicit minimum bar).
    const ruleIdsOnPublishableOrUrlLines = findings.filter(
      (f) => f.line === 1 || f.line === 3,
    );
    expect(ruleIdsOnPublishableOrUrlLines).toHaveLength(0);
  });

  it("does NOT flag the publishable-key exclusion in isolation", async () => {
    const ctx = makeContext("const pk = process.env.NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY;");

    const findings = await clientExposureDetector.detect(ctx);

    expect(findings).toHaveLength(0);
  });

  it("does NOT flag a plain public URL var", async () => {
    const ctx = makeContext("const url = process.env.NEXT_PUBLIC_API_URL;");

    const findings = await clientExposureDetector.detect(ctx);

    expect(findings).toHaveLength(0);
  });

  it("does NOT flag the same vulnerable string inside a __tests__/fixtures path (FP allowlist guard)", async () => {
    const ctx = makeContext(
      "const key = process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY;",
      "src/__tests__/fixtures/env-fixture.ts",
    );

    const findings = await clientExposureDetector.detect(ctx);

    expect(findings).toHaveLength(0);
  });

  it("reports a 1-indexed line number matching the variable's actual line", async () => {
    const ctx = makeContext(
      "// line 1\n// line 2\nconst key = process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY;\n",
    );

    const findings = await clientExposureDetector.detect(ctx);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.line).toBe(3);
  });

  it("never includes a secret value in matchedText, only the variable name", async () => {
    const ctx = makeContext("const key = process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY;");

    const findings = await clientExposureDetector.detect(ctx);
    const finding = findings[0];

    expect(finding).toBeDefined();
    expect(finding?.matchedText).toBe("NEXT_PUBLIC_STRIPE_SECRET_KEY");
  });
});

describe("clientExposureDetector — no-throw contract", () => {
  it("resolves to [] for empty content", async () => {
    const ctx = makeContext("");

    const findings = await clientExposureDetector.detect(ctx);

    expect(findings).toEqual([]);
  });

  it("resolves to [] for malformed/binary-ish content without rejecting", async () => {
    const ctx = makeContext(" � garbled content");

    await expect(clientExposureDetector.detect(ctx)).resolves.toEqual([]);
  });
});

describe("clientExposureDetector — config", () => {
  it("declares category client-exposure and a name of 'client-exposure'", () => {
    expect(clientExposureDetector.config.name).toBe("client-exposure");
    expect(clientExposureDetector.config.category).toBe("client-exposure");
  });

  it("declares text-targetable globs including .env files", () => {
    expect(clientExposureDetector.config.globs.some((glob) => glob.includes(".env"))).toBe(true);
  });
});

describe("clientExposureDetector — more client prefixes and public-by-design keys", () => {
  async function ruleIds(content: string): Promise<string[]> {
    const findings = await clientExposureDetector.detect(makeContext(content));
    return findings.map((finding) => finding.ruleId);
  }

  it("flags secret-named vars behind Expo, CRA, Nuxt, and Gatsby client prefixes", async () => {
    expect(await ruleIds("const k = process.env.EXPO_PUBLIC_OPENAI_API_KEY;")).toEqual(["BUNDLE-01"]);
    expect(await ruleIds("const k = process.env.REACT_APP_STRIPE_SECRET_KEY;")).toEqual(["BUNDLE-01"]);
    expect(await ruleIds("const k = config.NUXT_PUBLIC_ANTHROPIC_API_KEY;")).toEqual(["BUNDLE-01"]);
    expect(await ruleIds("const k = process.env.GATSBY_GITHUB_TOKEN;")).toEqual(["BUNDLE-01"]);
  });

  it("does NOT flag keys that are public by design", async () => {
    for (const name of [
      "NEXT_PUBLIC_SUPABASE_ANON_KEY",
      "VITE_SUPABASE_ANON_KEY",
      "EXPO_PUBLIC_SUPABASE_ANON_KEY",
      "NEXT_PUBLIC_FIREBASE_API_KEY",
      "NEXT_PUBLIC_RECAPTCHA_SITE_KEY",
      "NEXT_PUBLIC_TURNSTILE_SITE_KEY",
      "NEXT_PUBLIC_VAPID_PUBLIC_KEY",
      "NEXT_PUBLIC_GOOGLE_MAPS_API_KEY",
      "NEXT_PUBLIC_MAPBOX_TOKEN",
      "NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY",
      "EXPO_PUBLIC_REVENUECAT_IOS_KEY",
    ]) {
      expect(await ruleIds(`const k = process.env.${name};`), name).toEqual([]);
    }
  });

  it("still flags a public-looking name that also says SECRET / PRIVATE / SERVICE_ROLE / ADMIN", async () => {
    expect(await ruleIds("process.env.NEXT_PUBLIC_FIREBASE_PRIVATE_KEY")).toEqual(["BUNDLE-01"]);
    expect(await ruleIds("process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY")).toEqual(["BUNDLE-01"]);
    expect(await ruleIds("process.env.VITE_FIREBASE_ADMIN_KEY")).toEqual(["BUNDLE-01"]);
  });

  it("does NOT flag non-secret names that merely contain ADMIN or PRIVATE", async () => {
    expect(await ruleIds("process.env.NEXT_PUBLIC_ADMIN_EMAIL")).toEqual([]);
    expect(await ruleIds("process.env.NEXT_PUBLIC_PRIVATE_BETA_ENABLED")).toEqual([]);
  });

  it("flags an LLM SDK client constructed with dangerouslyAllowBrowser: true as BUNDLE-02", async () => {
    const findings = await clientExposureDetector.detect(
      makeContext("const client = new OpenAI({ apiKey: userKey, dangerouslyAllowBrowser: true });"),
    );

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ ruleId: "BUNDLE-02", severity: "HIGH", line: 1 });
  });
});

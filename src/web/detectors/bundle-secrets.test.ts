import { describe, expect, it } from "vitest";

import { bundleSecretsDetector } from "./bundle-secrets.js";

import type { FetchedTarget } from "../fetch-target.js";
import type { WebContext } from "../types.js";

function makeTarget(overrides: Partial<FetchedTarget> = {}): FetchedTarget {
  return {
    url: "https://example.com/",
    status: 200,
    headers: {},
    body: "<html></html>",
    scripts: [],
    cookies: [],
    ...overrides,
  };
}

function makeCtx(target: FetchedTarget): WebContext {
  return { target, probes: [] };
}

const LIVE_STRIPE_KEY = "sk_live_51H8xyzABCDEFGHIJKLMNOP";

describe("bundleSecretsDetector — WEB-SEC (vulnerable)", () => {
  it("flags a live Stripe key in a same-origin script bundle as CRITICAL, and redacts it", () => {
    const target = makeTarget({
      scripts: [{ url: "https://example.com/app.js", body: `const key = "${LIVE_STRIPE_KEY}";` }],
    });

    const findings = bundleSecretsDetector.detect(makeCtx(target));

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      ruleId: "WEB-SEC",
      category: "web",
      severity: "CRITICAL",
      file: "https://example.com/app.js",
    });
    // Raw secret must never appear anywhere in the finding output.
    const serialized = JSON.stringify(findings[0]);
    expect(serialized).not.toContain(LIVE_STRIPE_KEY);
    expect(serialized).toContain("[REDACTED]");
  });

  it("flags an AWS key as CRITICAL", () => {
    const target = makeTarget({
      scripts: [{ url: "https://example.com/app.js", body: "AKIAABCDEFGHIJKLMNOP" }],
    });

    const findings = bundleSecretsDetector.detect(makeCtx(target));

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ severity: "CRITICAL" });
  });

  it("flags an OpenAI-shaped key as HIGH", () => {
    const openAiKey = `sk-${"a".repeat(48)}`;
    const target = makeTarget({
      scripts: [{ url: "https://example.com/app.js", body: openAiKey }],
    });

    const findings = bundleSecretsDetector.detect(makeCtx(target));

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ severity: "HIGH" });
  });

  it("finds a secret inside an inline <script> block on the page body, reporting the page URL as file", () => {
    const target = makeTarget({
      body: `<html><body><script>var k = "${LIVE_STRIPE_KEY}";</script></body></html>`,
    });

    const findings = bundleSecretsDetector.detect(makeCtx(target));

    expect(findings).toHaveLength(1);
    expect(findings[0]?.file).toBe("https://example.com/");
  });

  it("reports a line number within the script body for a multi-line bundle", () => {
    const body = ["// line 1", "// line 2", `const key = "${LIVE_STRIPE_KEY}";`].join("\n");
    const target = makeTarget({ scripts: [{ url: "https://example.com/app.js", body }] });

    const findings = bundleSecretsDetector.detect(makeCtx(target));

    expect(findings[0]?.line).toBe(3);
  });
});

describe("bundleSecretsDetector — WEB-SEC (clean)", () => {
  it("yields zero findings when no script bundle or inline script contains a secret", () => {
    const target = makeTarget({
      scripts: [{ url: "https://example.com/app.js", body: "console.log('hello world');" }],
      body: "<html><body><script>console.log('hi');</script></body></html>",
    });

    expect(bundleSecretsDetector.detect(makeCtx(target))).toEqual([]);
  });

  it("yields zero findings for a target with no scripts and no inline scripts", () => {
    expect(bundleSecretsDetector.detect(makeCtx(makeTarget()))).toEqual([]);
  });
});

describe("bundleSecretsDetector — Google API keys", () => {
  const googleKey = `AIza${"S".repeat(35)}`;
  const target = (body: string) => ({
    target: { url: "https://example.com/", status: 200, headers: {}, body: "", scripts: [{ url: "https://example.com/app.js", body }], cookies: [] },
    probes: [],
  });

  it("does not report a Firebase web config key (public by design)", () => {
    const body = `const firebaseConfig = { apiKey: "${googleKey}", authDomain: "x.firebaseapp.com" };`;

    expect(bundleSecretsDetector.detect(target(body))).toEqual([]);
  });

  it("does not report a bare Google key with no Gemini context", () => {
    expect(bundleSecretsDetector.detect(target(`const k = "${googleKey}";`))).toEqual([]);
  });

  it("reports a Gemini key shipped to the browser as CRITICAL, naming the provider", () => {
    const body = `import { GoogleGenerativeAI } from "@google/generative-ai"; const genAI = new GoogleGenerativeAI("${googleKey}");`;

    const findings = bundleSecretsDetector.detect(target(body));

    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe("CRITICAL");
    expect(findings[0]?.message).toContain("Gemini");
  });
});

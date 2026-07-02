import { describe, expect, it } from "vitest";

import { REDACTED_PLACEHOLDER, Redactor, redactFinding } from "./redactor.js";

import type { Finding } from "../core/types.js";

/**
 * Fixture Anthropic key used across the redaction-proof tests (SAFE-01
 * criterion 1). Shaped as `sk-ant-api03-` followed by base64url-alphabet
 * characters, matching the real key format Anthropic issues. This exact
 * literal must NEVER appear verbatim in any redactor.ts output.
 */
const ANTHROPIC_KEY = "sk-ant-api03-AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLL-ZZZZ";

const STRIPE_KEY = "sk_live_4eC39HqLyjWDarjtT1zdp7dc";
const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";
const OPENAI_KEY = `sk-${"A".repeat(48)}`;

/** A syntactically well-formed base64url JWT shape (header.payload.signature), not a real token. */
const JWT_LIKE = "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYW5vbiJ9.abc123DEF456-_ghi";

describe("Redactor.redactSnippet — SAFE-01 redaction-proof gate", () => {
  it("replaces a verbatim Anthropic sk-ant-api03-... key with [REDACTED] and the key never survives verbatim", () => {
    const input = `const k = "${ANTHROPIC_KEY}";`;

    const output = Redactor.redactSnippet(input);

    expect(output).not.toContain(ANTHROPIC_KEY);
    expect(output).toContain(REDACTED_PLACEHOLDER);
  });

  it("replaces a Stripe sk_live_ key with [REDACTED]", () => {
    const input = `const stripeKey = "${STRIPE_KEY}";`;

    const output = Redactor.redactSnippet(input);

    expect(output).not.toContain(STRIPE_KEY);
    expect(output).toContain(REDACTED_PLACEHOLDER);
  });

  it("replaces an AWS AKIA... access key with [REDACTED]", () => {
    const input = `const awsKey = "${AWS_KEY}";`;

    const output = Redactor.redactSnippet(input);

    expect(output).not.toContain(AWS_KEY);
    expect(output).toContain(REDACTED_PLACEHOLDER);
  });

  it("replaces an OpenAI sk-<48 chars> key with [REDACTED]", () => {
    const input = `const openaiKey = "${OPENAI_KEY}";`;

    const output = Redactor.redactSnippet(input);

    expect(output).not.toContain(OPENAI_KEY);
    expect(output).toContain(REDACTED_PLACEHOLDER);
  });

  it("replaces a service_role-shaped JWT (eyJ...) with [REDACTED]", () => {
    const input = `const token = "${JWT_LIKE}";`;

    const output = Redactor.redactSnippet(input);

    expect(output).not.toContain(JWT_LIKE);
    expect(output).toContain(REDACTED_PLACEHOLDER);
  });

  it("replaces a bare SUPABASE_SERVICE_ROLE_KEY identifier reference with [REDACTED]", () => {
    const input = "const key = process.env.SUPABASE_SERVICE_ROLE_KEY;";

    const output = Redactor.redactSnippet(input);

    expect(output).not.toContain("SUPABASE_SERVICE_ROLE_KEY");
    expect(output).toContain(REDACTED_PLACEHOLDER);
  });

  it("replaces a high-entropy quoted literal anchored to a secret keyword on the same line", () => {
    // >=40 chars, high entropy (mixed case + digits + symbols), and the line
    // itself contains the keyword "secret" — should be redacted.
    const highEntropyValue = "Zq9!kP2vLxT7mR4wN8yB1sC6dF3hJ0uE5gK9aQzWx";
    const input = `const secret = "${highEntropyValue}"; // secret value`;

    const output = Redactor.redactSnippet(input);

    expect(output).not.toContain(highEntropyValue);
    expect(output).toContain(REDACTED_PLACEHOLDER);
  });

  it("leaves the SAME high-entropy literal intact when NO anchor keyword is present on its line (no over-redaction)", () => {
    // Same shape/length/entropy as above, but no secret/key/token/password
    // keyword anywhere on the line — must NOT be redacted.
    const highEntropyValue = "Zq9!kP2vLxT7mR4wN8yB1sC6dF3hJ0uE5gK9aQzWx";
    const input = `const uuidLikeValue = "${highEntropyValue}";`;

    const output = Redactor.redactSnippet(input);

    expect(output).toContain(highEntropyValue);
    expect(output).not.toContain(REDACTED_PLACEHOLDER);
  });

  it("returns ordinary prose / low-entropy code unchanged", () => {
    const input = "const total = price * qty;";

    const output = Redactor.redactSnippet(input);

    expect(output).toBe(input);
  });

  it("is idempotent — running redactSnippet twice yields the same string", () => {
    const input = `const k = "${ANTHROPIC_KEY}"; const stripeKey = "${STRIPE_KEY}";`;

    const once = Redactor.redactSnippet(input);
    const twice = Redactor.redactSnippet(once);

    expect(twice).toBe(once);
  });
});

describe("redactFinding — Finding.matchedText/message redaction", () => {
  const BASE_FINDING: Finding = {
    ruleId: "SEC-99",
    category: "secrets",
    detectorName: "test-fixture",
    file: "src/config.ts",
    line: 1,
    severity: "CRITICAL",
    confidence: "HIGH",
    message: `Hardcoded Anthropic key found: ${ANTHROPIC_KEY}`,
    remediation: `Rotate the key. It was found here: ${ANTHROPIC_KEY}`,
    matchedText: ANTHROPIC_KEY,
  };

  it("redacts remediation so a leaked secret embedded there is absent (belt-and-suspenders for SAFE-01)", () => {
    const redacted = redactFinding(BASE_FINDING);

    expect(redacted.remediation).not.toContain(ANTHROPIC_KEY);
    expect(redacted.remediation).toContain(REDACTED_PLACEHOLDER);
  });

  it("does not mutate the input finding's remediation", () => {
    const originalRemediation = BASE_FINDING.remediation;

    redactFinding(BASE_FINDING);

    expect(BASE_FINDING.remediation).toBe(originalRemediation);
  });

  it("redacts matchedText so the verbatim secret is absent", () => {
    const redacted = redactFinding(BASE_FINDING);

    expect(redacted.matchedText).not.toContain(ANTHROPIC_KEY);
    expect(redacted.matchedText).toContain(REDACTED_PLACEHOLDER);
  });

  it("redacts message so the verbatim secret is absent", () => {
    const redacted = redactFinding(BASE_FINDING);

    expect(redacted.message).not.toContain(ANTHROPIC_KEY);
    expect(redacted.message).toContain(REDACTED_PLACEHOLDER);
  });

  it("does not mutate the input finding", () => {
    const originalMessage = BASE_FINDING.message;
    const originalMatchedText = BASE_FINDING.matchedText;

    redactFinding(BASE_FINDING);

    expect(BASE_FINDING.message).toBe(originalMessage);
    expect(BASE_FINDING.matchedText).toBe(originalMatchedText);
  });

  it("preserves other Finding fields unchanged", () => {
    const redacted = redactFinding(BASE_FINDING);

    expect(redacted.ruleId).toBe(BASE_FINDING.ruleId);
    expect(redacted.category).toBe(BASE_FINDING.category);
    expect(redacted.file).toBe(BASE_FINDING.file);
    expect(redacted.line).toBe(BASE_FINDING.line);
    expect(redacted.severity).toBe(BASE_FINDING.severity);
    expect(redacted.confidence).toBe(BASE_FINDING.confidence);
  });

  it("handles a Finding with no matchedText gracefully", () => {
    const findingWithoutMatchedText: Finding = {
      ruleId: "SEC-99",
      category: "secrets",
      detectorName: "test-fixture",
      file: "src/config.ts",
      line: 1,
      severity: "CRITICAL",
      confidence: "HIGH",
      message: "Plain message with no secret.",
      remediation: "N/A",
    };

    const redacted = redactFinding(findingWithoutMatchedText);

    expect(redacted.matchedText).toBeUndefined();
    expect(redacted.message).toBe("Plain message with no secret.");
  });
});

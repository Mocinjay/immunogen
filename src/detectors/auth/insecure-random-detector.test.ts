import { describe, expect, it } from "vitest";

import { buildAstCache } from "../../core/parse/ast-cache.js";
import { insecureRandomDetector } from "./insecure-random-detector.js";

import type { DetectorContext, StackHints } from "../../core/types.js";

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

async function names(content: string, filePath = "lib/auth.ts"): Promise<string[]> {
  const { astCache } = buildAstCache(new Map([[filePath, content]]));
  const ctx: DetectorContext = { filePath, content, ast: astCache.get(filePath), stackHints: STACK_HINTS, fileSet: new Map([[filePath, content]]) };
  const findings = await insecureRandomDetector.detect(ctx);
  return findings.map((finding) => `${finding.ruleId} ${finding.severity} ${finding.matchedText ?? ""}`);
}

describe("insecureRandomDetector — AUTH-11", () => {
  it.each([
    ["a 6-digit OTP", "const otp = Math.floor(100000 + Math.random() * 900000);", "otp"],
    ["a verification code string", "const verificationCode = Math.random().toString().slice(2, 8);", "verificationCode"],
    ["a reset token in an object", "await db.user.update({ data: { resetToken: Math.random().toString(36).slice(2) } });", "resetToken"],
    ["a code-generating function", "function generateLoginCode() { return String(Math.floor(Math.random() * 1e6)).padStart(6, '0'); }", "generateLoginCode"],
    ["an arrow helper", "export const makeCode = () => Math.floor(Math.random() * 10000);", "makeCode"],
    ["an assignment to a session id", "user.sessionId = Math.random().toString(36);", "sessionId"],
  ])("flags %s", async (_label, code, name) => {
    expect(await names(code)).toEqual([`AUTH-11 MEDIUM ${name}`]);
  });

  it.each([
    ["animation jitter", "const delay = Math.random() * 300;"],
    ["a random colour code", "const colorCode = '#' + Math.floor(Math.random() * 0xffffff).toString(16);"],
    ["a status code in a mock", "const statusCode = Math.random() > 0.5 ? 200 : 500;"],
    ["an id", "const id = Math.random().toString(36).slice(2);"],
    ["a pinned flag", "const pinned = Math.random() > 0.5;"],
    ["crypto.randomInt", "const otp = crypto.randomInt(100000, 1000000);"],
  ])("does NOT flag %s", async (_label, code) => {
    expect(await names(code)).toEqual([]);
  });

  it("skips seed scripts and tests", async () => {
    const code = "const token = Math.random().toString(36);";
    expect(await names(code, "prisma/seed.ts")).toEqual([]);
    expect(await names(code, "scripts/make-users.ts")).toEqual([]);
    expect(await names(code, "lib/auth.test.ts")).toEqual([]);
  });
});

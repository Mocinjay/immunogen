/**
 * Coverage for the 14-item "What a HACKER tries on your vibe coded app"
 * checklist. Each item has one deliberately vulnerable file in
 * tests/fixtures/vulnerable-apps/hacker-checklist (see its README) and a
 * safe twin in tests/fixtures/clean-apps/hacker-checklist-clean.
 *
 * The vulnerable scan must raise the expected rule on the expected file for
 * every item; the clean twin must raise nothing (the golden suite also
 * asserts that). Runs offline: queryOsvBatch is mocked at the module
 * boundary, the same pattern as phase5-coverage.test.ts.
 */
import { describe, expect, it, vi } from "vitest";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import type { OsvResult } from "../../src/detectors/deps/osv-client.js";

vi.mock("../../src/detectors/deps/osv-client.js", () => ({
  queryOsvBatch: (): Promise<OsvResult[]> => Promise.resolve([]),
}));

const { scan } = await import("../../src/index.js");

const __dirname = dirname(fileURLToPath(import.meta.url));
const VULNERABLE_ROOT = join(__dirname, "..", "fixtures", "vulnerable-apps", "hacker-checklist");
const CLEAN_ROOT = join(__dirname, "..", "fixtures", "clean-apps", "hacker-checklist-clean");

/** [checklist item, file, ruleId] — every row must fire. */
const CHECKLIST: Array<[string, string, string]> = [
  ["1. Script in your username", "lib/profile-card.ts", "INJECT-01"],
  ["2. Change the ID in the URL", "app/account/page.tsx", "AUTH-08"],
  ["3. Type /admin (page)", "app/admin/page.tsx", "AUTH-09"],
  ["3. Type /admin (API)", "app/api/admin/users/route.ts", "AUTH-09"],
  ["4. API key in the browser", "components/ChatWidget.tsx", "BUNDLE-01"],
  ["5. Prompt-inject your AI", "app/api/support/route.ts", "AILAYER-07"],
  ["6. Admin at signup", "app/api/signup/route.ts", "AUTH-10"],
  ["7. Edit the price", "app/api/checkout/route.ts", "PAY-03"],
  ["8. Fake a payment", "app/api/orders/[id]/paid/route.ts", "PAY-04"],
  ["9. Redeem it 100 times", "app/api/cart/coupon/route.ts", "PAY-05"],
  ["10. Order -1 items", "app/api/cart/route.ts", "PAY-06"],
  ["11. Guess the login code (no attempt limit)", "app/api/auth/verify-code/route.ts", "RATE-01"],
  ["11. Guess the login code (predictable code)", "lib/otp.ts", "AUTH-11"],
  ["12. Query your database", "app/api/products/search/route.ts", "INJECT-02"],
  ["13. .env in Git", ".env", "SEC-05"],
  ["14. Upload a non-photo", "app/api/avatar/route.ts", "UPLOAD-01"],
];

describe("hacker checklist — every item is caught", async () => {
  const result = await scan(VULNERABLE_ROOT, { offline: true });

  it.each(CHECKLIST)("%s -> %s raises %s", (_item, file, ruleId) => {
    const hits = result.findings.filter((finding) => finding.file === file && finding.ruleId === ruleId);
    expect(hits.length, `${ruleId} on ${file}`).toBeGreaterThan(0);
  });

  it("blocks the launch", () => {
    expect(result.score.verdict).toBe("blocked");
    expect(result.score.grade).toBe("F");
  });

  it("does not report the code-verification route as unauthenticated (it runs before a session exists)", () => {
    expect(result.findings.some((finding) => finding.ruleId === "AUTH-01" && finding.file === "app/api/auth/verify-code/route.ts")).toBe(false);
  });
});

describe("hacker checklist — the safe twin is clean", () => {
  it("raises no findings", async () => {
    const result = await scan(CLEAN_ROOT);
    expect(result.findings.map((finding) => `${finding.ruleId} ${finding.file}:${finding.line}`)).toEqual([]);
  });
});

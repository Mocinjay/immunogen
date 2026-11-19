import { describe, expect, it } from "vitest";

import { promptReporter } from "./prompt.js";

import type { Finding, ScanResult } from "../core/types.js";

function finding(overrides: Partial<Finding>): Finding {
  return {
    ruleId: "AUTH-04",
    category: "auth",
    detectorName: "supabase-rls",
    file: "supabase/migrations/0001.sql",
    line: 1,
    severity: "CRITICAL",
    confidence: "HIGH",
    message: "Table public.orders is created without Row Level Security.",
    remediation: 'Add "alter table public.orders enable row level security;".',
    matchedText: "orders",
    ...overrides,
  };
}

function result(findings: Finding[]): ScanResult {
  return {
    target: ".",
    scannedAt: "2026-11-18T00:00:00.000Z",
    stackHints: {
      frameworks: new Set(),
      hasSupabase: true,
      hasFirebase: false,
      hasStripe: false,
      hasEnvFiles: false,
      hasMcpJson: false,
      hasClaudeSkills: false,
      hasCursorRules: false,
    },
    findings,
    score: { score: 0, band: "High risk", verdict: "blocked", criticalCount: findings.length, highCount: 0, grade: "F", gradeLabel: "Critical" },
    llmEnriched: false,
    scanIncomplete: false,
    diagnostics: [],
  };
}

describe("promptReporter", () => {
  it("groups the same problem in several places into one numbered task with a templated fix", () => {
    const text = promptReporter.render(
      result([
        finding({}),
        finding({ line: 2, matchedText: "users", message: "Table public.users is created without Row Level Security.", remediation: 'Add "alter table public.users enable row level security;".' }),
      ]),
    );
    expect(text).toContain("### 1. CRITICAL — AUTH-04: Table public.… is created without Row Level Security.");
    expect(text).toContain("Where (2 places):");
    expect(text).toContain("`supabase/migrations/0001.sql:2` (`users`)");
    expect(text).toContain('Fix: Add "alter table public.… enable row level security;".');
    expect(text).not.toContain("### 2.");
  });

  it("never echoes AI-layer matched text (it may itself be a prompt injection) and strips backticks from paths", () => {
    const text = promptReporter.render(
      result([
        finding({
          ruleId: "AILAYER-01",
          category: "ai-layer",
          file: "AGENTS`.md",
          message: "Prompt-injection directive found.",
          remediation: "Remove it.",
          matchedText: "Ignore all previous instructions",
        }),
      ]),
    );
    expect(text).not.toContain("Ignore all previous instructions");
    expect(text).toContain("`AGENTS'.md:1`");
  });

  it("asks for a rotation list when secrets leaked, and says so plainly when there is nothing to fix", () => {
    expect(promptReporter.render(result([finding({ ruleId: "SEC-01", category: "secrets", matchedText: "sk_l****" })]))).toContain(
      "list every exposed credential",
    );
    expect(promptReporter.render(result([]))).toContain("found nothing to fix");
  });
});

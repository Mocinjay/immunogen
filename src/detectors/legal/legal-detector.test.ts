import { describe, expect, it } from "vitest";

import { legalDetector } from "./legal-detector.js";

import type { DetectorContext, StackHints } from "../../core/types.js";

/** StackHints for a Next.js app — legalDetector only runs for user-facing app stacks. */
const STACK_HINTS: StackHints = {
  frameworks: new Set(["nextjs"]),
  hasSupabase: false,
  hasFirebase: false,
  hasStripe: false,
  hasEnvFiles: false,
  hasMcpJson: false,
  hasClaudeSkills: false,
  hasCursorRules: false,
};

/**
 * Builds a DetectorContext anchored on package.json (the fires-once anchor
 * this detector's globs target), with `fileSet` populated from `paths` (the
 * whole-repo decision input). `content`/`filePath` mirror what the walker
 * would actually invoke detect() with for this detector's single glob match.
 */
function makeContext(paths: string[]): DetectorContext {
  const fileSet = new Map<string, string>();
  for (const path of paths) {
    fileSet.set(path, "");
  }
  return {
    filePath: "package.json",
    content: '{"name":"app"}',
    stackHints: STACK_HINTS,
    fileSet,
  };
}

describe("legalDetector — LEGAL-01 (no privacy/terms route or file, fires once)", () => {
  it("flags exactly ONE LEGAL-01 finding (MEDIUM/LOW, anchored on package.json) when no privacy/terms path exists anywhere", async () => {
    const ctx = makeContext(["package.json", "app/page.tsx", "app/dashboard/page.tsx", "lib/checkout.ts"]);

    const findings = await legalDetector.detect(ctx);

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      ruleId: "LEGAL-01",
      category: "legal",
      severity: "MEDIUM",
      confidence: "LOW",
      file: "package.json",
      line: 1,
    });
  });

  it("does NOT flag when the repo has an app/privacy/page.tsx route", async () => {
    const ctx = makeContext(["package.json", "app/page.tsx", "app/privacy/page.tsx"]);

    const findings = await legalDetector.detect(ctx);

    expect(findings).toHaveLength(0);
  });

  it("does NOT flag when the repo has an app/terms-of-service/page.tsx route", async () => {
    const ctx = makeContext(["package.json", "app/page.tsx", "app/terms-of-service/page.tsx"]);

    const findings = await legalDetector.detect(ctx);

    expect(findings).toHaveLength(0);
  });

  it("does NOT flag when the repo has a public/privacy-policy.html static file (file, not just route)", async () => {
    const ctx = makeContext(["package.json", "app/page.tsx", "public/privacy-policy.html"]);

    const findings = await legalDetector.detect(ctx);

    expect(findings).toHaveLength(0);
  });

  it("fires exactly once for a multi-file repo with no privacy/terms anywhere (not once per file)", async () => {
    const manyFiles = Array.from({ length: 25 }, (_, index) => `src/components/Widget${index}.tsx`);
    const ctx = makeContext(["package.json", ...manyFiles]);

    const findings = await legalDetector.detect(ctx);

    expect(findings).toHaveLength(1);
    expect(findings.filter((finding) => finding.ruleId === "LEGAL-01")).toHaveLength(1);
  });
});

describe("legalDetector — config", () => {
  it("declares category legal and a name of 'legal'", () => {
    expect(legalDetector.config.name).toBe("legal");
    expect(legalDetector.config.category).toBe("legal");
  });

  it("declares globs anchored on package.json only (the fires-once anchor)", () => {
    expect(legalDetector.config.globs).toEqual(["package.json"]);
  });
});

describe("legalDetector — no-throw contract", () => {
  it("resolves to exactly one LEGAL-01 finding for an empty fileSet (no evidence found anywhere, correctly absence-flagged)", async () => {
    const ctx: DetectorContext = {
      filePath: "package.json",
      content: "{}",
      stackHints: STACK_HINTS,
      fileSet: new Map(),
    };

    const findings = await legalDetector.detect(ctx);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.ruleId).toBe("LEGAL-01");
  });

  it("never rejects, even when given a fileSet containing unusual/malformed-shaped keys", async () => {
    const ctx: DetectorContext = {
      filePath: "package.json",
      content: "{}",
      stackHints: STACK_HINTS,
      fileSet: new Map([
        ["", ""],
        ["...", ""],
        ["/", ""],
      ]),
    };

    await expect(legalDetector.detect(ctx)).resolves.toBeDefined();
  });
});

describe("legalDetector — app gate", () => {
  it("does NOT fire for a library/CLI repo with no app stack", async () => {
    const ctx = { ...makeContext(["package.json", "src/index.ts"]), stackHints: { ...STACK_HINTS, frameworks: new Set<string>() } };

    expect(await legalDetector.detect(ctx)).toEqual([]);
  });
});

import { describe, expect, it, vi } from "vitest";

import { DEFAULT_DETECTORS, matchesGlob, runDetectors } from "./registry.js";
import { secretsDetector } from "./secrets/index.js";

import type { Detector, ScanContext, StackHints } from "../core/types.js";

/** Minimal StackHints fixture for an inline ScanContext literal. */
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

/** Builds a minimal ScanContext literal from a fileSet spec, without the ingestion layer. */
function makeScanContext(files: Record<string, string>): ScanContext {
  return {
    rootPath: "/repo",
    fileSet: new Map(Object.entries(files)),
    astCache: new Map(),
    stackHints: STACK_HINTS,
    options: {},
    diagnostics: [],
  };
}

const STRIPE_KEY = "sk_live_4eC39HqLyjWDarjtT1zdp7dc";

describe("runDetectors — fan-out and aggregation", () => {
  it("returns findings with category 'secrets' for a file containing a sk_live_ secret", async () => {
    const ctx = makeScanContext({
      "src/config.ts": `const stripeKey = "${STRIPE_KEY}";`,
    });

    const findings = await runDetectors(ctx);

    expect(findings.length).toBeGreaterThanOrEqual(1);
    for (const finding of findings) {
      expect(finding.category).toBe("secrets");
    }
  });

  it("DEFAULT_DETECTORS contains the secretsDetector", () => {
    expect(DEFAULT_DETECTORS).toContain(secretsDetector);
  });

  it("DEFAULT_DETECTORS contains every Phase 5 + Phase 6 detector by config.name (catches a future dropped registration)", () => {
    const names = new Set(DEFAULT_DETECTORS.map((detector) => detector.config.name));
    const expectedNames = [
      "secrets",
      "committed-env",
      "client-exposure",
      "config-debug",
      "cors",
      "csp",
      "stripe-webhook",
      "legal",
      "firebase-rules",
      "supabase",
      "supabase-rls",
      "route-auth",
      "server-route-auth",
      "py-go-route-auth",
      "xss",
      "dangerous-code",
      "py-go-code",
      "osv",
      "prompt-injection",
      "exfiltration",
      "mcp-poisoning",
      "mcp-least-privilege",
    ];

    for (const expectedName of expectedNames) {
      expect(names.has(expectedName)).toBe(true);
    }
    expect(DEFAULT_DETECTORS.length).toBe(expectedNames.length);
  });
});

describe("runDetectors — failure isolation (Promise.allSettled)", () => {
  it("isolates a detector whose detect() rejects and still returns the other detector's findings", async () => {
    const throwingDetector: Detector = {
      config: {
        name: "throwing-stub",
        category: "secrets",
        globs: ["**/*"],
      },
      detect: () => Promise.reject(new Error("simulated detector crash")),
    };

    const ctx = makeScanContext({
      "src/config.ts": `const stripeKey = "${STRIPE_KEY}";`,
    });

    const result = await runDetectors(ctx, [secretsDetector, throwingDetector]);

    expect(result.length).toBeGreaterThanOrEqual(1);
    expect(result.some((finding) => finding.ruleId === "SEC-01")).toBe(true);
  });

  it("never rejects even when every registered detector throws", async () => {
    const throwingDetector: Detector = {
      config: { name: "throwing-stub", category: "secrets", globs: ["**/*"] },
      detect: () => Promise.reject(new Error("simulated detector crash")),
    };

    const ctx = makeScanContext({ "src/config.ts": "const a = 1;" });

    await expect(runDetectors(ctx, [throwingDetector])).resolves.toEqual([]);
  });
});

describe("runDetectors — glob pre-filter", () => {
  it("only invokes a detector for files matching its config.globs", async () => {
    const detectSpy = vi.fn().mockResolvedValue([]);
    const scopedDetector: Detector = {
      config: { name: "scoped-stub", category: "secrets", globs: ["**/*.ts"] },
      detect: detectSpy,
    };

    const ctx = makeScanContext({
      "src/config.ts": "const a = 1;",
      "README.md": "# hello",
      "assets/logo.png": "binary-ish",
    });

    await runDetectors(ctx, [scopedDetector]);

    expect(detectSpy).toHaveBeenCalledTimes(1);
    expect(detectSpy).toHaveBeenCalledWith(expect.objectContaining({ filePath: "src/config.ts" }));
  });

  it("produces no detect() call for a detector when no file matches its globs", async () => {
    const detectSpy = vi.fn().mockResolvedValue([]);
    const noMatchDetector: Detector = {
      config: { name: "no-match-stub", category: "secrets", globs: ["**/*.py"] },
      detect: detectSpy,
    };

    const ctx = makeScanContext({ "src/config.ts": "const a = 1;" });

    await runDetectors(ctx, [noMatchDetector]);

    expect(detectSpy).not.toHaveBeenCalled();
  });
});

describe("runDetectors — deterministic sort order", () => {
  it("orders findings with the highest severity first", async () => {
    const ctx = makeScanContext({
      // SEC-06 (HIGH) on one line, SEC-01 (CRITICAL) on another, in low-to-high source order.
      "src/config.ts": [
        'const apiSecret = "aB3xQ9zK2mN7pL5wR8tY4vU6sD1fG0hJ2kM8nQ4r";',
        `const stripeKey = "${STRIPE_KEY}";`,
      ].join("\n"),
    });

    const findings = await runDetectors(ctx);

    expect(findings.length).toBeGreaterThanOrEqual(2);
    expect(findings[0]?.severity).toBe("CRITICAL");
    const ranks = findings.map((f) => f.severity);
    const criticalIndex = ranks.indexOf("CRITICAL");
    const highIndex = ranks.indexOf("HIGH");
    if (highIndex !== -1) {
      expect(criticalIndex).toBeLessThan(highIndex);
    }
  });
});

describe("matchesGlob", () => {
  it("'**/*.ts' matches a nested .ts file", () => {
    expect(matchesGlob("src/a/b.ts", ["**/*.ts"])).toBe(true);
  });

  it("'**/*.ts' matches a root-level .ts file (zero leading segments)", () => {
    expect(matchesGlob("a.ts", ["**/*.ts"])).toBe(true);
  });

  it("'**/*.ts' does not match a .js file", () => {
    expect(matchesGlob("src/a.js", ["**/*.ts"])).toBe(false);
  });

  it("supports '{a,b}' brace alternation", () => {
    expect(matchesGlob("a.ts", ["*.{ts,tsx}"])).toBe(true);
    expect(matchesGlob("a.tsx", ["*.{ts,tsx}"])).toBe(true);
    expect(matchesGlob("a.js", ["*.{ts,tsx}"])).toBe(false);
  });

  it("a single '*' does not cross a path separator", () => {
    expect(matchesGlob("a.ts", ["*.ts"])).toBe(true);
    expect(matchesGlob("src/a.ts", ["*.ts"])).toBe(false);
  });

  it("matches '**/.env*' against a nested dotenv-style file", () => {
    expect(matchesGlob("nested/.env.local", ["**/.env*"])).toBe(true);
    expect(matchesGlob(".env", ["**/.env*"])).toBe(true);
  });

  it("returns false when no glob in the list matches", () => {
    expect(matchesGlob("image.png", ["**/*.ts", "**/*.js"])).toBe(false);
  });
});

describe("runDetectors — inline immunogen-ignore suppression", () => {
  const flagEveryLine: Detector = {
    config: { name: "every-line", category: "secrets", globs: ["**/*"] },
    detect(ctx) {
      return Promise.resolve(
        ctx.content.split("\n").map((_, index) => ({
          ruleId: index % 2 === 0 ? "SEC-06" : "AUTH-01",
          category: "secrets" as const,
          detectorName: "every-line",
          file: ctx.filePath,
          line: index + 1,
          severity: "HIGH" as const,
          confidence: "HIGH" as const,
          message: "m",
          remediation: "r",
        })),
      );
    },
  };

  function makeScanContext(content: string, noIgnore = false): ScanContext {
    return {
      rootPath: "/repo",
      fileSet: new Map([["src/a.ts", content]]),
      astCache: new Map(),
      stackHints: {
        frameworks: new Set(),
        hasSupabase: false,
        hasFirebase: false,
        hasStripe: false,
        hasEnvFiles: false,
        hasMcpJson: false,
        hasClaudeSkills: false,
        hasCursorRules: false,
      },
      options: noIgnore ? { noIgnore: true } : {},
      diagnostics: [],
    };
  }

  it("suppresses findings on the marker's own line and the line below it", async () => {
    const content = ["a // immunogen-ignore", "b", "c", "d"].join("\n");

    const findings = await runDetectors(makeScanContext(content), [flagEveryLine]);

    expect(findings.map((finding) => finding.line).sort()).toEqual([3, 4]);
  });

  it("only suppresses the listed rule ids when ids are given", async () => {
    const content = ["// immunogen-ignore AUTH-01", "x", "// immunogen-ignore SEC-06, AUTH-01", "y"].join("\n");

    const findings = await runDetectors(makeScanContext(content), [flagEveryLine]);

    // line 1 (SEC-06) is not listed on its own marker; line 2 (AUTH-01) is
    // covered by the marker above; lines 3-4 are covered by both ids.
    expect(findings.map((finding) => `${finding.ruleId}@${String(finding.line)}`)).toEqual(["SEC-06@1"]);
  });

  it("keeps everything with noIgnore", async () => {
    const content = ["a // immunogen-ignore", "b"].join("\n");

    expect(await runDetectors(makeScanContext(content, true), [flagEveryLine])).toHaveLength(2);
  });
});

import { describe, expect, it } from "vitest";

import { mcpLeastPrivilegeDetector } from "./mcp-least-privilege-detector.js";

import type { DetectorContext, StackHints } from "../../core/types.js";

/** Benign StackHints literal — this detector reads no stack hints. */
const BENIGN_STACK_HINTS: StackHints = {
  frameworks: new Set(),
  hasSupabase: false,
  hasFirebase: false,
  hasStripe: false,
  hasEnvFiles: false,
  hasMcpJson: true,
  hasClaudeSkills: false,
  hasCursorRules: false,
};

/** Builds a DetectorContext literal for `content` at the given `filePath`, without the ingestion layer. */
function makeContext(content: string, filePath: string): DetectorContext {
  return {
    filePath,
    content,
    stackHints: BENIGN_STACK_HINTS,
    fileSet: new Map(),
  };
}

describe("mcpLeastPrivilegeDetector — vulnerable cases", () => {
  it("flags a server with shell/network-capable tools and no permissions field as AILAYER-04 MEDIUM/MEDIUM", async () => {
    const json = JSON.stringify(
      {
        mcpServers: {
          fetcher: {
            command: "npx",
            args: ["mcp-fetch-server"],
            tools: [
              {
                name: "fetch_url",
                description: "Fetches a URL via https:// and returns the response body.",
              },
            ],
          },
        },
      },
      null,
      2,
    );
    const ctx = makeContext(json, ".mcp.json");

    const findings = await mcpLeastPrivilegeDetector.detect(ctx);

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      ruleId: "AILAYER-04",
      category: "ai-layer",
      detectorName: "mcp-least-privilege",
      severity: "MEDIUM",
      confidence: "MEDIUM",
      file: ".mcp.json",
    });
    expect(findings[0]?.line).toBeGreaterThan(0);
    expect(findings[0]?.message).toContain("permissions");
  });

  it("flags a server with wildcard permissions (\"*\") as AILAYER-04 MEDIUM/MEDIUM", async () => {
    const json = JSON.stringify({
      mcpServers: {
        fetcher: {
          command: "npx",
          permissions: ["*"],
          tools: [{ name: "fetch_url", description: "Fetches a URL." }],
        },
      },
    });
    const ctx = makeContext(json, ".mcp.json");

    const findings = await mcpLeastPrivilegeDetector.detect(ctx);

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      ruleId: "AILAYER-04",
      severity: "MEDIUM",
      confidence: "MEDIUM",
    });
    expect(findings[0]?.message.toLowerCase()).toContain("wildcard");
  });

  it("flags a server with wildcard permissions declared as \"all\" (case-insensitive)", async () => {
    const json = JSON.stringify({
      mcpServers: {
        fetcher: { permissions: ["ALL"], tools: [{ name: "fetch_url" }] },
      },
    });
    const ctx = makeContext(json, ".mcp.json");

    const findings = await mcpLeastPrivilegeDetector.detect(ctx);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.ruleId).toBe("AILAYER-04");
  });

  it("never escalates beyond MEDIUM regardless of which capability category triggers", async () => {
    const json = JSON.stringify({
      mcpServers: {
        shellServer: {
          command: "bash",
          tools: [{ name: "run_shell", description: "Executes a shell command via exec." }],
        },
      },
    });
    const ctx = makeContext(json, ".mcp.json");

    const findings = await mcpLeastPrivilegeDetector.detect(ctx);

    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings.every((f) => f.severity === "MEDIUM")).toBe(true);
    expect(findings.every((f) => f.confidence === "MEDIUM")).toBe(true);
  });
});

describe("mcpLeastPrivilegeDetector — clean cases (zero-FP)", () => {
  it("does NOT flag a server with an explicit, non-wildcard permissions list", async () => {
    const json = JSON.stringify({
      mcpServers: {
        fetcher: {
          permissions: ["file_read"],
          tools: [{ name: "fetch_url", description: "Fetches a URL." }],
        },
      },
    });
    const ctx = makeContext(json, ".mcp.json");

    const findings = await mcpLeastPrivilegeDetector.detect(ctx);

    expect(findings).toEqual([]);
  });

  it("does NOT flag a docs-only server with no capabilities and no permissions", async () => {
    const json = JSON.stringify({
      mcpServers: {
        docs: {
          tools: [
            {
              name: "search_docs",
              description: "Searches the local documentation index.",
            },
          ],
        },
      },
    });
    const ctx = makeContext(json, ".mcp.json");

    const findings = await mcpLeastPrivilegeDetector.detect(ctx);

    expect(findings).toEqual([]);
  });

  it("does NOT flag a vulnerable .mcp.json under a fixtures/ path (FP allowlist guard)", async () => {
    const json = JSON.stringify({
      mcpServers: {
        fetcher: {
          command: "npx",
          tools: [{ name: "fetch_url", description: "Fetches a URL via https://" }],
        },
      },
    });
    const ctx = makeContext(json, "fixtures/vulnerable-mcp/.mcp.json");

    const findings = await mcpLeastPrivilegeDetector.detect(ctx);

    expect(findings).toEqual([]);
  });
});

describe("mcpLeastPrivilegeDetector — no-throw contract", () => {
  it("resolves to [] for malformed JSON (never throws)", async () => {
    const ctx = makeContext("{ broken", ".mcp.json");

    const findings = await mcpLeastPrivilegeDetector.detect(ctx);

    expect(findings).toEqual([]);
  });

  it("resolves to [] for empty content", async () => {
    const ctx = makeContext("", ".mcp.json");

    const findings = await mcpLeastPrivilegeDetector.detect(ctx);

    expect(findings).toEqual([]);
  });

  it("resolves to [] for a JSON shape with no recognizable server structure (unknown shape)", async () => {
    const ctx = makeContext(JSON.stringify({ unrelatedField: "hello" }), ".mcp.json");

    const findings = await mcpLeastPrivilegeDetector.detect(ctx);

    expect(findings).toEqual([]);
  });
});

describe("mcpLeastPrivilegeDetector — config", () => {
  it("declares name 'mcp-least-privilege' and category 'ai-layer'", () => {
    expect(mcpLeastPrivilegeDetector.config.name).toBe("mcp-least-privilege");
    expect(mcpLeastPrivilegeDetector.config.category).toBe("ai-layer");
  });

  it("declares globs covering .mcp.json and .cursor/mcp.json", () => {
    const globs = mcpLeastPrivilegeDetector.config.globs;
    expect(globs.some((glob) => glob.includes(".mcp.json"))).toBe(true);
    expect(globs.some((glob) => glob.includes(".cursor/mcp.json"))).toBe(true);
  });
});

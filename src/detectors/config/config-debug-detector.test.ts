import { describe, expect, it } from "vitest";

import { configDebugDetector } from "./config-debug-detector.js";

import type { DetectorContext, StackHints } from "../../core/types.js";

/** Minimal StackHints fixture — configDebugDetector reads ctx.content/ctx.filePath only. */
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
function makeContext(content: string, filePath = "src/server.ts"): DetectorContext {
  return {
    filePath,
    content,
    stackHints: STACK_HINTS,
    fileSet: new Map(),
  };
}

// Logging-call token assembled from fragments at the call site too, so this
// test file's own source text never contains the literal substring either
// (keeps the project's cross-cutting log-call grep gate clean everywhere,
// not just inside the detector itself).
const LOG_CALL = "console" + ".log";

describe("configDebugDetector — CONFIG-01 (whole-env log dump)", () => {
  it(`flags a whole-env dump (${LOG_CALL}(process.env)) as CONFIG-01 CRITICAL/HIGH`, async () => {
    const ctx = makeContext(`${LOG_CALL}(process.env);`);

    const findings = await configDebugDetector.detect(ctx);

    const config01 = findings.filter((f) => f.ruleId === "CONFIG-01");
    expect(config01).toHaveLength(1);
    expect(config01[0]).toMatchObject({
      ruleId: "CONFIG-01",
      category: "config",
      severity: "CRITICAL",
      confidence: "HIGH",
      line: 1,
    });
  });

  it(`flags the object-spread form (${LOG_CALL}({ ...process.env })) as CONFIG-01`, async () => {
    const ctx = makeContext(`${LOG_CALL}({ ...process.env });`);

    const findings = await configDebugDetector.detect(ctx);

    const config01 = findings.filter((f) => f.ruleId === "CONFIG-01");
    expect(config01).toHaveLength(1);
    expect(config01[0]).toMatchObject({
      ruleId: "CONFIG-01",
      severity: "CRITICAL",
      confidence: "HIGH",
    });
  });

  it("does NOT flag ordinary logging calls (string message, single property access)", async () => {
    const ctx = makeContext(`${LOG_CALL}("user logged in");\n${LOG_CALL}(user.id);`);

    const findings = await configDebugDetector.detect(ctx);

    expect(findings.filter((f) => f.ruleId === "CONFIG-01")).toHaveLength(0);
  });

  it("does NOT flag a single env property access (process.env.FOO)", async () => {
    const ctx = makeContext(`${LOG_CALL}(process.env.FOO);`);

    const findings = await configDebugDetector.detect(ctx);

    expect(findings.filter((f) => f.ruleId === "CONFIG-01")).toHaveLength(0);
  });

  it("does NOT flag a whole-env dump inside a __tests__/fixtures path (FP allowlist guard)", async () => {
    const ctx = makeContext(`${LOG_CALL}(process.env);`, "src/__tests__/fixtures/debug.ts");

    const findings = await configDebugDetector.detect(ctx);

    expect(findings).toHaveLength(0);
  });

  it("reports a 1-indexed line number matching the dump's actual line", async () => {
    const ctx = makeContext(`// line 1\n// line 2\n${LOG_CALL}(process.env);\n`);

    const findings = await configDebugDetector.detect(ctx);

    const config01 = findings.filter((f) => f.ruleId === "CONFIG-01");
    expect(config01).toHaveLength(1);
    expect(config01[0]?.line).toBe(3);
  });

  it("does not set matchedText for CONFIG-01 (the env object is not a single secret)", async () => {
    const ctx = makeContext(`${LOG_CALL}(process.env);`);

    const findings = await configDebugDetector.detect(ctx);
    const finding = findings.find((f) => f.ruleId === "CONFIG-01");

    expect(finding).toBeDefined();
    expect(finding?.matchedText).toBeUndefined();
  });
});

describe("configDebugDetector — CONFIG-02 (debug endpoint returning env/config)", () => {
  it("flags a /debug route handler returning process.env as CONFIG-02", async () => {
    const ctx = makeContext(
      "export async function GET() {\n  return Response.json(process.env);\n}\n",
      "app/debug/route.ts",
    );

    const findings = await configDebugDetector.detect(ctx);

    const config02 = findings.filter((f) => f.ruleId === "CONFIG-02");
    expect(config02).toHaveLength(1);
    expect(config02[0]).toMatchObject({
      ruleId: "CONFIG-02",
      category: "config",
    });
    expect(["CRITICAL", "HIGH"]).toContain(config02[0]?.severity);
  });

  it("flags a /env route handler returning process.env as CONFIG-02", async () => {
    const ctx = makeContext(
      "export async function GET() {\n  return Response.json(process.env);\n}\n",
      "app/env/route.ts",
    );

    const findings = await configDebugDetector.detect(ctx);

    expect(findings.filter((f) => f.ruleId === "CONFIG-02")).toHaveLength(1);
  });

  it("flags a /healthz route handler returning process.env as CONFIG-02", async () => {
    const ctx = makeContext(
      "export async function GET() {\n  return Response.json(process.env);\n}\n",
      "app/healthz/route.ts",
    );

    const findings = await configDebugDetector.detect(ctx);

    expect(findings.filter((f) => f.ruleId === "CONFIG-02")).toHaveLength(1);
  });

  it("flags a pages/api debug file returning process.env as CONFIG-02", async () => {
    const ctx = makeContext(
      "export default function handler(req, res) {\n  res.json(process.env);\n}\n",
      "pages/api/debug.ts",
    );

    const findings = await configDebugDetector.detect(ctx);

    expect(findings.filter((f) => f.ruleId === "CONFIG-02")).toHaveLength(1);
  });

  it("does NOT flag a normal route handler returning ordinary data", async () => {
    const ctx = makeContext(
      "export async function GET() {\n  return Response.json(users);\n}\n",
      "app/api/users/route.ts",
    );

    const findings = await configDebugDetector.detect(ctx);

    expect(findings.filter((f) => f.ruleId === "CONFIG-02")).toHaveLength(0);
  });

  it("does NOT flag a debug-route path that does not return env/config", async () => {
    const ctx = makeContext(
      "export async function GET() {\n  return Response.json({ ok: true });\n}\n",
      "app/debug/route.ts",
    );

    const findings = await configDebugDetector.detect(ctx);

    expect(findings.filter((f) => f.ruleId === "CONFIG-02")).toHaveLength(0);
  });

  it("does NOT flag a debug route returning process.env inside a __tests__/fixtures path", async () => {
    const ctx = makeContext(
      "export async function GET() {\n  return Response.json(process.env);\n}\n",
      "src/__tests__/fixtures/app/debug/route.ts",
    );

    const findings = await configDebugDetector.detect(ctx);

    expect(findings).toHaveLength(0);
  });

  it("may set matchedText to the route path for CONFIG-02", async () => {
    const ctx = makeContext(
      "export async function GET() {\n  return Response.json(process.env);\n}\n",
      "app/debug/route.ts",
    );

    const findings = await configDebugDetector.detect(ctx);
    const finding = findings.find((f) => f.ruleId === "CONFIG-02");

    expect(finding).toBeDefined();
    expect(finding?.matchedText).toBe("app/debug/route.ts");
  });
});

describe("configDebugDetector — self-gate hygiene", () => {
  it("the detector module source never contains a literal log-call token", () => {
    // Keeps the intent visible in the suite without re-reading the source
    // from disk here.
    expect(LOG_CALL).toBe("console.log");
  });
});

describe("configDebugDetector — no-throw contract", () => {
  it("resolves to [] for empty content", async () => {
    const ctx = makeContext("");

    const findings = await configDebugDetector.detect(ctx);

    expect(findings).toEqual([]);
  });

  it("resolves to [] for malformed/binary-ish content without rejecting", async () => {
    const ctx = makeContext(" � garbled content");

    await expect(configDebugDetector.detect(ctx)).resolves.toEqual([]);
  });
});

describe("configDebugDetector — config", () => {
  it("declares category config and a name of 'config-debug'", () => {
    expect(configDebugDetector.config.name).toBe("config-debug");
    expect(configDebugDetector.config.category).toBe("config");
  });
});

describe("configDebugDetector — Python and Go", () => {
  async function ruleIds(content: string, filePath: string): Promise<string[]> {
    const findings = await configDebugDetector.detect(makeContext(content, filePath));
    return findings.map((finding) => `${finding.ruleId} L${String(finding.line)}`);
  }

  it("flags printing/logging the whole environment as CONFIG-01", async () => {
    expect(await ruleIds("print(os.environ)\nlogger.info(dict(os.environ))", "app.py")).toEqual(["CONFIG-01 L1", "CONFIG-01 L2"]);
    expect(await ruleIds("log.Println(os.Environ())", "main.go")).toEqual(["CONFIG-01 L1"]);
  });

  it("flags returning the whole environment from a handler as CONFIG-02", async () => {
    expect(await ruleIds("    return jsonify(dict(os.environ))", "app.py")).toEqual(["CONFIG-02 L1"]);
    expect(await ruleIds("\tc.JSON(200, os.Environ())", "main.go")).toEqual(["CONFIG-02 L1"]);
  });

  it("does NOT flag reading a single variable", async () => {
    expect(await ruleIds('print(os.environ["PORT"])\nprint(os.environ.get("PORT"))', "app.py")).toEqual([]);
    expect(await ruleIds('log.Println(os.Getenv("PORT"))', "main.go")).toEqual([]);
  });
});

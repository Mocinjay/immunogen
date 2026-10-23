import { describe, expect, it } from "vitest";

import { corsDetector } from "./cors-detector.js";

import type { DetectorContext, StackHints } from "../../core/types.js";

/** Minimal StackHints fixture — corsDetector reads ctx.content only, never ctx.stackHints. */
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
function makeContext(content: string, filePath = "src/api/route.ts"): DetectorContext {
  return {
    filePath,
    content,
    stackHints: STACK_HINTS,
    fileSet: new Map(),
  };
}

describe("corsDetector — CORS-01 (wildcard origin + credentials)", () => {
  it("flags the forbidden combination (wildcard origin + credentials true) as CRITICAL/HIGH at the wildcard-origin line", async () => {
    const ctx = makeContext(
      [
        "// line 1",
        "res.setHeader('Access-Control-Allow-Origin', '*');",
        "res.setHeader('Access-Control-Allow-Credentials', 'true');",
      ].join("\n"),
    );

    const findings = await corsDetector.detect(ctx);

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      ruleId: "CORS-01",
      category: "cors-headers",
      severity: "CRITICAL",
      confidence: "HIGH",
      file: "src/api/route.ts",
      line: 2,
    });
  });

  it("does NOT flag a wildcard origin with no credentials header (the FP guard — legitimate public API)", async () => {
    const ctx = makeContext("res.setHeader('Access-Control-Allow-Origin', '*');");

    const findings = await corsDetector.detect(ctx);

    expect(findings).toHaveLength(0);
  });

  it("does NOT flag credentials true combined with a specific (non-wildcard) origin", async () => {
    const ctx = makeContext(
      [
        "res.setHeader('Access-Control-Allow-Origin', 'https://app.example.com');",
        "res.setHeader('Access-Control-Allow-Credentials', 'true');",
      ].join("\n"),
    );

    const findings = await corsDetector.detect(ctx);

    expect(findings).toHaveLength(0);
  });

  it("does NOT flag the forbidden combination inside a __tests__/fixtures path (FP allowlist guard)", async () => {
    const ctx = makeContext(
      [
        "res.setHeader('Access-Control-Allow-Origin', '*');",
        "res.setHeader('Access-Control-Allow-Credentials', 'true');",
      ].join("\n"),
      "src/__tests__/fixtures/cors-config.ts",
    );

    const findings = await corsDetector.detect(ctx);

    expect(findings).toHaveLength(0);
  });

  it("matches any quote style (double quotes) and any line order (credentials before origin)", async () => {
    const ctx = makeContext(
      [
        'res.setHeader("Access-Control-Allow-Credentials", "true");',
        'res.setHeader("Access-Control-Allow-Origin", "*");',
      ].join("\n"),
    );

    const findings = await corsDetector.detect(ctx);

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      ruleId: "CORS-01",
      severity: "CRITICAL",
      confidence: "HIGH",
      line: 2,
    });
  });

  it("matches header names case-insensitively", async () => {
    const ctx = makeContext(
      [
        "headers['access-control-allow-origin'] = '*';",
        "headers['access-control-allow-credentials'] = 'true';",
      ].join("\n"),
    );

    const findings = await corsDetector.detect(ctx);

    expect(findings).toHaveLength(1);
  });
});

describe("corsDetector — no-throw contract", () => {
  it("resolves to [] for empty content", async () => {
    const ctx = makeContext("");

    const findings = await corsDetector.detect(ctx);

    expect(findings).toEqual([]);
  });

  it("resolves to [] for malformed/binary-ish content without rejecting", async () => {
    const ctx = makeContext(" � garbled content");

    await expect(corsDetector.detect(ctx)).resolves.toEqual([]);
  });
});

describe("corsDetector — config", () => {
  it("declares category cors-headers and a name of 'cors'", () => {
    expect(corsDetector.config.name).toBe("cors");
    expect(corsDetector.config.category).toBe("cors-headers");
  });

  it("declares text-targetable globs covering common config/source extensions", () => {
    expect(corsDetector.config.globs.some((glob) => glob.includes("ts"))).toBe(true);
  });
});

describe("corsDetector — CORS-02 credentials for any (reflected) origin", () => {
  async function summarize(content: string): Promise<string[]> {
    const findings = await corsDetector.detect(makeContext(content));
    return findings.map((finding) => `${finding.ruleId} ${finding.severity} L${String(finding.line)}`);
  }

  it("flags cors({ origin: true, credentials: true }) across lines", async () => {
    const content = ["const app = express();", "app.use(cors({", "  origin: true,", "  credentials: true,", "}));"].join("\n");

    expect(await summarize(content)).toEqual(["CORS-02 CRITICAL L2"]);
  });

  it("flags cors({ origin: '*', credentials: true })", async () => {
    expect(await summarize("app.use(cors({ origin: '*', credentials: true }));")).toEqual(["CORS-02 CRITICAL L1"]);
  });

  it("flags an Allow-Origin header copied from the request with credentials", async () => {
    const content = [
      "res.setHeader('Access-Control-Allow-Origin', req.headers.origin);",
      "res.setHeader('Access-Control-Allow-Credentials', 'true');",
    ].join("\n");

    expect(await summarize(content)).toEqual(["CORS-02 CRITICAL L1"]);
  });

  it("does NOT flag an allowlisted origin, or any-origin without credentials", async () => {
    expect(await summarize("app.use(cors({ origin: ['https://app.example.com'], credentials: true }));")).toEqual([]);
    expect(await summarize("app.use(cors({ origin: true }));")).toEqual([]);
    expect(await summarize("res.setHeader('Access-Control-Allow-Origin', req.headers.origin);")).toEqual([]);
  });
});

describe("corsDetector — Python and Go CORS-02", () => {
  async function ruleIds(content: string, filePath: string): Promise<string[]> {
    const findings = await corsDetector.detect(makeContext(content, filePath));
    return findings.map((finding) => `${finding.ruleId} L${String(finding.line)}`);
  }

  it("flags FastAPI CORSMiddleware with allow_origins=['*'] and allow_credentials=True", async () => {
    const content = [
      "app.add_middleware(",
      "    CORSMiddleware,",
      '    allow_origins=["*"],',
      "    allow_credentials=True,",
      ")",
    ].join("\n");

    expect(await ruleIds(content, "main.py")).toEqual(["CORS-02 L3"]);
  });

  it("flags flask-cors with supports_credentials and no origin restriction", async () => {
    expect(await ruleIds("CORS(app, supports_credentials=True)", "app.py")).toEqual(["CORS-02 L1"]);
    expect(await ruleIds('CORS(app, origins="https://app.example.com", supports_credentials=True)', "app.py")).toEqual([]);
  });

  it("flags Go rs/cors and gin-contrib/cors any-origin + credentials", async () => {
    const rsCors = 'c := cors.New(cors.Options{\n\tAllowedOrigins: []string{"*"},\n\tAllowCredentials: true,\n})';
    const gin = "r.Use(cors.New(cors.Config{\n\tAllowAllOrigins: true,\n\tAllowCredentials: true,\n}))";

    expect(await ruleIds(rsCors, "main.go")).toEqual(["CORS-02 L2"]);
    expect(await ruleIds(gin, "server/main.go")).toEqual(["CORS-02 L2"]);
  });

  it("does NOT flag any-origin without credentials", async () => {
    expect(await ruleIds('app.add_middleware(CORSMiddleware, allow_origins=["*"])', "main.py")).toEqual([]);
    expect(await ruleIds('cors.Options{AllowedOrigins: []string{"*"}}', "main.go")).toEqual([]);
  });
});

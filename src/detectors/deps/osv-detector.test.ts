import { afterEach, describe, expect, it, vi } from "vitest";

import { osvDetector } from "./osv-detector.js";

import type { DetectorContext, StackHints } from "../../core/types.js";
import type { OsvResult } from "./osv-client.js";

// queryOsvBatch is mocked at the module boundary so this test suite NEVER
// performs a real network call (tests are offline and deterministic;
// queryOsvBatch lives in its own module so it can be stubbed).
const queryOsvBatchMock = vi.fn<(queries: Array<{ name: string; version: string }>) => Promise<OsvResult[]>>();

const fetchVulnSeveritiesMock = vi.fn<(ids: string[]) => Promise<Map<string, string>>>(() => Promise.resolve(new Map()));

vi.mock("./osv-client.js", () => ({
  queryOsvBatch: (queries: Array<{ name: string; version: string }>) => queryOsvBatchMock(queries),
  fetchVulnSeverities: (ids: string[]) => fetchVulnSeveritiesMock(ids),
}));

/** Minimal StackHints fixture — osvDetector reads ctx.content only, never ctx.stackHints. */
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

/** Builds a DetectorContext literal for a package.json's `content`, without the ingestion layer. */
function makeContext(content: string, filePath = "package.json"): DetectorContext {
  return {
    filePath,
    content,
    stackHints: STACK_HINTS,
    fileSet: new Map(),
  };
}

const VULNERABLE_PACKAGE_JSON = JSON.stringify(
  {
    name: "fixture-app",
    version: "1.0.0",
    dependencies: {
      lodash: "4.17.20",
    },
  },
  null,
  2,
);

const CLEAN_PACKAGE_JSON = JSON.stringify(
  {
    name: "fixture-app",
    version: "1.0.0",
    dependencies: {
      lodash: "4.17.21",
      axios: "1.7.0",
    },
  },
  null,
  2,
);

afterEach(() => {
  queryOsvBatchMock.mockReset();
});

describe("osvDetector — vulnerable via fallback path (OSV stubbed to fail)", () => {
  it("emits a DEP-01 finding for lodash AND exactly one DEP-OFFLINE sentinel", async () => {
    queryOsvBatchMock.mockRejectedValue(new Error("network unavailable"));
    const ctx = makeContext(VULNERABLE_PACKAGE_JSON);

    const findings = await osvDetector.detect(ctx);

    const depFindings = findings.filter((finding) => finding.ruleId === "DEP-01");
    expect(depFindings.length).toBeGreaterThanOrEqual(1);
    expect(depFindings.some((finding) => finding.message.includes("lodash"))).toBe(true);
    expect(depFindings[0]).toMatchObject({ category: "deps" });

    const offlineFindings = findings.filter((finding) => finding.ruleId === "DEP-OFFLINE");
    expect(offlineFindings).toHaveLength(1);
    expect(offlineFindings[0]).toMatchObject({ category: "deps", severity: "INFO" });
  });
});

describe("osvDetector — vulnerable via OSV path (network succeeds)", () => {
  it("emits a DEP-01 finding carrying the OSV vuln id, with NO DEP-OFFLINE sentinel", async () => {
    queryOsvBatchMock.mockResolvedValue([{ vulns: [{ id: "GHSA-osv-test-1234" }] }]);
    const ctx = makeContext(JSON.stringify({ dependencies: { "some-pkg": "1.0.0" } }));

    const findings = await osvDetector.detect(ctx);

    const depFindings = findings.filter((finding) => finding.ruleId === "DEP-01");
    expect(depFindings).toHaveLength(1);
    expect(depFindings[0]?.message).toContain("GHSA-osv-test-1234");

    const offlineFindings = findings.filter((finding) => finding.ruleId === "DEP-OFFLINE");
    expect(offlineFindings).toHaveLength(0);
  });
});

describe("osvDetector — clean, online", () => {
  it("returns zero DEP-01 and zero DEP-OFFLINE findings when OSV reports no vulns", async () => {
    queryOsvBatchMock.mockResolvedValue([{ vulns: [] }, { vulns: [] }]);
    const ctx = makeContext(CLEAN_PACKAGE_JSON);

    const findings = await osvDetector.detect(ctx);

    expect(findings.filter((finding) => finding.ruleId === "DEP-01")).toHaveLength(0);
    expect(findings.filter((finding) => finding.ruleId === "DEP-OFFLINE")).toHaveLength(0);
  });
});

describe("osvDetector — offline degradation is VISIBLE, never silent", () => {
  it("with clean deps and OSV timing out, returns zero vuln findings but exactly one DEP-OFFLINE sentinel", async () => {
    queryOsvBatchMock.mockRejectedValue(new Error("timeout"));
    const ctx = makeContext(CLEAN_PACKAGE_JSON);

    const findings = await osvDetector.detect(ctx);

    expect(findings.filter((finding) => finding.ruleId === "DEP-01")).toHaveLength(0);
    const offlineFindings = findings.filter((finding) => finding.ruleId === "DEP-OFFLINE");
    expect(offlineFindings).toHaveLength(1);
    expect(offlineFindings[0]).toMatchObject({
      ruleId: "DEP-OFFLINE",
      category: "deps",
      severity: "INFO",
    });
    expect(offlineFindings[0]?.message.toLowerCase()).toContain("offline");
  });
});

describe("osvDetector — privacy (only name/version/ecosystem ever sent to OSV)", () => {
  it("the request payload built for OSV contains ONLY name + version + ecosystem (queryOsvBatch's own argument), never other package.json fields", async () => {
    queryOsvBatchMock.mockResolvedValue([{ vulns: [] }]);
    const packageJsonWithExtraFields = JSON.stringify({
      name: "fixture-app",
      author: "someone@example.com",
      scripts: { build: "do-the-thing --secret=abc123" },
      dependencies: { "some-pkg": "1.0.0" },
    });
    const ctx = makeContext(packageJsonWithExtraFields);

    await osvDetector.detect(ctx);

    expect(queryOsvBatchMock).toHaveBeenCalledTimes(1);
    const calledWith = queryOsvBatchMock.mock.calls[0]?.[0];
    expect(calledWith).toBeDefined();
    const serialized = JSON.stringify(calledWith);
    expect(serialized).not.toContain("author");
    expect(serialized).not.toContain("someone@example.com");
    expect(serialized).not.toContain("scripts");
    expect(serialized).not.toContain("secret=abc123");
    // Every query entry exposes only name + version + ecosystem (no other package.json keys leak through).
    for (const query of calledWith ?? []) {
      expect(Object.keys(query).sort()).toEqual(["ecosystem", "name", "version"]);
    }
  });
});

describe("osvDetector — no-throw contract", () => {
  it("resolves to [] (or just DEP-OFFLINE) for a malformed package.json, never rejects", async () => {
    queryOsvBatchMock.mockResolvedValue([]);
    const ctx = makeContext("{ this is not valid json !!!");

    await expect(osvDetector.detect(ctx)).resolves.toBeInstanceOf(Array);
    const findings = await osvDetector.detect(ctx);
    expect(findings.filter((finding) => finding.ruleId === "DEP-01")).toHaveLength(0);
  });

  it("never rejects even when queryOsvBatch itself throws synchronously", async () => {
    queryOsvBatchMock.mockImplementation(() => {
      throw new Error("synchronous failure");
    });
    const ctx = makeContext(CLEAN_PACKAGE_JSON);

    await expect(osvDetector.detect(ctx)).resolves.toBeInstanceOf(Array);
  });
});

describe("osvDetector — config", () => {
  it("declares category deps, name osv, requiresNetwork true, and globs package.json", () => {
    expect(osvDetector.config.name).toBe("osv");
    expect(osvDetector.config.category).toBe("deps");
    expect(osvDetector.config.requiresNetwork).toBe(true);
    expect(osvDetector.config.globs).toContain("package.json");
  });
});

describe("osvDetector — nested manifests and offline mode", () => {
  it("reports findings against the nested package.json path it actually read", async () => {
    queryOsvBatchMock.mockResolvedValue([{ vulns: [{ id: "GHSA-nested-0001" }] }]);

    const findings = await osvDetector.detect(
      makeContext(JSON.stringify({ dependencies: { next: "14.0.0" } }, null, 2), "apps/web/package.json"),
    );

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ ruleId: "DEP-01", file: "apps/web/package.json" });
  });

  it("skips package.json files under node_modules or fixture/test directories", async () => {
    const content = JSON.stringify({ dependencies: { next: "14.0.0" } });

    for (const filePath of [
      "node_modules/next/package.json",
      "tests/fixtures/app/package.json",
      "src/__tests__/package.json",
      "examples/demo/package.json",
      "not-a-package.json",
    ]) {
      expect(await osvDetector.detect(makeContext(content, filePath))).toEqual([]);
    }
    expect(queryOsvBatchMock).not.toHaveBeenCalled();
  });

  it("never calls OSV in offline mode and still emits the DEP-OFFLINE sentinel", async () => {
    const ctx = { ...makeContext(JSON.stringify({ dependencies: { lodash: "4.17.15" } })), offline: true };

    const findings = await osvDetector.detect(ctx);

    expect(queryOsvBatchMock).not.toHaveBeenCalled();
    expect(findings.map((finding) => finding.ruleId)).toEqual(["DEP-01", "DEP-OFFLINE"]);
  });
});

describe("osvDetector — one finding per vulnerable package", () => {
  it("groups every advisory for a package into a single DEP-01 finding", async () => {
    queryOsvBatchMock.mockResolvedValue([
      { vulns: [{ id: "GHSA-a" }, { id: "GHSA-b" }, { id: "GHSA-c" }, { id: "GHSA-d" }, { id: "GHSA-a" }] },
    ]);

    const findings = await osvDetector.detect(makeContext(JSON.stringify({ dependencies: { next: "14.0.0" } })));

    expect(findings).toHaveLength(1);
    expect(findings[0]?.message).toBe(
      "Vulnerable dependency: next@14.0.0 (4 OSV advisories: GHSA-a, GHSA-b, GHSA-c, +1 more).",
    );
  });
});

describe("osvDetector — Python and Go manifests", () => {
  it("queries PyPI for pinned requirements.txt entries and reports at the manifest line", async () => {
    queryOsvBatchMock.mockResolvedValue([{ vulns: [{ id: "PYSEC-2023-1" }] }, { vulns: [] }]);
    const content = "# deps\nFlask==2.0.1\nrequests>=2.0\nPyYAML==5.3\n";

    const findings = await osvDetector.detect(makeContext(content, "api/requirements.txt"));

    expect(queryOsvBatchMock.mock.calls[0]?.[0]).toEqual([
      { name: "flask", version: "2.0.1", ecosystem: "PyPI" },
      { name: "pyyaml", version: "5.3", ecosystem: "PyPI" },
    ]);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ ruleId: "DEP-01", file: "api/requirements.txt", line: 2 });
    expect(findings[0]?.message).toBe("Vulnerable dependency: flask@2.0.1 (OSV advisory PYSEC-2023-1).");
  });

  it("queries the Go ecosystem for go.mod requirements", async () => {
    queryOsvBatchMock.mockResolvedValue([{ vulns: [{ id: "GO-2023-1" }] }]);

    const findings = await osvDetector.detect(makeContext("module x\nrequire github.com/gin-gonic/gin v1.9.0\n", "go.mod"));

    expect(queryOsvBatchMock.mock.calls[0]?.[0]).toEqual([
      { name: "github.com/gin-gonic/gin", version: "1.9.0", ecosystem: "Go" },
    ]);
    expect(findings[0]?.remediation).toContain("ecosystem=Go");
  });

  it("emits the DEP-OFFLINE sentinel (no npm fallback list) when a Python manifest cannot be checked online", async () => {
    queryOsvBatchMock.mockRejectedValue(new Error("offline"));

    const findings = await osvDetector.detect(makeContext("flask==2.0.1\n", "requirements.txt"));

    expect(findings.map((finding) => finding.ruleId)).toEqual(["DEP-OFFLINE"]);
  });
});

describe("osvDetector — real advisory severity", () => {
  it("rates a package by its worst advisory and lists the worst first", async () => {
    queryOsvBatchMock.mockResolvedValue([{ vulns: [{ id: "GHSA-low" }, { id: "GHSA-crit" }, { id: "GHSA-mod" }] }]);
    fetchVulnSeveritiesMock.mockResolvedValueOnce(
      new Map([
        ["GHSA-low", "LOW"],
        ["GHSA-crit", "CRITICAL"],
        ["GHSA-mod", "MEDIUM"],
      ]),
    );

    const findings = await osvDetector.detect(makeContext(JSON.stringify({ dependencies: { next: "14.0.0" } })));

    expect(fetchVulnSeveritiesMock).toHaveBeenCalledWith(["GHSA-low", "GHSA-crit", "GHSA-mod"]);
    expect(findings[0]).toMatchObject({ severity: "CRITICAL" });
    expect(findings[0]?.message).toBe(
      "Vulnerable dependency: next@14.0.0 (3 OSV advisories, highest CRITICAL: GHSA-crit, GHSA-mod, GHSA-low).",
    );
  });

  it("can rate a package below HIGH when its advisories are minor", async () => {
    queryOsvBatchMock.mockResolvedValue([{ vulns: [{ id: "GHSA-only" }] }]);
    fetchVulnSeveritiesMock.mockResolvedValueOnce(new Map([["GHSA-only", "LOW"]]));

    const findings = await osvDetector.detect(makeContext(JSON.stringify({ dependencies: { pkg: "1.0.0" } })));

    expect(findings[0]).toMatchObject({ severity: "LOW", message: "Vulnerable dependency: pkg@1.0.0 (LOW OSV advisory GHSA-only)." });
  });

  it("keeps the HIGH default when the severity lookup fails", async () => {
    queryOsvBatchMock.mockResolvedValue([{ vulns: [{ id: "GHSA-x" }] }]);
    fetchVulnSeveritiesMock.mockRejectedValueOnce(new Error("network"));

    const findings = await osvDetector.detect(makeContext(JSON.stringify({ dependencies: { pkg: "1.0.0" } })));

    expect(findings.map((finding) => [finding.ruleId, finding.severity])).toEqual([["DEP-01", "HIGH"]]);
  });
});

describe("osvDetector — lockfiles", () => {
  const PACKAGE_JSON = JSON.stringify({ name: "app", dependencies: { lodash: "^4.17.0", debug: "^2.6.0" } }, null, 2);
  const LOCK = JSON.stringify(
    {
      lockfileVersion: 3,
      packages: {
        "": { name: "app" },
        "node_modules/lodash": { version: "4.17.15" },
        "node_modules/debug": { version: "2.6.8" },
        "node_modules/ms": { version: "2.0.0" },
      },
    },
    null,
    2,
  );

  function lockContext(filePath: string, files: Record<string, string>): DetectorContext {
    const fileSet = new Map(Object.entries(files));
    return { filePath, content: fileSet.get(filePath) ?? "", stackHints: STACK_HINTS, fileSet };
  }

  it("leaves package.json to its lockfile (no duplicate, no range guessing)", async () => {
    const findings = await osvDetector.detect(lockContext("package.json", { "package.json": PACKAGE_JSON, "package-lock.json": LOCK }));

    expect(findings).toEqual([]);
    expect(queryOsvBatchMock).not.toHaveBeenCalled();
  });

  it("queries every resolved version, pointing direct deps at package.json and transitive ones at the lockfile", async () => {
    queryOsvBatchMock.mockResolvedValue([{ vulns: [{ id: "GHSA-lodash" }] }, { vulns: [] }, { vulns: [{ id: "GHSA-ms" }] }]);

    const findings = await osvDetector.detect(lockContext("package-lock.json", { "package.json": PACKAGE_JSON, "package-lock.json": LOCK }));

    expect(queryOsvBatchMock.mock.calls[0]?.[0]).toEqual([
      { name: "lodash", version: "4.17.15", ecosystem: "npm" },
      { name: "debug", version: "2.6.8", ecosystem: "npm" },
      { name: "ms", version: "2.0.0", ecosystem: "npm" },
    ]);
    expect(findings.map((finding) => [finding.file, finding.line, finding.message])).toEqual([
      ["package.json", 4, "Vulnerable dependency: lodash@4.17.15 (OSV advisory GHSA-lodash)."],
      [
        "package-lock.json",
        13,
        "Vulnerable transitive dependency: ms@2.0.0 (OSV advisory GHSA-ms) — installed by another package, resolved in this lockfile.",
      ],
    ]);
    expect(findings[1]?.remediation).toContain("overrides");
  });

  it("lets a monorepo root lockfile govern a workspace package.json", async () => {
    const findings = await osvDetector.detect(
      lockContext("apps/web/package.json", { "apps/web/package.json": PACKAGE_JSON, "pnpm-lock.yaml": "lockfileVersion: '9.0'\n" }),
    );

    expect(findings).toEqual([]);
  });

  it("checks exact locked versions against the offline list and emits the sentinel when OSV is unreachable", async () => {
    queryOsvBatchMock.mockRejectedValue(new Error("offline"));

    const findings = await osvDetector.detect(lockContext("package-lock.json", { "package.json": PACKAGE_JSON, "package-lock.json": LOCK }));

    expect(findings.map((finding) => [finding.ruleId, finding.file])).toEqual([
      ["DEP-01", "package.json"],
      ["DEP-OFFLINE", "package-lock.json"],
    ]);
  });

  it("reads Python lockfiles next to pyproject.toml", async () => {
    queryOsvBatchMock.mockResolvedValue([{ vulns: [{ id: "PYSEC-1" }] }]);
    const files = {
      "pyproject.toml": '[tool.poetry.dependencies]\npython = "^3.11"\nflask = "^2.0"\n',
      "poetry.lock": '[[package]]\nname = "flask"\nversion = "2.0.1"\n',
    };

    expect(await osvDetector.detect(lockContext("pyproject.toml", files))).toEqual([]);
    const findings = await osvDetector.detect(lockContext("poetry.lock", files));

    expect(findings.map((finding) => [finding.file, finding.line, finding.message])).toEqual([
      ["pyproject.toml", 3, "Vulnerable dependency: flask@2.0.1 (OSV advisory PYSEC-1)."],
    ]);
  });
});

describe("osvDetector — npm specifiers are normalized before they reach OSV", () => {
  it("queries the lower bound of ranges, resolves npm: aliases, and skips non-registry specifiers", async () => {
    queryOsvBatchMock.mockImplementation((queries) => Promise.resolve(queries.map(() => ({}))));
    const content = JSON.stringify({
      dependencies: {
        a: "^1.2.3",
        b: ">=2.0.0 <3.0.0",
        c: "1.x",
        d: "~4",
        e: "npm:@scope/real@^5.1.0",
        f: "github:owner/repo",
        g: "owner/repo#main",
        h: "https://example.com/pkg.tgz",
        i: "next",
      },
    });

    await osvDetector.detect(makeContext(content));

    expect(queryOsvBatchMock.mock.calls[0]?.[0]).toEqual([
      { name: "a", version: "1.2.3", ecosystem: "npm" },
      { name: "b", version: "2.0.0", ecosystem: "npm" },
      { name: "c", version: "1.0.0", ecosystem: "npm" },
      { name: "d", version: "4.0.0", ecosystem: "npm" },
      { name: "@scope/real", version: "5.1.0", ecosystem: "npm" },
    ]);
  });
});

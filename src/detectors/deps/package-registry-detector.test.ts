import { afterEach, describe, expect, it, vi } from "vitest";

import { packageRegistryDetector } from "./package-registry-detector.js";

import type { DetectorContext } from "../../core/types.js";

afterEach(() => {
  vi.restoreAllMocks();
});

const HINTS = {
  frameworks: new Set<string>(),
  hasSupabase: false,
  hasFirebase: false,
  hasStripe: false,
  hasEnvFiles: false,
  hasMcpJson: false,
  hasClaudeSkills: false,
  hasCursorRules: false,
};

function context(filePath: string, files: Record<string, string>, offline = false): DetectorContext {
  const fileSet = new Map(Object.entries(files));
  return { filePath, content: fileSet.get(filePath) ?? "", stackHints: HINTS, fileSet, ...(offline ? { offline: true } : {}) };
}

/** A registry where only `known` names exist; records every URL asked. */
function registry(known: string[]) {
  const asked: string[] = [];
  vi.spyOn(globalThis, "fetch").mockImplementation((input) => {
    const url = input instanceof Request ? input.url : input.toString();
    asked.push(url);
    const hit = known.some((name) => url.endsWith(`/${name.replace("/", "%2f")}`) || url.includes(`/pypi/${name}/json`));
    return Promise.resolve(new Response(null, { status: hit ? 200 : 404 }));
  });
  return asked;
}

describe("packageRegistryDetector (DEP-02)", () => {
  it("flags a dependency the public npm registry has never heard of, at its manifest line", async () => {
    registry(["react", "zod"]);
    const manifest = JSON.stringify({ dependencies: { react: "18.3.1", "react-supabase-auth-helpers-pro": "^1.0.0" }, devDependencies: { zod: "3.23.8" } }, null, 2);

    const findings = await packageRegistryDetector.detect(context("package.json", { "package.json": manifest }));

    expect(findings.map((f) => `${f.ruleId} ${f.severity} ${f.matchedText ?? ""} L${String(f.line)}`)).toEqual([
      "DEP-02 HIGH react-supabase-auth-helpers-pro L4",
    ]);
  });

  it("skips workspace packages, non-registry specifiers and privately-scoped packages", async () => {
    const asked = registry([]);
    const files = {
      "package.json": JSON.stringify({
        dependencies: { "@acme/ui": "1.0.0", "shared-lib": "workspace:*", local: "file:../local", gh: "owner/repo", "@internal/thing": "^2.0.0" },
      }),
      "packages/internal/package.json": JSON.stringify({ name: "@internal/thing" }),
      ".npmrc": "@acme:registry=https://npm.acme.dev/\n",
    };

    expect(await packageRegistryDetector.detect(context("package.json", files))).toEqual([]);
    expect(asked).toEqual([]);
  });

  it("checks nothing when the repo points npm at a private default registry", async () => {
    const asked = registry([]);
    const files = { "package.json": JSON.stringify({ dependencies: { foo: "1.0.0" } }), ".npmrc": "registry=https://npm.corp.example/\n" };
    expect(await packageRegistryDetector.detect(context("package.json", files))).toEqual([]);
    expect(asked).toEqual([]);
  });

  it("flags a missing PyPI project, but not in a requirements file that names another index", async () => {
    registry(["requests"]);
    const plain = await packageRegistryDetector.detect(context("requirements.txt", { "requirements.txt": "requests==2.32.3\nfastapi-supabase-magic==0.1.0\n" }));
    const privateIndex = await packageRegistryDetector.detect(
      context("requirements.txt", { "requirements.txt": "--extra-index-url https://pypi.corp.example/simple\nfastapi-supabase-magic==0.1.0\n" }),
    );
    expect(plain.map((f) => f.matchedText)).toEqual(["fastapi-supabase-magic"]);
    expect(privateIndex).toEqual([]);
  });

  it("makes no request in offline mode and reports nothing when the registry is unreachable", async () => {
    const asked = registry([]);
    const files = { "package.json": JSON.stringify({ dependencies: { "made-up-pkg-xyz": "1.0.0" } }) };
    expect(await packageRegistryDetector.detect(context("package.json", files, true))).toEqual([]);
    expect(asked).toEqual([]);

    vi.restoreAllMocks();
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(null, { status: 418 }));
    expect(await packageRegistryDetector.detect(context("package.json", { "package.json": JSON.stringify({ dependencies: { "another-made-up-pkg": "1.0.0" } }) }))).toEqual([]);
  });
});

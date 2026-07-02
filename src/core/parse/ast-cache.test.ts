import { describe, expect, it } from "vitest";

import { buildAstCache } from "./ast-cache.js";
import { makeFileSet } from "../../../tests/helpers/make-file-set-ast.js";

describe("buildAstCache — valid TS/TSX/JSX parse success", () => {
  it("caches every JS/TS/JSX/TSX file and emits zero diagnostics", () => {
    const fileSet = makeFileSet({
      "a.ts": "const x: number = 1;",
      "b.tsx": [
        "export const C = () => <div>{1}</div>;",
        "const id = <T,>(v: T): T => v;",
      ].join("\n"),
      "c.jsx": "export const D = () => <span>hello</span>;",
    });

    const { astCache, diagnostics } = buildAstCache(fileSet);

    expect(astCache.has("a.ts")).toBe(true);
    expect(astCache.has("b.tsx")).toBe(true);
    expect(astCache.has("c.jsx")).toBe(true);
    expect(diagnostics.length).toBe(0);
  });

  it("produces a truthy object cache value without importing @babel/types", () => {
    const fileSet = makeFileSet({
      "a.ts": "const x: number = 1;",
    });

    const { astCache } = buildAstCache(fileSet);

    const value = astCache.get("a.ts");
    expect(value).toBeTruthy();
    expect(typeof value).toBe("object");
  });
});

describe("buildAstCache — malformed .tsx produces PARSE_WARN, no crash", () => {
  it("skips the malformed file and emits exactly one PARSE_WARN diagnostic", () => {
    const fileSet = makeFileSet({
      "bad.tsx": "export const = <<< broken(((",
    });

    const { astCache, diagnostics } = buildAstCache(fileSet);

    expect(astCache.has("bad.tsx")).toBe(false);
    expect(diagnostics.length).toBe(1);
    expect(diagnostics[0]?.code).toBe("PARSE_WARN");
    expect(diagnostics[0]?.file).toBe("bad.tsx");
    expect(diagnostics[0]?.level).toBe("warn");
  });

  it("does not throw and still caches well-formed siblings alongside the malformed file", () => {
    const fileSet = makeFileSet({
      "good.ts": "const ok = true;",
      "bad.tsx": "export const = <<< broken(((",
    });

    expect(() => buildAstCache(fileSet)).not.toThrow();

    const { astCache, diagnostics } = buildAstCache(fileSet);
    expect(astCache.has("good.ts")).toBe(true);
    expect(astCache.has("bad.tsx")).toBe(false);
    expect(diagnostics.length).toBe(1);
    expect(diagnostics[0]?.file).toBe("bad.tsx");
  });
});

describe("buildAstCache — non-JS/TS files are skipped entirely", () => {
  it("does not cache or warn on data.json, README.md, or .env", () => {
    const fileSet = makeFileSet({
      "data.json": '{"key":"value"}',
      "README.md": "# Title\n\nSome docs.",
      ".env": "API_KEY=supersecret",
    });

    const { astCache, diagnostics } = buildAstCache(fileSet);

    expect(astCache.has("data.json")).toBe(false);
    expect(astCache.has("README.md")).toBe(false);
    expect(astCache.has(".env")).toBe(false);
    expect(astCache.size).toBe(0);
    expect(diagnostics.length).toBe(0);
  });
});

import { describe, expect, it } from "vitest";

import { buildAstCache, isParseable, parseSource } from "./ast-cache.js";
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

describe("parseSource — per-extension parser plugins", () => {
  it("parses decorators in .ts files (NestJS / Angular / TypeORM)", () => {
    const { ast, diagnostic } = parseSource(
      "src/users.controller.ts",
      "@Controller('users')\nexport class UsersController {\n  @Get()\n  list() { return []; }\n}\n",
    );

    expect(diagnostic).toBeUndefined();
    expect(ast).toBeTruthy();
  });

  it("parses angle-bracket type assertions in .ts files (no JSX ambiguity)", () => {
    const { ast, diagnostic } = parseSource("src/cast.ts", "const value = <string>input;\nexport default value;\n");

    expect(diagnostic).toBeUndefined();
    expect(ast).toBeTruthy();
  });

  it("still parses JSX in .tsx and .jsx files", () => {
    expect(parseSource("a.tsx", "export const A = () => <div>{1}</div>;").ast).toBeTruthy();
    expect(parseSource("a.jsx", "export const A = () => <div>{1}</div>;").ast).toBeTruthy();
  });

  it("parses .mts / .cts and CommonJS top-level return", () => {
    expect(parseSource("a.mts", "export const x: number = 1;").ast).toBeTruthy();
    expect(parseSource("a.cts", "export const x: number = 1;").ast).toBeTruthy();
    expect(parseSource("a.cjs", "if (process.env.X) return;\nmodule.exports = {};").ast).toBeTruthy();
  });

  it("returns neither an AST nor a diagnostic for a non-JS/TS path", () => {
    expect(parseSource("README.md", "# hi")).toEqual({});
    expect(isParseable("README.md")).toBe(false);
    expect(isParseable("src/a.TS")).toBe(true);
  });
});

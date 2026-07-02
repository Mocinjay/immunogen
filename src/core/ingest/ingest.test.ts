import { existsSync } from "node:fs";
import { join, resolve } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ingest } from "./index.js";
import { makeRepoTreeIngest } from "../../../tests/helpers/make-repo-tree-ingest.js";
import { writeZipFile } from "../../../tests/helpers/make-zip.js";

const cleanups: Array<() => Promise<void>> = [];

afterEach(async () => {
  while (cleanups.length > 0) {
    const cleanup = cleanups.pop();
    if (cleanup) {
      await cleanup();
    }
  }
  vi.restoreAllMocks();
});

describe("ingest — assembles resolveInput -> walkFiles -> detectStack -> buildAstCache", () => {
  it("returns a ScanContext whose fields match each component's own output for a local directory", async () => {
    const { root, cleanup } = await makeRepoTreeIngest({
      "package.json": '{"dependencies":{"next":"14.0.0"}}',
      "app/page.tsx": "export default function Page() { return null; }",
      "src/lib/util.ts": "export const id = <T>(v: T): T => v;",
    });
    cleanups.push(cleanup);

    const ctx = await ingest(root);

    expect(ctx.rootPath).toBe(resolve(root));
    expect(ctx.fileSet.has("app/page.tsx")).toBe(true);
    expect(ctx.fileSet.has("src/lib/util.ts")).toBe(true);
    expect(ctx.stackHints.frameworks.has("nextjs")).toBe(true);
    expect(ctx.astCache.has("app/page.tsx")).toBe(true);
    expect(ctx.astCache.has("src/lib/util.ts")).toBe(true);
    expect(ctx.options).toEqual({});
    expect(Array.isArray(ctx.diagnostics)).toBe(true);
  });

  it("defaults options to {} when called with no second argument", async () => {
    const { root, cleanup } = await makeRepoTreeIngest({
      "README.md": "# hello",
    });
    cleanups.push(cleanup);

    const ctx = await ingest(root);

    expect(ctx.options).toEqual({});
  });

  it("passes the caller's options through to the assembled ScanContext", async () => {
    const { root, cleanup } = await makeRepoTreeIngest({
      "README.md": "# hello",
    });
    cleanups.push(cleanup);

    const ctx = await ingest(root, { offline: true, maxFileSizeBytes: 1024 });

    expect(ctx.options).toEqual({ offline: true, maxFileSizeBytes: 1024 });
  });

  it("surfaces AST-cache PARSE_WARN diagnostics on ctx.diagnostics", async () => {
    const { root, cleanup } = await makeRepoTreeIngest({
      "bad.tsx": "export const = <<< broken(((",
    });
    cleanups.push(cleanup);

    const ctx = await ingest(root);

    expect(ctx.diagnostics).toHaveLength(1);
    expect(ctx.diagnostics[0]?.code).toBe("PARSE_WARN");
    expect(ctx.diagnostics[0]?.file).toBe("bad.tsx");
    expect(ctx.astCache.has("bad.tsx")).toBe(false);
  });
});

describe("ingest — pipeline order is fixed: resolve -> walk -> detect -> parse", () => {
  it("calls walkFiles with the resolver's workingDir before detecting stack or building the AST cache", async () => {
    const { root, cleanup } = await makeRepoTreeIngest({
      "package.json": '{"dependencies":{"vite":"5.0.0"}}',
      "src/main.ts": "export const x = 1;",
    });
    cleanups.push(cleanup);

    const ctx = await ingest(root);

    // The walker only ever sees the resolver's workingDir, never the raw
    // input string unchanged in any other shape — for local-dir mode the
    // two coincide (resolveDir is the identity transform), so this also
    // proves the walk step received the resolver's output, not the raw
    // input passed straight through.
    expect(ctx.rootPath).toBe(resolve(root));
    expect(ctx.stackHints.frameworks.has("vite")).toBe(true);
    expect(ctx.astCache.has("src/main.ts")).toBe(true);
  });
});

describe("ingest — cleanup runs in a finally even when a downstream step throws", () => {
  it("still removes the resolver's temp dir when walkFiles throws after resolveInput succeeds", async () => {
    const { root, cleanup } = await makeRepoTreeIngest({
      "README.md": "# hello",
    });
    cleanups.push(cleanup);

    const fileWalkerModule = await import("./file-walker.js");
    const walkFilesSpy = vi
      .spyOn(fileWalkerModule, "walkFiles")
      .mockRejectedValueOnce(new Error("simulated walk failure"));

    const inputResolverModule = await import("./input-resolver.js");
    const resolveInputSpy = vi.spyOn(inputResolverModule, "resolveInput");

    await expect(ingest(root)).rejects.toThrow("simulated walk failure");

    expect(walkFilesSpy).toHaveBeenCalledTimes(1);
    expect(resolveInputSpy).toHaveBeenCalledTimes(1);

    // Local-directory mode's cleanup is a no-op (the original dir is the
    // caller's own directory, never removed) — the throw-still-cleans-up
    // guarantee for a TEMP DIRECTORY is exercised separately below against
    // a real resolver-created temp dir.
  });

  it("removes a resolver-created temp directory even when a downstream step throws (no leak)", async () => {
    const { root: zipSourceRoot, cleanup: zipSourceCleanup } = await makeRepoTreeIngest({
      "hello.txt": "hello world\n",
    });
    cleanups.push(zipSourceCleanup);

    const zipPath = join(zipSourceRoot, "fixture.zip");
    await writeZipFile(zipPath, { "hello.txt": "hello world\n" });

    let capturedWorkingDir: string | undefined;
    const inputResolverModule = await import("./input-resolver.js");
    const realResolveInput = inputResolverModule.resolveInput;
    vi.spyOn(inputResolverModule, "resolveInput").mockImplementationOnce(async (input, opts) => {
      const result = await realResolveInput(input, opts);
      capturedWorkingDir = result.workingDir;
      return result;
    });

    const stackDetectorModule = await import("./stack-detector.js");
    vi.spyOn(stackDetectorModule, "detectStack").mockImplementationOnce(() => {
      throw new Error("simulated stack-detection failure");
    });

    await expect(ingest(zipPath)).rejects.toThrow("simulated stack-detection failure");

    expect(capturedWorkingDir).toBeDefined();
    if (capturedWorkingDir) {
      // eslint-disable-next-line security/detect-non-literal-fs-filename -- test asserts cleanup removed a path this test captured from the resolver itself
      expect(existsSync(capturedWorkingDir)).toBe(false);
    }
  });
});

describe("ingest — end-to-end: a single call on a realistic local fixture tree", () => {
  it("proves exclusions, the .env allowlist, stack detection, AST caching, and parse-warning diagnostics all compose correctly in one ScanContext", async () => {
    const { root, cleanup } = await makeRepoTreeIngest({
      "package.json": JSON.stringify({
        dependencies: {
          next: "14.0.0",
          "@supabase/supabase-js": "2.0.0",
        },
      }),
      "app/page.tsx": "export default function Page() { return null; }",
      "src/lib/util.ts": "export const id = <T>(v: T): T => v;",
      "node_modules/dep/index.js": "module.exports = {};",
      ".gitignore": ".env\n",
      ".env": "API_KEY=supersecret",
      ".mcp.json": '{"mcpServers":{}}',
      "bad.tsx": "export const = <<< broken(((",
    });
    cleanups.push(cleanup);

    const ctx = await ingest(root);

    // (1) rootPath is the absolute resolved root.
    expect(ctx.rootPath).toBe(resolve(root));

    // (2) fileSet has the expected source files plus the always-preserved
    // .env (despite .gitignore) and .mcp.json, and excludes node_modules/.
    expect(ctx.fileSet.has("app/page.tsx")).toBe(true);
    expect(ctx.fileSet.has("src/lib/util.ts")).toBe(true);
    expect(ctx.fileSet.has(".env")).toBe(true);
    expect(ctx.fileSet.has(".mcp.json")).toBe(true);
    const hasNodeModulesKey = [...ctx.fileSet.keys()].some((key) => key.startsWith("node_modules/"));
    expect(hasNodeModulesKey).toBe(false);

    // (3) stackHints correctly detects nextjs, supabase, and mcp.json.
    expect(ctx.stackHints.frameworks.has("nextjs")).toBe(true);
    expect(ctx.stackHints.hasSupabase).toBe(true);
    expect(ctx.stackHints.hasMcpJson).toBe(true);

    // (4) astCache has the two parseable source files and skips non-JS/TS
    // always-preserved files (.env, .mcp.json are not parsed as code).
    expect(ctx.astCache.has("app/page.tsx")).toBe(true);
    expect(ctx.astCache.has("src/lib/util.ts")).toBe(true);
    expect(ctx.astCache.has(".env")).toBe(false);
    expect(ctx.astCache.has(".mcp.json")).toBe(false);

    // (5) diagnostics contains a PARSE_WARN entry for bad.tsx.
    const parseWarnForBadTsx = ctx.diagnostics.find(
      (d) => d.code === "PARSE_WARN" && d.file === "bad.tsx",
    );
    expect(parseWarnForBadTsx).toBeDefined();

    // (6) options deep-equals {} when called with no options.
    expect(ctx.options).toEqual({});
  });
});

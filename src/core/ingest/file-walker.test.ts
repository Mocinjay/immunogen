import { simpleGit } from "simple-git";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { walkFiles } from "./file-walker.js";
import { makeRepoTree } from "../../../tests/helpers/make-repo-tree.js";
import type { MadeRepoTree } from "../../../tests/helpers/make-repo-tree.js";

const trees: MadeRepoTree[] = [];

afterEach(async () => {
  while (trees.length > 0) {
    const tree = trees.pop();
    if (tree) {
      await tree.cleanup();
    }
  }
});

/** Builds the representative fixture tree shared by every assertion below. */
async function buildFixtureTree(): Promise<MadeRepoTree> {
  const tree = await makeRepoTree({
    "package.json": '{"name":"fixture"}',
    "node_modules/lodash/index.js": "module.exports = {};",
    ".next/build.js": "// generated build output",
    "dist/out.js": "// bundled output",
    ".gitignore": "secret-notes.txt\n.env\n",
    "secret-notes.txt": "do not commit this",
    ".env": "API_KEY=supersecret",
    ".env.local": "LOCAL_KEY=alsosecret",
    ".mcp.json": "{}",
    ".cursor/rules": "always use TypeScript strict mode",
    ".claude/skills/s.md": "# Skill s",
    "src/app/page.tsx": "export default function Page() { return null; }",
    "big.generated.js": "x".repeat(600 * 1024),
    "blob.bin": `binary\0content`,
    "Pods/SomeVendoredLib/README.md": "example api key: not-a-real-secret",
  });
  trees.push(tree);
  return tree;
}

describe("walkFiles — hard exclusions", () => {
  it("excludes node_modules, .next, and dist entirely", async () => {
    const tree = await buildFixtureTree();

    const { fileSet: result } = await walkFiles(tree.root);

    for (const key of result.keys()) {
      expect(key).not.toContain("node_modules/");
      expect(key).not.toContain(".next/");
      expect(key).not.toContain("dist/");
    }
  });

  it("excludes Pods/ (CocoaPods vendored dependencies) entirely", async () => {
    const tree = await buildFixtureTree();

    const { fileSet: result } = await walkFiles(tree.root);

    for (const key of result.keys()) {
      expect(key).not.toContain("Pods/");
    }
  });
});

describe("walkFiles — .gitignore filtering", () => {
  it("drops a gitignored file that is not in the always-preserve allowlist", async () => {
    const tree = await buildFixtureTree();

    const { fileSet: result } = await walkFiles(tree.root);

    expect(result.has("secret-notes.txt")).toBe(false);
  });

  it("drops a gitignored .env outside a git repo (local config, never committed)", async () => {
    const tree = await buildFixtureTree();

    const { fileSet: result } = await walkFiles(tree.root);

    expect(result.has(".env")).toBe(false);
  });

  it("keeps a .env that .gitignore does not cover (it would be committed)", async () => {
    const tree = await buildFixtureTree();

    const { fileSet: result } = await walkFiles(tree.root);

    expect(result.get(".env.local")).toBe("LOCAL_KEY=alsosecret");
  });

  it("honors glob and anchored .gitignore patterns for env files (.env*.local, /.env)", async () => {
    const tree = await makeRepoTree({
      ".gitignore": ".env*.local\n/.env\n",
      ".env": "A=1",
      ".env.local": "B=2",
      ".env.production.local": "C=3",
      ".env.production": "D=4",
      "apps/web/.env": "E=5",
    });
    trees.push(tree);

    const { fileSet: result } = await walkFiles(tree.root);

    expect(result.has(".env")).toBe(false);
    expect(result.has(".env.local")).toBe(false);
    expect(result.has(".env.production.local")).toBe(false);
    expect(result.has(".env.production")).toBe(true);
    // `/.env` is anchored to the root, so a nested .env is still committable.
    expect(result.has("apps/web/.env")).toBe(true);
  });

  it("applies a nested .gitignore relative to its own directory", async () => {
    const tree = await makeRepoTree({
      "app/.gitignore": ".env\nbuild-cache/\n",
      "app/.env": "A=1",
      "app/build-cache/x.js": "x",
      "app/src/index.ts": "export {};",
      "other/.env": "B=2",
    });
    trees.push(tree);

    const { fileSet: result } = await walkFiles(tree.root);

    expect(result.has("app/.env")).toBe(false);
    expect(result.has("app/build-cache/x.js")).toBe(false);
    expect(result.has("app/src/index.ts")).toBe(true);
    expect(result.has("other/.env")).toBe(true);
  });
});

describe("walkFiles — git-tracked env files", () => {
  it("keeps a .env that git TRACKS even though .gitignore lists it (committed, then ignored)", async () => {
    const tree = await makeRepoTree({ ".gitignore": ".env\n.env.local\n", ".env": "A=1", ".env.local": "B=2" });
    trees.push(tree);
    const git = simpleGit(tree.root);
    await git.init();
    await git.add(["-f", ".env"]);

    const { fileSet: result } = await walkFiles(tree.root);

    expect(result.has(".env")).toBe(true);
    expect(result.has(".env.local")).toBe(false);
  });

  it("resolves tracked paths relative to a scanned subdirectory of the repo", async () => {
    const tree = await makeRepoTree({ "app/.gitignore": ".env\n", "app/.env": "A=1", "app/index.ts": "export {};" });
    trees.push(tree);
    const git = simpleGit(tree.root);
    await git.init();
    await git.add(["-f", "app/.env"]);

    const { fileSet: result } = await walkFiles(join(tree.root, "app"));

    expect(result.has(".env")).toBe(true);
  });
});

describe("walkFiles — always-preserve allowlist", () => {
  it("keeps .mcp.json, .cursor/rules, and .claude/skills/s.md", async () => {
    const tree = await buildFixtureTree();

    const { fileSet: result } = await walkFiles(tree.root);

    expect(result.has(".mcp.json")).toBe(true);
    expect(result.has(".cursor/rules")).toBe(true);
    expect(result.has(".claude/skills/s.md")).toBe(true);
  });

  it("keeps .cursor/mcp.json and a per-file .mdc rule under .cursor/rules/", async () => {
    const tree = await makeRepoTree({
      ".cursor/mcp.json": "{}",
      ".cursor/rules/typescript.mdc": "use strict mode",
      ".gitignore": ".cursor/\n",
    });
    trees.push(tree);

    const { fileSet: result } = await walkFiles(tree.root);

    expect(result.has(".cursor/mcp.json")).toBe(true);
    expect(result.has(".cursor/rules/typescript.mdc")).toBe(true);
  });

  it("keeps .cursorrules even when gitignored", async () => {
    const tree = await makeRepoTree({
      ".cursorrules": "legacy single-file rules",
      ".gitignore": ".cursorrules\n",
    });
    trees.push(tree);

    const { fileSet: result } = await walkFiles(tree.root);

    expect(result.has(".cursorrules")).toBe(true);
  });
});

describe("walkFiles — size cap and binary skip", () => {
  it("drops a file over the default 512KB size cap", async () => {
    const tree = await buildFixtureTree();

    const { fileSet: result } = await walkFiles(tree.root);

    expect(result.has("big.generated.js")).toBe(false);
  });

  it("drops a file containing a NUL byte in its first 8KB", async () => {
    const tree = await buildFixtureTree();

    const { fileSet: result } = await walkFiles(tree.root);

    expect(result.has("blob.bin")).toBe(false);
  });

  it("respects a custom maxFileSizeBytes option", async () => {
    const tree = await makeRepoTree({
      "small.txt": "x".repeat(100),
    });
    trees.push(tree);

    const { fileSet: result } = await walkFiles(tree.root, { maxFileSizeBytes: 50 });

    expect(result.has("small.txt")).toBe(false);
  });
});

describe("walkFiles — total-repo cap (belt-and-suspenders alongside the per-file cap)", () => {
  it("stops reading once maxTotalBytes is exceeded and emits a SCAN_TRUNCATED diagnostic, without throwing", async () => {
    const tree = await makeRepoTree({
      "a.txt": "x".repeat(100),
      "b.txt": "x".repeat(100),
      "c.txt": "x".repeat(100),
    });
    trees.push(tree);

    const { fileSet, diagnostics } = await walkFiles(tree.root, { maxTotalBytes: 150 });

    // Never crashes; returns whatever was read before the cap tripped.
    expect(fileSet.size).toBeLessThan(3);
    const truncated = diagnostics.find((d) => d.code === "SCAN_TRUNCATED");
    expect(truncated).toBeDefined();
    expect(truncated?.level).toBe("warn");
  });

  it("stops reading once maxTotalFiles is exceeded and emits a SCAN_TRUNCATED diagnostic", async () => {
    const tree = await makeRepoTree({
      "a.txt": "a",
      "b.txt": "b",
      "c.txt": "c",
    });
    trees.push(tree);

    const { fileSet, diagnostics } = await walkFiles(tree.root, { maxTotalFiles: 2 });

    expect(fileSet.size).toBe(2);
    expect(diagnostics.some((d) => d.code === "SCAN_TRUNCATED")).toBe(true);
  });

  it("emits no SCAN_TRUNCATED diagnostic when the repo stays within the default caps", async () => {
    const tree = await makeRepoTree({
      "small.txt": "hello",
    });
    trees.push(tree);

    const { diagnostics } = await walkFiles(tree.root);

    expect(diagnostics.some((d) => d.code === "SCAN_TRUNCATED")).toBe(false);
  });
});

describe("walkFiles — output shape", () => {
  it("returns repo-relative forward-slash keys with no leading slash", async () => {
    const tree = await buildFixtureTree();

    const { fileSet: result } = await walkFiles(tree.root);

    expect(result.has("src/app/page.tsx")).toBe(true);
    expect(result.get("src/app/page.tsx")).toBe(
      "export default function Page() { return null; }",
    );

    for (const key of result.keys()) {
      expect(key.startsWith("/")).toBe(false);
      expect(key.includes("\\")).toBe(false);
    }
  });

  it("returns an empty map for an empty directory", async () => {
    const tree = await makeRepoTree({});

    const { fileSet: result } = await walkFiles(tree.root);

    expect(result.size).toBe(0);
  });
});

describe("walkFiles — .immunogenignore", () => {
  it("excludes paths listed in a root .immunogenignore, unless noIgnore is set", async () => {
    const tree = await makeRepoTree({
      ".immunogenignore": "seed/\n*.generated.ts\n",
      "seed/users.json": "[]",
      "src/api.generated.ts": "export {};",
      "src/index.ts": "export {};",
    });
    trees.push(tree);

    const { fileSet: honored } = await walkFiles(tree.root);
    const { fileSet: overridden } = await walkFiles(tree.root, { noIgnore: true });

    expect([...honored.keys()].sort()).toEqual([".immunogenignore", "src/index.ts"]);
    expect(overridden.has("seed/users.json")).toBe(true);
    expect(overridden.has("src/api.generated.ts")).toBe(true);
  });
});

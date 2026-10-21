import { simpleGit } from "simple-git";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { parseIndexPaths, readTrackedFiles } from "./git-index.js";
import { makeRepoTree } from "../../../tests/helpers/make-repo-tree.js";
import type { MadeRepoTree } from "../../../tests/helpers/make-repo-tree.js";

const trees: MadeRepoTree[] = [];

afterEach(async () => {
  while (trees.length > 0) {
    await trees.pop()?.cleanup();
  }
});

/** Builds a temp repo, `git add`s `tracked`, optionally rewrites the index at `indexVersion`, and returns the tree. */
async function makeGitRepo(tracked: string[], indexVersion?: number): Promise<MadeRepoTree> {
  const tree = await makeRepoTree({
    ".env": "A=1",
    "src/app/page.tsx": "export {};",
    "src/app/api/route.ts": "export {};",
    "src/lib/deep/nested/file.ts": "export {};",
    "untracked.txt": "x",
  });
  trees.push(tree);
  const git = simpleGit(tree.root);
  await git.init();
  await git.add(["-f", ...tracked]);
  if (indexVersion !== undefined) {
    await git.raw(["update-index", "--index-version", String(indexVersion)]);
  }
  return tree;
}

describe("parseIndexPaths", () => {
  for (const version of [2, 3, 4]) {
    it(`reads every tracked path from a real index v${String(version)}`, async () => {
      const tracked = [".env", "src/app/api/route.ts", "src/app/page.tsx", "src/lib/deep/nested/file.ts"];
      const tree = await makeGitRepo(tracked, version);

      // eslint-disable-next-line security/detect-non-literal-fs-filename -- test reads its own temp repo's index
      const paths = parseIndexPaths(await readFile(join(tree.root, ".git", "index")));

      expect(paths).toEqual(tracked);
    });
  }

  it("returns undefined for a buffer that is not a git index", () => {
    expect(parseIndexPaths(Buffer.from("not an index at all"))).toBeUndefined();
    expect(parseIndexPaths(Buffer.alloc(0))).toBeUndefined();
  });

  it("returns undefined for a truncated index instead of throwing", async () => {
    const tree = await makeGitRepo([".env", "src/app/page.tsx"]);
    // eslint-disable-next-line security/detect-non-literal-fs-filename -- test reads its own temp repo's index
    const full = await readFile(join(tree.root, ".git", "index"));

    expect(parseIndexPaths(full.subarray(0, 40))).toBeUndefined();
  });
});

describe("readTrackedFiles", () => {
  it("returns undefined outside a git work tree", async () => {
    const tree = await makeRepoTree({ "a.ts": "export {};" });
    trees.push(tree);

    expect(await readTrackedFiles(tree.root)).toBeUndefined();
  });

  it("returns tracked paths relative to a scanned subdirectory", async () => {
    const tree = await makeGitRepo([".env", "src/app/page.tsx"]);

    const tracked = await readTrackedFiles(join(tree.root, "src"));

    expect(tracked).toEqual(new Set(["app/page.tsx"]));
  });
});

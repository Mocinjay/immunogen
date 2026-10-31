/**
 * Keeps the README's version-pinned install URLs in step with package.json.
 * npx caches whatever a URL first downloaded, so the one-off and CI examples
 * pin a release; a version bump that forgets them fails here instead of
 * leaving users on the old release.
 */
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const readme = readFileSync(new URL("../../README.md", import.meta.url), "utf8");
const { version } = JSON.parse(readFileSync(new URL("../../package.json", import.meta.url), "utf8")) as {
  version: string;
};

describe("README install instructions", () => {
  it("pins every versioned release URL to the package.json version", () => {
    const pinned = [...readme.matchAll(/releases\/download\/v([^/\s]+)\/immunogen-([^\s]+?)\.tgz/g)];

    expect(pinned.length).toBeGreaterThan(0);
    for (const [url, tagVersion, fileVersion] of pinned) {
      expect({ url, tagVersion, fileVersion }).toEqual({ url, tagVersion: version, fileVersion: version });
    }
  });
});

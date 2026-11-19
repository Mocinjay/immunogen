/**
 * Keeps the README's version pins in step with package.json: the GitHub
 * Action reference (`uses: Mocinjay/immunogen@vX.Y.Z`) and any versioned
 * release-tarball URL. A version bump that forgets them fails here instead
 * of pointing users at an older release.
 */
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const readme = readFileSync(new URL("../../README.md", import.meta.url), "utf8");
const { version } = JSON.parse(readFileSync(new URL("../../package.json", import.meta.url), "utf8")) as {
  version: string;
};

describe("README version pins", () => {
  it("pins the GitHub Action to the package.json version", () => {
    const actionPins = [...readme.matchAll(/uses: Mocinjay\/immunogen@v(\S+)/g)].map((match) => match[1]);

    expect(actionPins.length).toBeGreaterThan(0);
    expect(new Set(actionPins)).toEqual(new Set([version]));
  });

  it("pins every versioned release URL (if any) to the package.json version", () => {
    for (const [url, tagVersion, fileVersion] of readme.matchAll(/releases\/download\/v([^/\s]+)\/immunogen-([^\s]+?)\.tgz/g)) {
      expect({ url, tagVersion, fileVersion }).toEqual({ url, tagVersion: version, fileVersion: version });
    }
  });

  it("tells users to install from npm", () => {
    expect(readme).toContain("npm install -g immunogen");
    expect(readme).toContain("npx immunogen");
  });
});

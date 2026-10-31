import { describe, expect, it } from "vitest";

import { isInTestDirectory, isTestOrFixturePath } from "./test-paths.js";

describe("isTestOrFixturePath — one allowlist for every detector", () => {
  it.each([
    "src/__tests__/a.ts",
    "src/__mocks__/db.ts",
    "tests/fixtures/app/config.ts",
    "examples/demo/server.js",
    "pkg/testdata/main.go",
    "src/user.test.ts",
    "src/user.spec.ts",
    "src/Button.stories.tsx",
    "app/test_views.py",
    "app/views_test.py",
    "cmd/server_test.go",
    "conftest.py",
  ])("treats %s as test/fixture code", (path) => {
    expect(isTestOrFixturePath(path)).toBe(true);
  });

  it.each(["src/app.ts", "src/testing-utils.ts", "app/api/route.ts", "src/contest.py", ".env.test"])(
    "treats %s as shipped code",
    (path) => {
      expect(isTestOrFixturePath(path)).toBe(false);
    },
  );
});

describe("isInTestDirectory — directory-only check for committed env files and SQL", () => {
  it("ignores file-name conventions, so a committed .env.test.local is still checked", () => {
    expect(isInTestDirectory(".env.test.local")).toBe(false);
    expect(isInTestDirectory("fixtures/.env")).toBe(true);
  });
});

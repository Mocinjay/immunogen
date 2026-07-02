import { describe, expect, it } from "vitest";

import { detectStack } from "./stack-detector.js";
import { makeFileSet } from "../../../tests/helpers/make-file-set.js";

describe("detectStack — Next.js", () => {
  it("detects Next.js from a `next` dependency in package.json", () => {
    const fileSet = makeFileSet({
      "package.json": JSON.stringify({ dependencies: { next: "14.0.0" } }),
    });

    const hints = detectStack(fileSet);

    expect(hints.frameworks.has("nextjs")).toBe(true);
  });

  it("detects Next.js from an app/ directory alone, with no `next` dependency", () => {
    const fileSet = makeFileSet({
      "package.json": JSON.stringify({ dependencies: {} }),
      "app/page.tsx": "export default function Page() { return null; }",
    });

    const hints = detectStack(fileSet);

    expect(hints.frameworks.has("nextjs")).toBe(true);
  });
});

describe("detectStack — Supabase", () => {
  it("sets hasSupabase from the @supabase/supabase-js dependency", () => {
    const fileSet = makeFileSet({
      "package.json": JSON.stringify({ dependencies: { "@supabase/supabase-js": "2.0.0" } }),
    });

    const hints = detectStack(fileSet);

    expect(hints.hasSupabase).toBe(true);
    expect(hints.frameworks.has("supabase")).toBe(true);
  });
});

describe("detectStack — Firebase", () => {
  it("sets hasFirebase from the firebase dependency", () => {
    const fileSet = makeFileSet({
      "package.json": JSON.stringify({ dependencies: { firebase: "10.0.0" } }),
    });

    const hints = detectStack(fileSet);

    expect(hints.hasFirebase).toBe(true);
  });
});

describe("detectStack — Stripe", () => {
  it("sets hasStripe from the stripe dependency", () => {
    const fileSet = makeFileSet({
      "package.json": JSON.stringify({ dependencies: { stripe: "16.0.0" } }),
    });

    const hints = detectStack(fileSet);

    expect(hints.hasStripe).toBe(true);
  });
});

describe("detectStack — MCP JSON", () => {
  it("sets hasMcpJson when .mcp.json is present", () => {
    const fileSet = makeFileSet({
      ".mcp.json": "{}",
    });

    const hints = detectStack(fileSet);

    expect(hints.hasMcpJson).toBe(true);
  });

  it("sets hasMcpJson when .cursor/mcp.json is present", () => {
    const fileSet = makeFileSet({
      ".cursor/mcp.json": "{}",
    });

    const hints = detectStack(fileSet);

    expect(hints.hasMcpJson).toBe(true);
  });
});

describe("detectStack — Claude skills", () => {
  it("sets hasClaudeSkills when a file exists under .claude/skills/", () => {
    const fileSet = makeFileSet({
      ".claude/skills/scan.md": "# Skill scan",
    });

    const hints = detectStack(fileSet);

    expect(hints.hasClaudeSkills).toBe(true);
  });
});

describe("detectStack — Cursor rules", () => {
  it("sets hasCursorRules when .cursor/rules is present", () => {
    const fileSet = makeFileSet({
      ".cursor/rules": "always use TypeScript strict mode",
    });

    const hints = detectStack(fileSet);

    expect(hints.hasCursorRules).toBe(true);
  });

  it("sets hasCursorRules when .cursorrules is present", () => {
    const fileSet = makeFileSet({
      ".cursorrules": "legacy single-file rules",
    });

    const hints = detectStack(fileSet);

    expect(hints.hasCursorRules).toBe(true);
  });

  it("sets hasCursorRules when a per-file .mdc rule exists under .cursor/rules/", () => {
    const fileSet = makeFileSet({
      ".cursor/rules/typescript.mdc": "use strict mode",
    });

    const hints = detectStack(fileSet);

    expect(hints.hasCursorRules).toBe(true);
  });
});

describe("detectStack — malformed package.json", () => {
  it("does not throw and returns all-false booleans on malformed JSON", () => {
    const fileSet = makeFileSet({
      "package.json": "{ not valid json",
    });

    expect(() => detectStack(fileSet)).not.toThrow();

    const hints = detectStack(fileSet);

    expect(hints.hasSupabase).toBe(false);
    expect(hints.hasFirebase).toBe(false);
    expect(hints.hasStripe).toBe(false);
    expect(hints.hasMcpJson).toBe(false);
    expect(hints.hasClaudeSkills).toBe(false);
    expect(hints.hasCursorRules).toBe(false);
    expect(hints.frameworks.size).toBe(0);
  });
});

describe("detectStack — absent package.json", () => {
  it("returns a valid, all-false StackHints when no package.json is in the fileSet", () => {
    const fileSet = makeFileSet({});

    const hints = detectStack(fileSet);

    expect(hints.hasSupabase).toBe(false);
    expect(hints.hasFirebase).toBe(false);
    expect(hints.hasStripe).toBe(false);
    expect(hints.frameworks.size).toBe(0);
  });
});

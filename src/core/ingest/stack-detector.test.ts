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

describe("detectStack — nested apps and non-Next app/ folders", () => {
  it("reads dependencies from a nested app manifest (monorepo / app-in-subfolder)", () => {
    const fileSet = new Map([
      ["package.json", JSON.stringify({ name: "root", private: true })],
      ["apps/web/package.json", JSON.stringify({ dependencies: { next: "15.0.0", "@supabase/ssr": "0.5.0", stripe: "17.0.0" } })],
      ["node_modules/firebase/package.json", JSON.stringify({ dependencies: { firebase: "1.0.0" } })],
    ]);

    const hints = detectStack(fileSet);

    expect(hints.frameworks.has("nextjs")).toBe(true);
    expect(hints.hasSupabase).toBe(true);
    expect(hints.hasStripe).toBe(true);
    expect(hints.hasFirebase).toBe(false);
  });

  it("does NOT treat a React Native app/ folder as Next.js", () => {
    const fileSet = new Map([
      ["app/package.json", JSON.stringify({ dependencies: { "react-native": "0.76.0" } })],
      ["app/App.tsx", "export default function App() { return null; }"],
      ["app/src/screens/Home.tsx", "export {};"],
    ]);

    expect(detectStack(fileSet).frameworks.has("nextjs")).toBe(false);
  });

  it("detects Next.js from a Pages Router API file", () => {
    expect(detectStack(new Map([["src/pages/api/hello.ts", "export default () => {};"]])).frameworks.has("nextjs")).toBe(true);
  });
});

describe("detectStack — Python and Go", () => {
  it("detects Python frameworks and services from requirements.txt / pyproject.toml", () => {
    const hints = detectStack(
      new Map([
        ["requirements.txt", "FastAPI==0.110.0\nstripe==8.0.0\n"],
        ["worker/pyproject.toml", '[project]\ndependencies = ["supabase>=2", "firebase_admin==6.0.0"]\n'],
      ]),
    );

    expect([...hints.frameworks].sort()).toEqual(["fastapi", "firebase", "python", "stripe", "supabase"]);
    expect(hints.hasStripe).toBe(true);
    expect(hints.hasSupabase).toBe(true);
    expect(hints.hasFirebase).toBe(true);
  });

  it("detects Go and its web frameworks from go.mod", () => {
    const hints = detectStack(
      new Map([["go.mod", "module x\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.0\n\tgithub.com/stripe/stripe-go/v76 v76.0.0\n)\n"]]),
    );

    expect([...hints.frameworks].sort()).toEqual(["gin", "go", "stripe"]);
    expect(hints.hasStripe).toBe(true);
  });
});

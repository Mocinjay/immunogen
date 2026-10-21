import { describe, expect, it } from "vitest";

import { firebaseRulesDetector } from "./firebase-rules-detector.js";

import type { DetectorContext, StackHints } from "../../core/types.js";

/** StackHints with Firebase present — the gate this detector reads. */
const FIREBASE_STACK_HINTS: StackHints = {
  frameworks: new Set(["firebase"]),
  hasSupabase: false,
  hasFirebase: true,
  hasStripe: false,
  hasEnvFiles: false,
  hasMcpJson: false,
  hasClaudeSkills: false,
  hasCursorRules: false,
};

/** StackHints with no Firebase — proves the stack gate (Test 4). */
const NO_FIREBASE_STACK_HINTS: StackHints = {
  ...FIREBASE_STACK_HINTS,
  frameworks: new Set(),
  hasFirebase: false,
};

/** Builds a DetectorContext literal for `content` at the given `filePath`, without the ingestion layer. */
function makeContext(content: string, filePath: string, stackHints: StackHints = FIREBASE_STACK_HINTS): DetectorContext {
  return {
    filePath,
    content,
    stackHints,
    fileSet: new Map(),
  };
}

describe("firebaseRulesDetector — AUTH-02 (firestore/db rules)", () => {
  it("flags 'allow read, write: if true;' in firestore.rules as AUTH-02 CRITICAL/HIGH at the correct line", async () => {
    const ctx = makeContext(
      "rules_version = '2';\nservice cloud.firestore {\n  match /databases/{database}/documents {\n    match /{document=**} {\n      allow read, write: if true;\n    }\n  }\n}\n",
      "firestore.rules",
    );

    const findings = await firebaseRulesDetector.detect(ctx);

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      ruleId: "AUTH-02",
      category: "auth",
      severity: "CRITICAL",
      confidence: "HIGH",
      file: "firestore.rules",
      line: 5,
    });
  });
});

describe("firebaseRulesDetector — STORAGE-01 (storage.rules)", () => {
  it("flags 'allow write: if true;' in storage.rules as STORAGE-01 CRITICAL/HIGH", async () => {
    const ctx = makeContext(
      "rules_version = '2';\nservice firebase.storage {\n  match /b/{bucket}/o {\n    match /{allPaths=**} {\n      allow write: if true;\n    }\n  }\n}\n",
      "storage.rules",
    );

    const findings = await firebaseRulesDetector.detect(ctx);

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      ruleId: "STORAGE-01",
      category: "storage",
      severity: "CRITICAL",
      confidence: "HIGH",
    });
  });
});

describe("firebaseRulesDetector — clean cases", () => {
  it("does NOT flag an ownership-checked allow condition", async () => {
    const ctx = makeContext(
      "service cloud.firestore {\n  match /databases/{database}/documents {\n    match /users/{userId} {\n      allow read, write: if request.auth != null && request.auth.uid == userId;\n    }\n  }\n}\n",
      "firestore.rules",
    );

    const findings = await firebaseRulesDetector.detect(ctx);

    expect(findings).toHaveLength(0);
  });

  it("does NOT flag a generic *.rules file when stackHints.hasFirebase is false (stack gate)", async () => {
    const ctx = makeContext(
      "allow read, write: if true;",
      "config/lint.rules",
      NO_FIREBASE_STACK_HINTS,
    );

    const findings = await firebaseRulesDetector.detect(ctx);

    expect(findings).toHaveLength(0);
  });

  it("still checks firestore.rules by name when the Firebase SDK is not a root dependency", async () => {
    const ctx = makeContext("allow read, write: if true;", "firestore.rules", NO_FIREBASE_STACK_HINTS);

    const findings = await firebaseRulesDetector.detect(ctx);

    expect(findings).toHaveLength(1);
  });

  it("does NOT flag 'if true' inside a __tests__/fixtures/examples path (FP allowlist guard)", async () => {
    const ctx = makeContext(
      "allow read, write: if true;",
      "src/__tests__/fixtures/firestore.rules",
    );

    const findings = await firebaseRulesDetector.detect(ctx);

    expect(findings).toHaveLength(0);
  });
});

describe("firebaseRulesDetector — config", () => {
  it("declares name 'firebase-rules' and category 'storage'", () => {
    expect(firebaseRulesDetector.config.name).toBe("firebase-rules");
    expect(firebaseRulesDetector.config.category).toBe("storage");
  });

  it("declares requiresStack including 'firebase'", () => {
    expect(firebaseRulesDetector.config.requiresStack).toContain("firebase");
  });

  it("declares globs covering firestore.rules, storage.rules, and database.rules.json", () => {
    const globs = firebaseRulesDetector.config.globs;
    expect(globs.some((glob) => glob.includes("firestore.rules"))).toBe(true);
    expect(globs.some((glob) => glob.includes("storage.rules"))).toBe(true);
    expect(globs.some((glob) => glob.includes("database.rules.json"))).toBe(true);
  });
});

describe("firebaseRulesDetector — no-throw contract", () => {
  it("resolves to [] for empty content", async () => {
    const ctx = makeContext("", "firestore.rules");

    const findings = await firebaseRulesDetector.detect(ctx);

    expect(findings).toEqual([]);
  });
});

describe("firebaseRulesDetector — test mode, Realtime Database, and signed-in-only rules", () => {
  it("flags the console's test-mode rule (request.time < timestamp.date) as CRITICAL", async () => {
    const rules = [
      "service cloud.firestore {",
      "  match /databases/{database}/documents {",
      "    match /{document=**} {",
      "      allow read, write: if request.time < timestamp.date(2025, 12, 31);",
      "    }",
      "  }",
      "}",
    ].join("\n");

    const findings = await firebaseRulesDetector.detect(makeContext(rules, "firestore.rules"));

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ ruleId: "AUTH-02", severity: "CRITICAL", line: 4 });
    expect(findings[0]?.message).toContain("test-mode");
  });

  it('flags Realtime Database ".read": true / ".write": true as CRITICAL', async () => {
    const rules = ['{', '  "rules": {', '    ".read": true,', '    ".write": "true"', "  }", "}"].join("\n");

    const findings = await firebaseRulesDetector.detect(makeContext(rules, "database.rules.json"));

    expect(findings.map((finding) => [finding.severity, finding.line])).toEqual([
      ["CRITICAL", 3],
      ["CRITICAL", 4],
    ]);
  });

  it("flags signed-in-only access on a recursive wildcard as HIGH, but not on a scoped collection", async () => {
    const rules = [
      "service cloud.firestore {",
      "  match /databases/{database}/documents {",
      "    match /posts/{postId} {",
      "      allow read: if request.auth != null;",
      "    }",
      "    match /{document=**} {",
      "      allow read, write: if request.auth != null;",
      "    }",
      "  }",
      "}",
    ].join("\n");

    const findings = await firebaseRulesDetector.detect(makeContext(rules, "firestore.rules"));

    expect(findings.map((finding) => [finding.severity, finding.line])).toEqual([["HIGH", 7]]);
  });
});

import { describe, expect, it } from "vitest";

import { buildAstCache } from "../../core/parse/ast-cache.js";
import { dangerousCodeDetector } from "./dangerous-code-detector.js";

import type { DetectorContext, StackHints } from "../../core/types.js";

const STACK_HINTS: StackHints = {
  frameworks: new Set(),
  hasSupabase: false,
  hasFirebase: false,
  hasStripe: false,
  hasEnvFiles: false,
  hasMcpJson: false,
  hasClaudeSkills: false,
  hasCursorRules: false,
};

function makeContext(content: string, filePath = "app/api/items/route.ts"): DetectorContext {
  const { astCache } = buildAstCache(new Map([[filePath, content]]));
  return { filePath, content, ast: astCache.get(filePath), stackHints: STACK_HINTS, fileSet: new Map([[filePath, content]]) };
}

async function ruleIds(content: string, filePath?: string): Promise<string[]> {
  const findings = await dangerousCodeDetector.detect(makeContext(content, filePath));
  return findings.map((finding) => finding.ruleId);
}

describe("dangerousCodeDetector — INJECT-02 SQL injection", () => {
  it.each([
    ["Prisma $queryRawUnsafe with a template literal", "await prisma.$queryRawUnsafe(`SELECT * FROM users WHERE id = ${id}`);"],
    ["Prisma $executeRawUnsafe with concatenation", "await prisma.$executeRawUnsafe('DELETE FROM t WHERE id = ' + id);"],
    ["pg .query with an interpolated SELECT", "await pool.query(`SELECT * FROM orders WHERE user_id = '${userId}'`);"],
    ["mysql .execute with a concatenated UPDATE", "await conn.execute('UPDATE users SET name = \"' + name + '\" WHERE id = 1');"],
    ["knex.raw with an interpolated query", "await knex.raw(`select * from t where name = '${name}'`);"],
    ["better-sqlite3 prepare with interpolation", "db.prepare(`SELECT * FROM notes WHERE id = ${req.params.id}`).get();"],
  ])("flags %s", async (_label, code) => {
    expect(await ruleIds(code)).toEqual(["INJECT-02"]);
  });

  it.each([
    ["a tagged sql template", "await sql`SELECT * FROM users WHERE id = ${id}`;"],
    ["Prisma's tagged $queryRaw", "await prisma.$queryRaw`SELECT * FROM users WHERE id = ${id}`;"],
    ["a parameterized query", "await pool.query('SELECT * FROM users WHERE id = $1', [id]);"],
    ["a static template literal", "await pool.query(`SELECT 1`);"],
    ["a non-SQL interpolated .get()", "await axios.get(`https://api.example.com/items/${id}`);"],
  ])("does NOT flag %s", async (_label, code) => {
    expect(await ruleIds(code)).toEqual([]);
  });
});

describe("dangerousCodeDetector — INJECT-03 dynamic code / shell execution", () => {
  it.each([
    ["eval of a variable", "const result = eval(code);"],
    ["new Function from input", "const fn = new Function('a', body);"],
    ["vm.runInNewContext of input", "vm.runInNewContext(userScript, sandbox);"],
    ["exec with an interpolated command", "exec(`convert ${file} out.png`);"],
    ["execSync with concatenation", "execSync('git clone ' + repoUrl);"],
  ])("flags %s", async (_label, code) => {
    expect(await ruleIds(code)).toEqual(["INJECT-03"]);
  });

  it.each([
    ["eval of a literal", "eval('1 + 1');"],
    ["a static exec command", "exec('ls -la');"],
    ["regex.exec", "const m = /a(b)/.exec(input);"],
    ["a method named eval on an object", "math.eval(expression);"],
  ])("does NOT flag %s", async (_label, code) => {
    expect(await ruleIds(code)).toEqual([]);
  });
});

describe("dangerousCodeDetector — AUTH-06 unverified JWT", () => {
  it("flags jwt.decode in a file that never verifies a token", async () => {
    const code = ["import jwt from 'jsonwebtoken';", "export function userId(t) { return jwt.decode(t).sub; }"].join("\n");

    const findings = await dangerousCodeDetector.detect(makeContext(code, "lib/auth.ts"));

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ ruleId: "AUTH-06", category: "auth", severity: "HIGH", line: 2 });
  });

  it("does NOT flag jwt.decode when the file also calls jwt.verify", async () => {
    const code = "jwt.verify(t, secret); const header = jwt.decode(t, { complete: true });";

    expect(await ruleIds(code, "lib/auth.ts")).toEqual([]);
  });

  it("does NOT flag the client-side jwt-decode library", async () => {
    expect(await ruleIds("const claims = jwtDecode(token);", "components/Avatar.tsx")).toEqual([]);
  });
});

describe("dangerousCodeDetector — guards", () => {
  it("skips test files and unparseable files", async () => {
    expect(await ruleIds("eval(code);", "src/lib/thing.test.ts")).toEqual([]);
    const ctx = { ...makeContext("eval(code);"), ast: undefined };
    expect(await dangerousCodeDetector.detect(ctx)).toEqual([]);
  });
});

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

describe("dangerousCodeDetector — INJECT-04 SSRF", () => {
  it.each([
    ["a URL from searchParams", 'const target = new URL(req.url).searchParams.get("url");\nconst r = await fetch(target);'],
    ["a URL destructured from the JSON body", "const { url } = await req.json();\nawait axios.get(url);"],
    ["a URL two variables away", "const body = await request.json();\nconst target = body.webhookUrl;\nawait fetch(target, { method: 'POST' });"],
    ["an Express query param", "app.get('/proxy', async (req, res) => { const r = await got(req.query.url); res.send(r.body); });"],
    ["a request-controlled host in a template", "const host = req.query.host;\nawait fetch(`https://${host}/internal/status`);"],
    ["axios with an options object", "await axios({ method: 'get', url: req.body.callback });"],
    ["Hono c.req.query", "app.get('/img', async (c) => fetch(c.req.query('src')));"],
  ])("flags %s", async (_label, code) => {
    expect(await ruleIds(code, "app/api/proxy/route.ts")).toEqual(["INJECT-04"]);
  });

  it.each([
    ["a fixed origin with a request-controlled path", "const id = req.query.id;\nawait fetch(`https://api.example.com/items/${id}`);"],
    ["a constant URL", "await fetch(process.env.API_URL + '/health');"],
    ["a URL checked against an allowlist", "const u = new URL(req.query.url);\nif (!ALLOWED_HOSTS.includes(u.hostname)) throw new Error();\nawait fetch(u);"],
  ])("does NOT flag %s", async (_label, code) => {
    expect(await ruleIds(code, "app/api/proxy/route.ts")).toEqual([]);
  });

  it("does NOT flag client components (the request runs in the user's browser)", async () => {
    const code = '"use client";\nconst q = useSearchParams();\nfetch(q.get("url"));';

    expect(await ruleIds(code, "app/viewer/page.tsx")).toEqual([]);
    expect(await ruleIds('const q = useSearchParams();\nfetch(q.get("url"));', "components/Viewer.tsx")).toEqual([]);
  });
});

describe("dangerousCodeDetector — REDIRECT-01 open redirect", () => {
  async function summarize(code: string, filePath = "app/login/route.ts"): Promise<string[]> {
    const findings = await dangerousCodeDetector.detect(makeContext(code, filePath));
    return findings.map((finding) => `${finding.ruleId} ${finding.severity} L${String(finding.line)}`);
  }

  it.each([
    ["Next.js redirect() of searchParams", 'const next = req.nextUrl.searchParams.get("next");\nredirect(next);'],
    ["NextResponse.redirect(new URL(next, req.url))", 'const next = searchParams.get("next");\nreturn NextResponse.redirect(new URL(next, req.url));'],
    ["Express res.redirect(req.query.returnTo)", "app.get('/cb', (req, res) => res.redirect(req.query.returnTo));"],
    ["Express res.redirect with a status first", "res.redirect(302, req.query.to);"],
    ["a client router.push of a query param", 'const params = useSearchParams();\nrouter.push(params.get("redirect"));'],
    ["window.location.href assignment", 'const target = new URLSearchParams(location.search).get("next");\nwindow.location.href = target;'],
  ])("flags %s as MEDIUM", async (_label, code) => {
    const result = await summarize(code);
    expect(result).toHaveLength(1);
    expect(result[0]).toMatch(/^REDIRECT-01 MEDIUM/);
  });

  it.each([
    ["a fixed path", "redirect('/dashboard');"],
    ["a fixed path prefix with a query value", 'const id = searchParams.get("id");\nredirect(`/orders/${id}`);'],
    ["a validated target", 'const next = searchParams.get("next");\nif (!next.startsWith("/") || next.startsWith("//")) throw new Error();\nredirect(next);'],
    ["array push of a request value", "const items = [];\nitems.push(req.query.item);"],
    ["string replace of a request value", "const s = req.query.q.replace(/a/g, 'b');"],
  ])("does NOT flag %s", async (_label, code) => {
    expect(await summarize(code)).toEqual([]);
  });
});

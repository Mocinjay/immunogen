import { describe, expect, it } from "vitest";

import { pyGoCodeDetector } from "./py-go-code-detector.js";

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

async function ruleIds(content: string, filePath: string): Promise<string[]> {
  const ctx: DetectorContext = { filePath, content, stackHints: STACK_HINTS, fileSet: new Map([[filePath, content]]) };
  return (await pyGoCodeDetector.detect(ctx)).map((finding) => finding.ruleId);
}

describe("pyGoCodeDetector — Python", () => {
  it.each([
    ["an f-string execute", 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")'],
    ["%-formatting", 'cur.execute("DELETE FROM t WHERE id = %s" % item_id)'],
    ["concatenation", "cur.execute('UPDATE users SET name = ' + name)"],
    [".format()", 'db.execute("SELECT * FROM t WHERE x = {}".format(x))'],
    ["SQLAlchemy text(f...)", 'session.execute(text(f"select * from orders where user = \'{u}\'"))'],
    ["Django .raw(f...)", 'User.objects.raw(f"SELECT * FROM auth_user WHERE email = \'{email}\'")'],
    ["a triple-quoted f-string", 'cursor.execute(f"""\n    SELECT * FROM notes WHERE id = {note_id}\n""")'],
  ])("flags SQL injection via %s", async (_label, code) => {
    expect(await ruleIds(code, "app/db.py")).toEqual(["INJECT-02"]);
  });

  it.each([
    ["a parameterized execute", 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))'],
    ["a static text()", 'session.execute(text("select 1"))'],
    ["an f-string that is not SQL", 'logger.execute(f"running {job}")'],
  ])("does NOT flag %s", async (_label, code) => {
    expect(await ruleIds(code, "app/db.py")).toEqual([]);
  });

  it.each([
    ["eval of input", "result = eval(expression)"],
    ["exec of input", "exec(user_code)"],
    ["os.system with an f-string", 'os.system(f"convert {path} out.png")'],
    ["subprocess shell=True with an f-string", 'subprocess.run(f"git clone {url}", shell=True)'],
    ["yaml.load without SafeLoader", "data = yaml.load(request.data)"],
    ["pickle.loads of request data", "obj = pickle.loads(request.body)"],
  ])("flags code execution via %s", async (_label, code) => {
    expect(await ruleIds(code, "app/views.py")).toEqual(["INJECT-03"]);
  });

  it.each([
    ["model.eval()", "model.eval()"],
    ["ast.literal_eval", "value = ast.literal_eval(text)"],
    ["eval of a literal", "eval('1 + 1')"],
    ["subprocess with an argument list", "subprocess.run(['git', 'clone', url])"],
    ["yaml.load with SafeLoader", "yaml.load(f, Loader=yaml.SafeLoader)"],
    ["yaml.safe_load", "yaml.safe_load(f)"],
  ])("does NOT flag %s", async (_label, code) => {
    expect(await ruleIds(code, "app/views.py")).toEqual([]);
  });

  it("flags PyJWT decode with verification disabled", async () => {
    expect(await ruleIds('claims = jwt.decode(token, options={"verify_signature": False})', "app/auth.py")).toEqual([
      "AUTH-06",
    ]);
    expect(await ruleIds('claims = jwt.decode(token, key, algorithms=["HS256"])', "app/auth.py")).toEqual([]);
  });

  it("skips tests and comments", async () => {
    expect(await ruleIds("eval(code)", "tests/test_eval.py")).toEqual([]);
    expect(await ruleIds("# eval(code)", "app/x.py")).toEqual([]);
  });
});

describe("pyGoCodeDetector — Go", () => {
  it.each([
    ["Query with fmt.Sprintf", 'rows, err := db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %s", id))'],
    ["QueryContext with ctx", 'rows, err := db.QueryContext(ctx, fmt.Sprintf("SELECT * FROM t WHERE name = \'%s\'", name))'],
    ["Exec with concatenation", 'db.Exec("DELETE FROM sessions WHERE token = \'" + tok + "\'")'],
    ["sqlx Get with a destination", 'db.Get(&user, fmt.Sprintf("SELECT * FROM users WHERE email = \'%s\'", email))'],
  ])("flags SQL injection via %s", async (_label, code) => {
    expect(await ruleIds(code, "internal/store.go")).toEqual(["INJECT-02"]);
  });

  it("does NOT flag a parameterized query", async () => {
    expect(await ruleIds('db.Query("SELECT * FROM users WHERE id = $1", id)', "internal/store.go")).toEqual([]);
  });

  it("flags a shell with a non-literal command, but not a literal one", async () => {
    expect(await ruleIds('out, _ := exec.Command("sh", "-c", "convert "+path).Output()', "main.go")).toEqual(["INJECT-03"]);
    expect(await ruleIds('exec.Command("sh", "-c", "ls -la")', "main.go")).toEqual([]);
    expect(await ruleIds('exec.Command("convert", path, "out.png")', "main.go")).toEqual([]);
  });

  it("flags ParseUnverified only when the file never verifies", async () => {
    expect(await ruleIds("token, _, err := parser.ParseUnverified(raw, claims)", "auth.go")).toEqual(["AUTH-06"]);
    const both = "parser.ParseUnverified(raw, claims)\njwt.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) { return key, nil })";
    expect(await ruleIds(both, "auth.go")).toEqual([]);
  });

  it("skips _test.go files", async () => {
    expect(await ruleIds('db.Query(fmt.Sprintf("SELECT %s", x))', "store_test.go")).toEqual([]);
  });
});

describe("pyGoCodeDetector — INJECT-04 SSRF", () => {
  it.each([
    ["requests.get of request.args", 'r = requests.get(request.args.get("url"))', "app.py"],
    ["a variable assigned from request.json", 'target = request.json["webhook"]\nhttpx.post(target, json=payload)', "app.py"],
    ["a FastAPI url: str parameter", '@app.get("/preview")\nasync def preview(url: str):\n    return requests.get(url).text', "main.py"],
    ["urlopen of a request value", "u = request.args['u']\nurlopen(u)", "app.py"],
    ["an f-string whose host is request-controlled", 'host = request.args.get("h")\nrequests.get(f"https://{host}/status")', "app.py"],
    ["Go http.Get of r.URL.Query()", 'target := r.URL.Query().Get("url")\nresp, err := http.Get(target)', "main.go"],
    ["Go NewRequest with c.Query", 'u := c.Query("url")\nreq, _ := http.NewRequest("GET", u, nil)', "main.go"],
  ])("flags %s", async (_label, code, path) => {
    expect(await ruleIds(code, path)).toEqual(["INJECT-04"]);
  });

  it.each([
    ["a fixed URL", 'requests.get("https://api.example.com/items")', "app.py"],
    ["a fixed host with a request-controlled path", 'item = request.args.get("id")\nrequests.get(f"https://api.example.com/items/{item}")', "app.py"],
    ["an allowlisted host", 'u = request.args.get("url")\nif urlparse(u).hostname not in ALLOWED_HOSTS: abort(400)\nrequests.get(u)', "app.py"],
    ["Flask session.get of a literal key", 'user = session.get("user")', "app.py"],
    ["a Go constant URL", 'resp, err := http.Get("https://example.com")', "main.go"],
  ])("does NOT flag %s", async (_label, code, path) => {
    expect(await ruleIds(code, path)).toEqual([]);
  });
});

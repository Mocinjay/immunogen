import { describe, expect, it } from "vitest";

import { pyGoRouteAuthDetector } from "./py-go-route-auth-detector.js";

import type { DetectorContext, StackHints } from "../../core/types.js";

const BASE_STACK: StackHints = {
  frameworks: new Set(),
  hasSupabase: false,
  hasFirebase: false,
  hasStripe: false,
  hasEnvFiles: false,
  hasMcpJson: false,
  hasClaudeSkills: false,
  hasCursorRules: false,
};

const stack = (...frameworks: string[]): StackHints => ({ ...BASE_STACK, frameworks: new Set(frameworks) });

async function summarize(
  content: string,
  filePath: string,
  stackHints: StackHints,
  otherFiles: Record<string, string> = {},
): Promise<string[]> {
  const ctx: DetectorContext = {
    filePath,
    content,
    stackHints,
    fileSet: new Map([[filePath, content], ...Object.entries(otherFiles)]),
  };
  return (await pyGoRouteAuthDetector.detect(ctx)).map(
    (finding) => `${finding.severity} ${finding.matchedText ?? ""} L${String(finding.line)}`,
  );
}

describe("pyGoRouteAuthDetector — FastAPI", () => {
  const FASTAPI = stack("python", "fastapi");

  it("flags unauthenticated routes: mutations CRITICAL, GET HIGH", async () => {
    const content = [
      "app = FastAPI()",
      "",
      '@app.post("/api/orders")',
      "async def create_order(order: Order):",
      "    return await db.orders.insert(order)",
      "",
      '@app.get("/api/orders")',
      "def list_orders():",
      "    return db.orders.all()",
    ].join("\n");

    expect(await summarize(content, "main.py", FASTAPI)).toEqual([
      "CRITICAL POST /api/orders L3",
      "HIGH GET /api/orders L7",
    ]);
  });

  it.each([
    [
      "a Depends(get_current_user) parameter",
      ['@app.post("/api/orders")', "async def create(order: Order, user: User = Depends(get_current_user)):", "    ..."],
    ],
    [
      "a multi-line signature with Security()",
      ['@app.delete("/api/orders/{id}")', "async def delete(", "    id: int,", "    user=Security(verify_token),", "):", "    ..."],
    ],
    ["route dependencies=[...]", ['@app.post("/x", dependencies=[Depends(require_admin)])', "def x():", "    ..."]],
    [
      "an APIRouter created with auth dependencies",
      ["router = APIRouter(dependencies=[Depends(get_current_user)])", '@router.post("/x")', "def x():", "    ..."],
    ],
    ["a public-by-nature path", ['@app.post("/auth/login")', "def login(form: Form):", "    ..."]],
    ["a # public comment", ["# public", '@app.post("/newsletter")', "def subscribe(email: str):", "    ..."]],
  ])("does NOT flag a route protected by %s", async (_label, lines) => {
    expect(await summarize(lines.join("\n"), "main.py", FASTAPI)).toEqual([]);
  });
});

describe("pyGoRouteAuthDetector — Flask", () => {
  const FLASK = stack("python", "flask");

  it("flags an unprotected route with methods=[...], one finding per method", async () => {
    const content = ['@bp.route("/items/<id>", methods=["PUT", "DELETE"])', "def item(id):", "    return update(id)"].join(
      "\n",
    );

    expect(await summarize(content, "app/views.py", FLASK)).toEqual(["CRITICAL PUT /items/<id> L1", "CRITICAL DELETE /items/<id> L1"]);
  });

  it.each([
    ["@login_required", ['@app.route("/admin", methods=["POST"])', "@login_required", "def admin():", "    ..."]],
    ["@jwt_required()", ['@app.post("/api/x")', "@jwt_required()", "def x():", "    ..."]],
    ["a current_user read", ['@app.post("/api/x")', "def x():", "    if not current_user.is_authenticated:", "        abort(401)"]],
    [
      "an auth before_request hook",
      ["@app.before_request", "def check():", "    if not session.get('user'):", "        abort(401)", '@app.post("/x")', "def x():", "    ..."],
    ],
  ])("does NOT flag a route protected by %s", async (_label, lines) => {
    expect(await summarize(lines.join("\n"), "app.py", FLASK)).toEqual([]);
  });
});

describe("pyGoRouteAuthDetector — Go", () => {
  const GIN = stack("go", "gin");

  it("flags unprotected Gin routes", async () => {
    const content = [
      "r := gin.Default()",
      'r.POST("/api/orders", createOrder)',
      'r.GET("/api/orders", func(c *gin.Context) {',
      "\tc.JSON(200, listOrders())",
      "})",
    ].join("\n");

    expect(await summarize(content, "main.go", GIN)).toEqual(["CRITICAL POST /api/orders L2", "HIGH GET /api/orders L3"]);
  });

  it("names net/http and treats a method-less HandleFunc as HIGH; reads Go 1.22 method patterns", async () => {
    const findings = [
      'mux.HandleFunc("/api/reset", resetHandler)',
      'mux.HandleFunc("DELETE /api/users/{id}", deleteUser)',
    ].join("\n");

    expect(await summarize(findings, "main.go", stack("go"))).toEqual(["HIGH ANY /api/reset L1", "CRITICAL DELETE /api/users/{id} L2"]);
  });

  it.each([
    ["a middleware argument", 'r.POST("/api/x", AuthRequired(), createX)'],
    ["a group created with auth", 'admin := r.Group("/admin", AuthMiddleware())\nadmin.POST("/reset", reset)'],
    ["a group given auth with Use", 'api := r.Group("/api")\napi.Use(JWTAuth())\napi.POST("/x", createX)'],
    ["a router-wide auth Use before the route", 'r.Use(authMiddleware)\nr.POST("/api/x", createX)'],
    ["a wrapping auth call (net/http)", 'mux.Handle("/api/x", requireAuth(http.HandlerFunc(createX)))'],
    ["an inline handler that reads the user", 'r.POST("/api/x", func(c *gin.Context) {\n\tuser := c.MustGet("user")\n\t_ = user\n})'],
    ["a public path", 'r.POST("/login", login)'],
  ])("does NOT flag a route protected by %s", async (_label, content) => {
    expect(await summarize(content, "main.go", GIN)).toEqual([]);
  });

  it("follows a named handler into another Go file to find its identity check", async () => {
    const content = 'r.POST("/api/x", h.CreateX)';
    const handlers = 'package api\n\nfunc (h *Handler) CreateX(c *gin.Context) {\n\tuid := c.GetString("user")\n\tc.Get("user")\n}\n';

    expect(await summarize(content, "main.go", GIN, { "api/handlers.go": handlers })).toEqual([]);
  });

  it("downgrades to MEDIUM/LOW when another Go file registers auth middleware", async () => {
    const result = await summarize('admin.POST("/reset", reset)', "routes/admin.go", GIN, {
      "main.go": "r.Use(AuthMiddleware())",
    });

    expect(result).toEqual(["MEDIUM POST /reset L1"]);
  });
});

describe("pyGoRouteAuthDetector — gates", () => {
  it("does not run on Python without FastAPI/Flask, or on Go without a go.mod stack", async () => {
    expect(await summarize('@app.post("/x")\ndef x():\n    ...', "main.py", stack("python", "django"))).toEqual([]);
    expect(await summarize('r.POST("/x", h)', "main.go", stack())).toEqual([]);
  });

  it("skips test files", async () => {
    expect(await summarize('r.POST("/x", h)', "main_test.go", stack("go"))).toEqual([]);
    expect(await summarize('@app.post("/x")\ndef x():\n    ...', "tests/test_api.py", stack("python", "fastapi"))).toEqual([]);
  });
});

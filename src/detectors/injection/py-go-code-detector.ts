/**
 * pyGoCodeDetector — the dangerous-code rules (INJECT-02 SQL injection,
 * INJECT-03 code/shell execution and unsafe deserialization, AUTH-06
 * unverified JWT) for Python and Go source. dangerous-code-detector.ts
 * covers JavaScript/TypeScript with a real AST; Python and Go have no parser
 * in this project, so these rules are line-oriented text patterns kept
 * deliberately narrow — each requires both the risky API and the risky
 * argument shape on the same line.
 *
 * Python:
 *   INJECT-02 `cursor.execute(f"SELECT ... {x}")`, `.execute("..." % x)`,
 *             `.execute("..." + x)`, `.execute("...".format(x))`,
 *             SQLAlchemy `text(f"...")`, Django `.raw(f"...")` /
 *             `.extra(where=[f"..."])` — whenever the string opens like SQL.
 *   INJECT-03 `eval(x)` / `exec(x)` with a non-literal argument,
 *             `os.system(...)` / `os.popen(...)` with a non-literal command,
 *             `subprocess.*(..., shell=True)` with an f-string/concatenated/
 *             formatted command, `yaml.load(...)` without a safe Loader,
 *             `pickle.loads(...)` / `marshal.loads(...)` of request data.
 *   AUTH-06   PyJWT `jwt.decode(..., options={"verify_signature": False})`
 *             or `verify=False`.
 *   INJECT-04 `requests` / `httpx` / `urllib` / aiohttp fetching a URL read
 *             from the request (`request.args`, `request.json`, a route
 *             parameter named like a URL), directly or via a local variable.
 * Go:
 *   INJECT-02 `db.Query(fmt.Sprintf("SELECT ...%s", x))` and the Exec/
 *             QueryRow/*Context/sqlx/gorm `Raw`/`Exec` variants, or a `"..." +`
 *             concatenation, when the string opens like SQL.
 *   INJECT-03 `exec.Command("sh"|"bash"|"cmd", "-c"|"/c", <non-literal>)`.
 *   AUTH-06   golang-jwt `ParseUnverified(` in a file that never calls a
 *             verifying `Parse`/`ParseWithClaims`.
 *   INJECT-04 `http.Get` / `http.Post` / `http.NewRequest*` with a URL read
 *             from the request (`r.URL.Query().Get`, `r.FormValue`, Gin/Echo/
 *             Fiber `c.Query`/`c.PostForm`/`c.Param`/`c.FormValue`).
 *
 *   REDIRECT-01 (both, MEDIUM) Flask/Django/FastAPI `redirect(...)`,
 *             `RedirectResponse(...)`, `HttpResponseRedirect(...)`, Go
 *             `http.Redirect(w, r, X, ...)`, Gin/Echo/Fiber `c.Redirect(...)`
 *             with a request-controlled target.
 *
 * SSRF is skipped in files that validate targets against an allowlist, and
 * REDIRECT-01 in files that validate redirect targets.
 *
 * All findings are HIGH/MEDIUM, matching the JS rules.
 *
 * Text-only (ENG-05): never evaluates scanned source.
 *
 * No-throw contract (src/core/types.ts Detector.detect): the whole body runs
 * inside a try/catch returning `[]` on any failure.
 */
import type { Category, Detector, DetectorContext, Finding } from "../../core/types.js";
import { isTestOrFixturePath } from "../shared/test-paths.js";

/** Static text that opens a SQL statement. */
const SQL_START_RE = /^\s*(?:select|insert|update|delete|with|replace|merge|upsert|create|drop|alter)\b/i;

type RuleId = "INJECT-02" | "INJECT-03" | "AUTH-06" | "INJECT-04" | "REDIRECT-01";

/** Message, remediation, and category per ruleId. */
const RULE_COPY: Record<RuleId, { category: Category; message: string; remediation: string }> = {
  "INJECT-02": {
    category: "injection",
    message: "SQL query built with string formatting/concatenation passed to a query API (possible SQL injection).",
    remediation:
      "Pass values as bound parameters instead of formatting them into the SQL text — e.g. cursor.execute('... where id = %s', (id,)), text('... where id = :id').bindparams(id=id), or db.Query(\"... where id = $1\", id).",
  },
  "INJECT-03": {
    category: "injection",
    message:
      "Dynamic code/shell execution or unsafe deserialization of a non-literal input (eval / exec / shell command / yaml.load / pickle) — possible remote code execution.",
    remediation:
      "Remove the dynamic evaluation: parse data with json / yaml.safe_load, map user choices to a fixed allowlist, and run subprocesses with an argument list (no shell) — subprocess.run([...]) / exec.Command(name, args...).",
  },
  "INJECT-04": {
    category: "injection",
    message:
      "Server-side request to a URL taken from the request (SSRF) — an attacker can make your server call internal services (cloud metadata at 169.254.169.254, localhost admin ports) and read the response.",
    remediation:
      "Never fetch a user-supplied URL directly: parse it, allow only an explicit list of hosts (and https), reject private/link-local addresses after DNS resolution, and disable redirects.",
  },
  "REDIRECT-01": {
    category: "injection",
    message:
      "Redirect target taken from the request (open redirect) — a link to your site can bounce users to a phishing page, and login flows can leak tokens to it.",
    remediation:
      "Only redirect to relative paths you control (Django: url_has_allowed_host_and_scheme; otherwise accept only values starting with a single \"/\") or map the value to an allowlist of destinations.",
  },
  "AUTH-06": {
    category: "auth",
    message: "JWT signature verification is disabled — anyone can forge a token claiming to be any user.",
    remediation:
      "Verify every token with its signing key (PyJWT: jwt.decode(token, key, algorithms=[...]); golang-jwt: jwt.Parse/ParseWithClaims with a key function) before trusting any claim.",
  },
};

/**
 * Python: a query call whose first argument is a string literal; captures
 * the f-prefix, the quote, and the rest. Matched against a line with any
 * Django `.extra(where=[` wrapper already stripped (see pythonSites).
 */
const PY_QUERY_CALL_RE = /(?:\.(?:execute|executemany|executescript|raw|extra)|\btext)\(\s*([fF]?)("""|'''|"|')(.*)$/;

/** True when a Python query string is assembled at runtime: an f-string with `{`, or `%` / `+` / `.format(` after the literal. */
function isDynamicPythonSql(fPrefix: string, quote: string, rest: string, nextLine: string): boolean {
  const closing = rest.indexOf(quote);
  const literal = closing === -1 ? rest : rest.slice(0, closing);
  const sqlText = literal.trim() === "" && quote.length === 3 ? nextLine : literal;
  if (!SQL_START_RE.test(sqlText)) {
    return false;
  }
  if (fPrefix !== "") {
    return /\{[^}]*\}/.test(literal.trim() === "" ? nextLine : literal) || closing === -1;
  }
  const after = closing === -1 ? "" : rest.slice(closing + quote.length);
  return /^\s*(?:%|\+|\.format\()/.test(after);
}

/** Python INJECT-03 patterns (each already requires a non-literal argument). */
const PY_EXEC_PATTERNS: readonly RegExp[] = [
  // eval/exec builtins with a non-literal argument (not `model.eval()`, not ast.literal_eval).
  /(?<![\w.])(?:eval|exec)\(\s*(?!["')]|f?["'])[\w([]/,
  // os.system / os.popen with a variable, f-string, or concatenation.
  /\bos\.(?:system|popen)\(\s*(?:[fF]["']|[\w(][^)]*\)|\w)/,
  // subprocess with shell=True and an f-string / formatted / concatenated / variable command.
  /\bsubprocess\.(?:run|call|Popen|check_output|check_call|getoutput|getstatusoutput)\(\s*(?:[fF]["']|\w[\w.]*\s*[,)]|["'][^"']*["']\s*(?:%|\+|\.format\())[^\n]*shell\s*=\s*True/,
  // yaml.load without a safe loader.
  /\byaml\.(?:load|load_all)\((?![^)]*Loader\s*=\s*(?:yaml\.)?(?:Safe|Base)Loader)[^)]*\)/,
  // pickle/marshal of request data.
  /\b(?:pickle|cPickle|marshal|dill)\.loads?\(\s*(?:request\.|req\.|data\b|payload\b|body\b|await\s+request\.)/,
];

/** PyJWT decode with signature verification disabled. */
const PY_JWT_UNVERIFIED_RE = /\bjwt\.decode\([^\n]*(?:["']verify_signature["']\s*:\s*False|\bverify\s*=\s*False)/;

/**
 * Go: a SQL call whose query argument is fmt.Sprintf(...) or a
 * concatenation; captures the format/literal text. Matched against a line
 * whose leading `ctx, ` / `&dest, ` call arguments are already stripped
 * (see goSites).
 */
const GO_QUERY_CALL_RE =
  /\.(?:Query|QueryRow|QueryContext|QueryRowContext|QueryRowx|Queryx|Exec|ExecContext|Raw|Select|Get|Prepare|PrepareContext|MustExec)\(\s*(?:fmt\.Sprintf\(\s*"([^"]*)"|"([^"]*)"\s*\+)/;

/** Go: a shell invoked with a non-literal command string. */
const GO_SHELL_EXEC_RE =
  /\bexec\.Command(?:Context)?\(\s*"(?:sh|bash|zsh|\/bin\/sh|\/bin\/bash|cmd|cmd\.exe|powershell)"\s*,\s*"(?:-c|\/c|-Command)"\s*,(?!\s*"[^"]*"\s*\))/;

/** Go: golang-jwt parse without verification, and a verifying parse that would make it a header peek. */
const GO_JWT_UNVERIFIED_RE = /\.ParseUnverified\(/;
const GO_JWT_VERIFIED_RE = /\bjwt\.Parse(?:WithClaims)?\(|\.Parse(?:WithClaims)?\(\s*\w+\s*,[^)]*func\s*\(/;

/** Python: request input. */
const PY_REQUEST_SOURCE_RE = /\brequest\.(?:args|form|json|values|query_params|GET|POST|data|get_json\(|path_params)/;

/** Python: a route parameter whose name says it carries a URL or redirect target (FastAPI binds query/body params to these). */
const PY_URL_PARAM_RE =
  /\b(url|uri|target|link|endpoint|callback|callback_url|webhook|webhook_url|image_url|src|href|feed_url|next|redirect|redirect_to|redirect_url|return_to|continue_url)\s*:\s*(?:str|HttpUrl|AnyUrl)/g;

/** Python: a redirect call, capturing its target argument (matched with any `url=` keyword already stripped). */
const PY_REDIRECT_CALL_RE = /\b(?:redirect|RedirectResponse|HttpResponseRedirect|HttpResponsePermanentRedirect)\(\s*([^,)\n]+)/;

/** Python: evidence the file validates redirect targets. */
const PY_REDIRECT_VALIDATION_RE =
  /url_has_allowed_host_and_scheme|is_safe_url|urlparse\([^)]*\)\.netloc|\.startswith\(\s*["']\/["']\s*\)|ALLOWED_REDIRECT|is_safe_redirect/i;

/** Go: redirect calls, capturing the target argument. */
const GO_REDIRECT_CALL_RES: readonly RegExp[] = [
  /\bhttp\.Redirect\(\s*\w+\s*,\s*\w+\s*,\s*([^,)\n]+)/,
  /\bc\.Redirect\(\s*(?:http\.Status\w+|\d+)\s*,\s*([^,)\n]+)/,
  /\bc\.Redirect\(\s*([^,)\n]+)\)/,
];

/** Go: evidence the file validates redirect targets. */
const GO_REDIRECT_VALIDATION_RE = /strings\.HasPrefix\([^,]+,\s*"\/"\)|\.Host\s*(?:==|!=)|\.Hostname\(\)\s*(?:==|!=)|isSafeRedirect|allowedRedirect/i;

/**
 * Python: an outbound HTTP call, capturing the first argument's leading
 * text. Matched against a line whose leading `"GET",` method argument
 * (`requests.request("GET", url)`) is already stripped (see pythonSites).
 */
const PY_HTTP_CALL_RE =
  /\b(?:requests|httpx|client|session|aiohttp\.ClientSession\(\)|urllib\.request|urllib3\.PoolManager\(\))\.(?:get|post|put|patch|delete|head|request|urlopen|stream)\(\s*([^,)\n]+)|\burlopen\(\s*([^,)\n]+)/;

/** Go: request input. */
const GO_REQUEST_SOURCE_RE = /\br\.URL\.Query\(\)\.Get\(|\br\.(?:FormValue|PostFormValue)\(|\bc\.(?:Query|PostForm|Param|QueryParam|FormValue|Params|DefaultQuery)\(/;

/** Go: an outbound HTTP call, capturing the URL argument. */
const GO_HTTP_CALL_RE =
  /\bhttp\.(?:Get|Head|Post|PostForm)\(\s*([^,)\n]+)|\bhttp\.NewRequest\(\s*[^,]+,\s*([^,)\n]+)|\bhttp\.NewRequestWithContext\(\s*[^,]+,\s*[^,]+,\s*([^,)\n]+)/;

/** Evidence that a file validates outbound targets — suppresses INJECT-04. */
const PY_GO_URL_ALLOWLIST_RE = /allowed_?(?:hosts|domains|urls)|ALLOWED_(?:HOSTS|DOMAINS|URLS)|is_?(?:allowed|safe)_?(?:url|host)|validate_?url|\.hostname\s+(?:not\s+in|in)\b|\.Hostname\(\)\s*(?:==|!=)|ssrf/i;

/**
 * Names assigned from request input on any line (`url = request.args.get("u")`,
 * `target := c.Query("url")`), iterated so a second hop (`u = url.strip()`) is
 * also caught, plus — for Python — route parameters named like a URL.
 */
function requestTaintedNames(lines: string[], source: RegExp, language: "py" | "go"): Set<string> {
  const tainted = new Set<string>();
  if (language === "py") {
    for (const match of lines.join("\n").matchAll(PY_URL_PARAM_RE)) {
      tainted.add(match[1] ?? "");
    }
  }
  // Go allows `url, err := ...`; the class after the name swallows `, err `.
  const assignment = language === "py" ? /^\s*(\w+)\s*=\s*(.+)$/ : /^\s*(\w+)[\s,\w]*:?=\s*(.+)$/;
  let changed = true;
  while (changed) {
    changed = false;
    for (const line of lines) {
      const match = line.match(assignment);
      const name = match?.[1];
      const value = match?.[2] ?? "";
      if (name === undefined || tainted.has(name)) {
        continue;
      }
      const usesTainted = (value.match(/\w+/g) ?? []).some((word) => tainted.has(word));
      if (source.test(value) || usesTainted) {
        tainted.add(name);
        changed = true;
      }
    }
  }
  return tainted;
}

/** True when an outbound call's URL argument text is request-controlled (a tainted name, a direct read, or an f-string/format whose host is). */
function isTaintedUrlArgument(argument: string, tainted: ReadonlySet<string>, source: RegExp): boolean {
  const text = argument.trim();
  const isStringLiteral = /^[fFrRbB]?["'`]/.test(text);
  if (!isStringLiteral && source.test(text)) {
    return true;
  }
  const leadingName = text.match(/^(?:str\()?(\w+)/)?.[1];
  if (leadingName !== undefined && tainted.has(leadingName)) {
    return true;
  }
  // f"{url}/x" / f"https://{host}/x" — only a leading (scheme/host) placeholder lets the request pick the target.
  const hostExpression = text.replace(/^([fF]["'])https?:\/\//, "$1").match(/^[fF]["']\{([^}]*)\}/)?.[1];
  if (hostExpression === undefined) {
    return false;
  }
  const hostName = hostExpression.match(/^\w+/)?.[0];
  return source.test(hostExpression) || (hostName !== undefined && tainted.has(hostName));
}

/** One matched line. */
interface Site {
  ruleId: RuleId;
  line: number;
  text: string;
}

/** Python rules over `lines`. */
function pythonSites(lines: string[]): Site[] {
  const sites: Site[] = [];
  const content = lines.join("\n");
  const checksSsrf = !PY_GO_URL_ALLOWLIST_RE.test(content);
  const checksRedirects = !PY_REDIRECT_VALIDATION_RE.test(content);
  const requestTainted = requestTaintedNames(lines, PY_REQUEST_SOURCE_RE, "py");
  const tainted = checksSsrf ? requestTainted : new Set<string>();
  for (const [index, line] of lines.entries()) {
    if (/^\s*#/.test(line)) {
      continue;
    }
    const query = line.replace(/\bwhere\s*=\s*\[\s*/, "").match(PY_QUERY_CALL_RE);
    if (query !== null && isDynamicPythonSql(query[1] ?? "", query[2] ?? '"', query[3] ?? "", lines.at(index + 1) ?? "")) {
      sites.push({ ruleId: "INJECT-02", line: index + 1, text: line });
    } else if (PY_EXEC_PATTERNS.some((pattern) => pattern.test(line))) {
      sites.push({ ruleId: "INJECT-03", line: index + 1, text: line });
    } else if (PY_JWT_UNVERIFIED_RE.test(line)) {
      sites.push({ ruleId: "AUTH-06", line: index + 1, text: line });
    } else if (checksSsrf) {
      const call = line.replace(/\(\s*["'](?:GET|POST|PUT|PATCH|DELETE)["']\s*,\s*/, "(").match(PY_HTTP_CALL_RE);
      const argument = call?.[1] ?? call?.[2];
      if (argument !== undefined && isTaintedUrlArgument(argument, tainted, PY_REQUEST_SOURCE_RE)) {
        sites.push({ ruleId: "INJECT-04", line: index + 1, text: line });
        continue;
      }
    }
    if (checksRedirects) {
      const target = line.replace(/\(\s*url\s*=\s*/, "(").match(PY_REDIRECT_CALL_RE)?.[1];
      if (target !== undefined && isTaintedUrlArgument(target, requestTainted, PY_REQUEST_SOURCE_RE)) {
        sites.push({ ruleId: "REDIRECT-01", line: index + 1, text: line });
      }
    }
  }
  return sites;
}

/** Go rules over `lines`. */
function goSites(lines: string[], content: string): Site[] {
  const sites: Site[] = [];
  const verifiesTokens = GO_JWT_VERIFIED_RE.test(content);
  const checksSsrf = !PY_GO_URL_ALLOWLIST_RE.test(content);
  const checksRedirects = !GO_REDIRECT_VALIDATION_RE.test(content);
  const allTainted = requestTaintedNames(lines, GO_REQUEST_SOURCE_RE, "go");
  const tainted = checksSsrf ? allTainted : new Set<string>();
  for (const [index, rawLine] of lines.entries()) {
    if (/^\s*\/\//.test(rawLine)) {
      continue;
    }
    // Drop leading context / destination arguments: Query(ctx, q), Get(&dest, q), CommandContext(ctx, ...).
    const line = rawLine.replace(/\(\s*ctx\s*,\s*/g, "(").replace(/\(\s*&\w+\s*,\s*/g, "(");
    const query = line.match(GO_QUERY_CALL_RE);
    if (query !== null && SQL_START_RE.test(query[1] ?? query[2] ?? "")) {
      sites.push({ ruleId: "INJECT-02", line: index + 1, text: rawLine });
    } else if (GO_SHELL_EXEC_RE.test(line)) {
      sites.push({ ruleId: "INJECT-03", line: index + 1, text: rawLine });
    } else if (GO_JWT_UNVERIFIED_RE.test(line) && !verifiesTokens) {
      sites.push({ ruleId: "AUTH-06", line: index + 1, text: rawLine });
    } else if (checksSsrf) {
      const call = line.match(GO_HTTP_CALL_RE);
      const argument = call?.[1] ?? call?.[2] ?? call?.[3];
      if (argument !== undefined && isTaintedUrlArgument(argument, tainted, GO_REQUEST_SOURCE_RE)) {
        sites.push({ ruleId: "INJECT-04", line: index + 1, text: rawLine });
        continue;
      }
    }
    if (checksRedirects) {
      const target = GO_REDIRECT_CALL_RES.map((pattern) => line.match(pattern)?.[1]).find((value) => value !== undefined);
      if (target !== undefined && isTaintedUrlArgument(target, allTainted, GO_REQUEST_SOURCE_RE)) {
        sites.push({ ruleId: "REDIRECT-01", line: index + 1, text: rawLine });
      }
    }
  }
  return sites;
}

export const pyGoCodeDetector: Detector = {
  config: {
    name: "py-go-code",
    category: "injection",
    globs: ["**/*.{py,go}"],
  },

  // Not declared `async`: synchronous text work wrapped in Promise.resolve().
  detect(ctx: DetectorContext): Promise<Finding[]> {
    try {
      if (isTestOrFixturePath(ctx.filePath)) {
        return Promise.resolve([]);
      }
      const lines = ctx.content.split("\n");
      const sites = ctx.filePath.endsWith(".go") ? goSites(lines, ctx.content) : pythonSites(lines);

      const findings: Finding[] = sites.map((site) => ({
        ruleId: site.ruleId,
        category: RULE_COPY[site.ruleId].category,
        detectorName: "py-go-code",
        file: ctx.filePath,
        line: site.line,
        severity: site.ruleId === "REDIRECT-01" ? "MEDIUM" : "HIGH",
        confidence: "MEDIUM",
        message: RULE_COPY[site.ruleId].message,
        remediation: RULE_COPY[site.ruleId].remediation,
        matchedText: site.text.trim().slice(0, 120),
      }));
      return Promise.resolve(findings);
    } catch {
      // No-throw contract (src/core/types.ts Detector.detect).
      return Promise.resolve([]);
    }
  },
};

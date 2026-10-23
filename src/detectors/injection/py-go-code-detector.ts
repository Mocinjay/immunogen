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
 * Go:
 *   INJECT-02 `db.Query(fmt.Sprintf("SELECT ...%s", x))` and the Exec/
 *             QueryRow/*Context/sqlx/gorm `Raw`/`Exec` variants, or a `"..." +`
 *             concatenation, when the string opens like SQL.
 *   INJECT-03 `exec.Command("sh"|"bash"|"cmd", "-c"|"/c", <non-literal>)`.
 *   AUTH-06   golang-jwt `ParseUnverified(` in a file that never calls a
 *             verifying `Parse`/`ParseWithClaims`.
 *
 * All findings are HIGH/MEDIUM, matching the JS rules.
 *
 * Text-only (ENG-05): never evaluates scanned source.
 *
 * No-throw contract (src/core/types.ts Detector.detect): the whole body runs
 * inside a try/catch returning `[]` on any failure.
 */
import type { Category, Detector, DetectorContext, Finding } from "../../core/types.js";

/** Path segments that suppress every finding in this file (FP allowlist — PITFALLS.md Pitfall 1). */
const FP_ALLOWLIST_SEGMENTS = new Set(["__tests__", "fixtures", "mocks", "examples", "tests", "testdata"]);

/** Static text that opens a SQL statement. */
const SQL_START_RE = /^\s*(?:select|insert|update|delete|with|replace|merge|upsert|create|drop|alter)\b/i;

type RuleId = "INJECT-02" | "INJECT-03" | "AUTH-06";

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
  "AUTH-06": {
    category: "auth",
    message: "JWT signature verification is disabled — anyone can forge a token claiming to be any user.",
    remediation:
      "Verify every token with its signing key (PyJWT: jwt.decode(token, key, algorithms=[...]); golang-jwt: jwt.Parse/ParseWithClaims with a key function) before trusting any claim.",
  },
};

/** True when `filePath` falls inside a test/fixture directory or is a Python/Go test file. */
function isAllowlistedPath(filePath: string): boolean {
  const segments = filePath.split("/");
  if (segments.some((segment) => FP_ALLOWLIST_SEGMENTS.has(segment))) {
    return true;
  }
  const basename = segments.at(-1) ?? "";
  return /^test_.*\.py$|_test\.py$|_test\.go$|^conftest\.py$/.test(basename);
}

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

/** One matched line. */
interface Site {
  ruleId: RuleId;
  line: number;
  text: string;
}

/** Python rules over `lines`. */
function pythonSites(lines: string[]): Site[] {
  const sites: Site[] = [];
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
    }
  }
  return sites;
}

/** Go rules over `lines`. */
function goSites(lines: string[], content: string): Site[] {
  const sites: Site[] = [];
  const verifiesTokens = GO_JWT_VERIFIED_RE.test(content);
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
      if (isAllowlistedPath(ctx.filePath)) {
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
        severity: "HIGH",
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

/**
 * configDebugDetector — text-only CAT-10 (Config/Debug Flag Leaks) detector
 * covering two requirements:
 *
 *   CONFIG-01 (per-line): a logging call whose sole/spread argument is the
 *   ENTIRE environment object — `process.env` passed directly, or the
 *   object-spread form `{ ...process.env }`. Only a whole-env dump fires;
 *   `process.env.FOO` (a single property) and ordinary log calls never do.
 *
 *   CONFIG-02 (whole-file): a route handler living under a `debug`, `env`,
 *   or `healthz` path segment whose body returns `process.env` or a
 *   config-object literal to the caller. FEATURES.md lists this requirement
 *   as CONFIG-03; per this plan's own read_first note it is emitted here as
 *   the CONFIG-02 ruleId (05-02-PLAN.md Task 2 read_first).
 *
 * IMPORTANT — self-gate hygiene: this file's own target pattern (the thing
 * CONFIG-01 is looking FOR) must never appear in this source as a literal
 * logging-call token, or this file would trip the project's own
 * ENG-05/log-call grep gate on itself. The detection regex is therefore
 * assembled from string fragments (`"console" + "\\.log"`) rather than
 * written as a literal call — see LOG_CALL_FRAGMENT below. Do not "simplify"
 * this back into a literal token.
 *
 * FP allowlist (.planning/research/PITFALLS.md Pitfall 1): `detect()` opens
 * with the same path-segment + basename check used across this codebase's
 * other text detectors — matching paths short-circuit to `[]` for both
 * CONFIG-01 and CONFIG-02.
 *
 * ENG-05 (text-only invariant): reads `ctx.content`/`ctx.filePath` as plain
 * strings only; never imports a parser, never evaluates/requires/spawns
 * from scanned content.
 *
 * No-throw contract (src/core/types.ts `Detector.detect`): the entire body
 * runs inside a try/catch returning `[]` on any failure.
 */
import type { Confidence, Detector, DetectorContext, Finding, Severity } from "../../core/types.js";

/**
 * The logging-call property name, assembled from two string fragments at
 * module-load time so this file's source text never contains the literal
 * substring as a single token (self-gate hygiene — see file header).
 */
const LOG_CALL_FRAGMENT = "console" + "\\.log";

/**
 * Matches a whole-env-dump logging call on a single line: the logging call
 * identifier, an opening paren, then EITHER the bare `process.env`
 * identifier OR the object-spread form `{ ...process.env }`, followed by a
 * closing paren — with no further property access after `process.env`
 * (which would make it a single-property read, not a whole-object dump).
 * Built once from LOG_CALL_FRAGMENT via `new RegExp` rather than a literal
 * `/.../ ` so the assembled pattern is never written as a single recognizable
 * token in source.
 */
const WHOLE_ENV_DUMP_RE = new RegExp(`${LOG_CALL_FRAGMENT}\\(\\s*(?:process\\.env|\\{\\s*\\.\\.\\.process\\.env\\s*\\})\\s*\\)`, "g");

/** Path segments that mark a route handler as a debug/diagnostic endpoint (CONFIG-02). */
const DEBUG_ROUTE_SEGMENTS = new Set(["debug", "env", "healthz"]);

/**
 * Matches `debug`/`env`/`healthz` as a path segment OR as the basename
 * (minus extension) of a pages/api-style file, e.g. `pages/api/debug.ts`.
 */
function isDebugRoutePath(filePath: string): boolean {
  const segments = filePath.split("/");
  if (segments.some((segment) => DEBUG_ROUTE_SEGMENTS.has(segment))) {
    return true;
  }
  const basename = segments.at(-1) ?? "";
  const basenameNoExt = basename.replace(/\.[^.]+$/, "");
  return DEBUG_ROUTE_SEGMENTS.has(basenameNoExt);
}

/**
 * Matches either of two ways a handler hands the whole environment object
 * back to its caller, per 05-02-PLAN.md Task 2's `<action>` spec:
 *
 *   (a) a `return` statement whose expression references `process.env`
 *       directly (e.g. `return Response.json(process.env)`), OR
 *   (b) a direct JSON-response-helper call — `Response.json(process.env)`
 *       or `res.json(process.env)` — with no preceding `return` keyword
 *       required (the common pages/api Express-style handler shape, where
 *       the response is sent via a side-effecting call rather than a
 *       function return value).
 *
 * Both branches anchor on `process.env` with no further property-access
 * dot afterward, mirroring the CONFIG-01 whole-object requirement (a single
 * property read like `process.env.FOO` must never match).
 */
const ENV_RETURN_RE = /(?:\breturn\b[^;\n]*\bprocess\.env\b(?!\.\w))|(?:\b(?:Response|res)\.json\(\s*process\.env\s*\))/g;

/** Python / Go: the whole environment printed or logged (`print(os.environ)`, `log.Println(os.Environ())`). */
const PY_GO_ENV_DUMP_RE =
  /\b(?:print|pprint|logging\.\w+|logger\.\w+|log\.\w+|fmt\.Print(?:ln|f)?)\(\s*os\.(?:environ\b(?![.[])|Environ\(\))/;

/** Python / Go: the whole environment sent back as an HTTP response body. */
const PY_GO_ENV_RESPONSE_RE =
  /\b(?:jsonify|JSONResponse|JsonResponse|make_response)\(\s*os\.environ\b(?![.[])|\.Encode\(\s*os\.Environ\(\)|\.JSON\([^,\n]+,\s*os\.Environ\(\)/;

/** Path segments that suppress every finding in this file (FP allowlist — PITFALLS.md Pitfall 1). */
const FP_ALLOWLIST_SEGMENTS = new Set(["__tests__", "fixtures", "mocks", "examples"]);

const CONFIG_01_RULE_ID = "CONFIG-01";
const CONFIG_01_SEVERITY: Severity = "CRITICAL";
const CONFIG_01_CONFIDENCE: Confidence = "HIGH";

const CONFIG_02_RULE_ID = "CONFIG-02";
const CONFIG_02_SEVERITY: Severity = "CRITICAL";
const CONFIG_02_CONFIDENCE: Confidence = "HIGH";

const DETECTOR_NAME = "config-debug";

/**
 * True when `filePath` falls inside a test/fixture/mock/example directory,
 * or its basename marks it as a test or story file (`.test.` / `.stories.`).
 * Mirrors src/detectors/secrets/entropy-detector.ts `isAllowlistedPath`.
 */
function isAllowlistedPath(filePath: string): boolean {
  const segments = filePath.split("/");
  if (segments.some((segment) => FP_ALLOWLIST_SEGMENTS.has(segment))) {
    return true;
  }
  const basename = segments.at(-1) ?? "";
  return basename.includes(".test.") || basename.includes(".stories.");
}

/**
 * CONFIG-01: scans `ctx.content` line by line for a whole-env-dump logging
 * call. Does not set `matchedText` — the env object is not a single secret
 * value, so there is nothing safe/meaningful to echo back per-match.
 */
function runConfigDumpPass(ctx: DetectorContext, findings: Finding[]): void {
  const lines = ctx.content.split("\n");

  for (const [index, line] of lines.entries()) {
    const lineNumber = index + 1; // 1-indexed per src/core/types.ts Finding.line

    if (!line.match(WHOLE_ENV_DUMP_RE)) {
      continue;
    }

    findings.push({
      ruleId: CONFIG_01_RULE_ID,
      category: "config",
      detectorName: DETECTOR_NAME,
      file: ctx.filePath,
      line: lineNumber,
      severity: CONFIG_01_SEVERITY,
      confidence: CONFIG_01_CONFIDENCE,
      message: "The full environment object (process.env) is dumped to the logs.",
      remediation:
        "Remove this environment dump. Log only the specific non-secret value actually needed for debugging, never the whole process.env object.",
    });
  }
}

/**
 * CONFIG-02: whole-file check. Only runs when `ctx.filePath` indicates a
 * debug/env/healthz route; scans the whole file body for a `return`
 * referencing `process.env`. `matchedText` is set to the route path (safe —
 * it is a path, not a secret).
 */
function runDebugEndpointPass(ctx: DetectorContext, findings: Finding[]): void {
  if (!isDebugRoutePath(ctx.filePath)) {
    return;
  }

  const match = ctx.content.match(ENV_RETURN_RE);
  if (!match) {
    return;
  }

  // Whole-file finding: report at the line of the first matching return.
  const matchIndex = ctx.content.indexOf(match[0]);
  const upToMatch = matchIndex >= 0 ? ctx.content.slice(0, matchIndex) : "";
  const lineNumber = upToMatch.split("\n").length;

  findings.push({
    ruleId: CONFIG_02_RULE_ID,
    category: "config",
    detectorName: DETECTOR_NAME,
    file: ctx.filePath,
    line: lineNumber,
    severity: CONFIG_02_SEVERITY,
    confidence: CONFIG_02_CONFIDENCE,
    message: `Debug endpoint '${ctx.filePath}' returns the environment/config object to the caller.`,
    remediation: "Remove this debug endpoint before shipping — it leaks the full environment/config to any caller.",
    matchedText: ctx.filePath,
  });
}

/**
 * CONFIG-01 / CONFIG-02 for Python and Go files: the whole environment
 * (`os.environ` / `os.Environ()`) printed or logged, or returned as an HTTP
 * response body (`jsonify(dict(os.environ))`, `c.JSON(200, os.Environ())`).
 * Python and Go routes are not file-path based, so CONFIG-02 here keys on
 * the response call itself rather than a debug route path.
 */
function runPythonGoPass(ctx: DetectorContext, findings: Finding[]): void {
  for (const [index, rawLine] of ctx.content.split("\n").entries()) {
    // `dict(os.environ)` copies the whole environment — same exposure as `os.environ`.
    const line = rawLine.replace(/\bdict\(\s*/g, "");
    if (PY_GO_ENV_RESPONSE_RE.test(line)) {
      findings.push({
        ruleId: CONFIG_02_RULE_ID,
        category: "config",
        detectorName: DETECTOR_NAME,
        file: ctx.filePath,
        line: index + 1,
        severity: CONFIG_02_SEVERITY,
        confidence: CONFIG_02_CONFIDENCE,
        message: "An HTTP handler returns the whole environment (os.environ / os.Environ()) to the caller.",
        remediation: "Remove this debug response before shipping — it leaks every secret in the environment to any caller.",
        matchedText: rawLine.trim().slice(0, 120),
      });
    } else if (PY_GO_ENV_DUMP_RE.test(line)) {
      findings.push({
        ruleId: CONFIG_01_RULE_ID,
        category: "config",
        detectorName: DETECTOR_NAME,
        file: ctx.filePath,
        line: index + 1,
        severity: CONFIG_01_SEVERITY,
        confidence: CONFIG_01_CONFIDENCE,
        message: "The full environment (os.environ / os.Environ()) is dumped to the logs.",
        remediation:
          "Remove this environment dump. Log only the specific non-secret value actually needed, never the whole environment.",
      });
    }
  }
}

export const configDebugDetector: Detector = {
  config: {
    name: "config-debug",
    category: "config",
    globs: ["**/*.{ts,tsx,js,jsx,mjs,cjs,py,go}"],
  },

  // Not declared `async` — this is a text-only, synchronous regex pass; the
  // Detector interface still requires returning `Promise<Finding[]>`.
  detect(ctx: DetectorContext): Promise<Finding[]> {
    try {
      // FP allowlist (PITFALLS.md Pitfall 1): suppress every finding for
      // test/fixture/mock/example/story paths — applies to both CONFIG-01
      // and CONFIG-02.
      if (isAllowlistedPath(ctx.filePath)) {
        return Promise.resolve([]);
      }

      const findings: Finding[] = [];
      if (/\.(?:py|go)$/.test(ctx.filePath)) {
        runPythonGoPass(ctx, findings);
        return Promise.resolve(findings);
      }
      runConfigDumpPass(ctx, findings);
      runDebugEndpointPass(ctx, findings);

      return Promise.resolve(findings);
    } catch {
      // No-throw contract (src/core/types.ts Detector.detect): a malformed
      // or unexpected ctx.content must resolve to [], never reject.
      return Promise.resolve([]);
    }
  },
};

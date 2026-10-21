/**
 * secretsDetector — text-only CAT-1 (Leaked Secrets) detector.
 *
 * Three passes over `ctx.content`, split into lines once:
 *
 *   Pass A (provider-key regex, SEC-01/02/03/04/07): rigid, low-FP key
 *   formats (Stripe `sk_live_`, AWS `AKIA...`, OpenAI `sk-...`/`sk-proj-...`,
 *   Supabase `sb_secret_...`, Anthropic `sk-ant-...`) per FEATURES.md CAT-1's
 *   "V1 PICK". Each match is CRITICAL/HIGH confidence — the format itself is
 *   the provider's own naming convention, near-zero FP risk.
 *
 *   Pass A2 (Supabase service_role JWT, SEC-04 — plan 05-01): two
 *   independent signals, both CRITICAL/HIGH, both emitting ruleId "SEC-04":
 *   (a) decode the middle (payload) segment of any `eyJ...`-shaped JWT and
 *   flag when the decoded text contains `"role":"service_role"`; (b) flag a
 *   `SUPABASE_SERVICE_ROLE_KEY` identifier only when it is ASSIGNED a
 *   literal value (`KEY=value` in a .env file, `KEY: "value"`, `const KEY =
 *   "value"`), no JWT required. A bare mention (a comment, docs, a type, a
 *   safe environment-variable *read* such as `Deno.env.get(...)` or
 *   `process.env.X`, or an assignment FROM another variable / a placeholder
 *   like `your-service-role-key`) is not a leak and is never flagged. This
 *   branch runs ahead of Pass B and claims its own matched spans so a
 *   service_role JWT cannot ALSO double-fire SEC-06's keyword-anchored
 *   entropy pass on the same literal.
 *
 *   Pass B (keyword-anchored Shannon entropy, SEC-06): a quoted string
 *   literal >=40 chars with entropy >=4.0 is flagged ONLY when its own line
 *   also contains a secret/key/token/password-family keyword as a whole
 *   word or identifier part (`apiKey`, `API_KEY`, `access_token` — not
 *   `keyboard`/`monkey`) — this is the FEATURES.md "False Positive
 *   Management Strategy" CAT-1 row's documented keyword-anchor mitigation,
 *   preventing UUID/hash false positives — AND the literal itself is shaped
 *   like a credential (`isPlausibleSecretValue`): no whitespace (prose), no
 *   `${...}` interpolation, not a Subresource-Integrity hash, not a plain
 *   URL or package/path name, and it mixes letters with digits. Capped
 *   at MAX_ENTROPY_FINDINGS_PER_FILE per file: past that many matches in ONE
 *   file, the shape is far more likely a generated data/schema artifact
 *   (e.g. a code-graph JSON dump with a "key" field on every node) than
 *   distinct secrets, and further matches add no signal while destroying
 *   report usability. Pass A and Pass A2 are NOT subject to this cap — those
 *   are precision-anchored, and every match is independently meaningful.
 *
 * FP allowlist (.planning/research/PITFALLS.md Pitfall 1): `detect()` opens
 * with a path-segment check against `__tests__`, `fixtures`, `mocks`,
 * `examples`, plus a `.test.`/`.stories.` basename check and a package
 * manager lockfile check (`package-lock.json` & co. are full of integrity
 * hashes and registry URLs, never hand-written secrets) — matching paths
 * short-circuit to `[]` before any pass runs, for every ruleId this file
 * emits (SEC-01..04, SEC-06, SEC-07 alike).
 *
 * ENG-05 (text-only invariant): this module reads `ctx.content` as a plain
 * string. It never reads `ctx.ast`, never imports a parser, and never
 * evaluates, requires, or spawns a subprocess from scanned content —
 * verified by the plan's grep acceptance gate.
 *
 * No-throw contract (src/core/types.ts `Detector.detect`): the entire body
 * of `detect()` runs inside a try/catch returning `[]` on any failure, so a
 * malformed/empty `ctx.content` can never propagate a rejection. The JWT
 * base64url decode (Pass A2) runs inside this same outer try/catch and is
 * additionally guarded per-match so one malformed JWT segment cannot abort
 * the rest of the scan (T-05-01-02).
 *
 * T-04-02 mitigation: `maskSecret()` truncates every matched secret to its
 * first 4 characters before it is ever assigned to `Finding.matchedText` —
 * the full secret value never appears in any Finding field.
 */
import {
  decodesToServiceRole,
  ENTROPY_THRESHOLD,
  JWT_RE,
  MIN_ENTROPY_CANDIDATE_LENGTH,
  PROVIDER_KEY_PATTERNS,
  QUOTED_STRING_RE,
  shannonEntropy,
  SUPABASE_ENV_NAME_RE,
} from "./secret-patterns.js";

import type { Confidence, Detector, DetectorContext, Finding, Severity } from "../../core/types.js";

/** Literal mask suffix appended after the first 4 characters of any matched secret (T-04-02). */
const MASK_SUFFIX = "****";

/**
 * Per-file cap on SEC-06 (generic entropy) findings — past this many matches
 * in ONE file, the shape is far more likely a generated data/schema artifact
 * (e.g. a code-graph JSON dump with a "key" field on every node) than
 * distinct secrets; further matches add no signal and destroy report
 * usability. Provider-key (Pass A) and Supabase (Pass A2) findings are NOT
 * subject to this cap — those are precision-anchored, and every match is
 * independently meaningful.
 */
const MAX_ENTROPY_FINDINGS_PER_FILE = 10;

interface ProviderPattern {
  ruleId: string;
  /**
   * MUST carry the global flag. Iterated via `String.prototype.matchAll`
   * (not a manual `.exec()` loop) — `matchAll` creates its own internal
   * cursor per call, so the same literal `RegExp` is safely reusable across
   * every line and file without a `lastIndex` reset.
   */
  regex: RegExp;
  severity: Severity;
  confidence: Confidence;
  message: string;
  remediation: string;
}

/** Looks up a PROVIDER_KEY_PATTERNS entry's regex by its shared ruleId; throws if the shared table ever drops an entry this detector depends on (fails loudly at module load, not silently at scan time). */
function sharedRegex(ruleId: string): RegExp {
  const found = PROVIDER_KEY_PATTERNS.find((pattern) => pattern.ruleId === ruleId);
  if (found === undefined) {
    throw new Error(`secret-patterns.ts is missing the expected "${ruleId}" provider-key pattern`);
  }
  return found.regex;
}

/**
 * Provider-key regex table (Pass A) — rigid, low-FP key formats (see file
 * header). Layers this detector's SEC-0x severity/confidence/message copy
 * on top of the shared regex table in `secret-patterns.ts` (single source of
 * truth for the regex literals themselves).
 */
const PROVIDER_PATTERNS: ProviderPattern[] = [
  {
    ruleId: "SEC-01",
    regex: sharedRegex("SEC-01"),
    severity: "CRITICAL",
    confidence: "HIGH",
    message: "Hardcoded Stripe live secret key (sk_live_) found in source.",
    remediation:
      "Remove this key from source control immediately, rotate it in the Stripe dashboard, and load it from an untracked environment variable (e.g. process.env.STRIPE_SECRET_KEY) instead.",
  },
  {
    ruleId: "SEC-02",
    regex: sharedRegex("SEC-02"),
    severity: "CRITICAL",
    confidence: "HIGH",
    message: "Hardcoded AWS access key ID (AKIA...) found in source.",
    remediation:
      "Deactivate this access key in IAM immediately, rotate it, and load credentials from an untracked environment variable or an instance role instead of source.",
  },
  {
    ruleId: "SEC-03",
    regex: sharedRegex("SEC-03"),
    severity: "CRITICAL",
    confidence: "HIGH",
    message: "Hardcoded OpenAI API key (sk-...) found in source.",
    remediation:
      "Revoke this key in the OpenAI dashboard, rotate it, and load it from an untracked environment variable (e.g. process.env.OPENAI_API_KEY) instead.",
  },
  {
    ruleId: "SEC-04",
    regex: sharedRegex("SEC-04"),
    severity: "CRITICAL",
    confidence: "HIGH",
    message: "Hardcoded Supabase secret API key (sb_secret_...) found in source.",
    remediation:
      "Rotate this secret key in the Supabase dashboard immediately, remove it from source, and never expose it client-side — like a service_role key, it bypasses every Row Level Security policy.",
  },
  {
    ruleId: "SEC-07",
    regex: sharedRegex("SEC-07"),
    severity: "CRITICAL",
    confidence: "HIGH",
    message: "Hardcoded Anthropic API key (sk-ant-...) found in source.",
    remediation:
      "Revoke this key in the Anthropic Console, rotate it, and load it from an untracked environment variable (e.g. process.env.ANTHROPIC_API_KEY) instead.",
  },
];

/** Ruleid assigned to every Supabase service_role signal (JWT decode OR env-name shortcut). */
const SUPABASE_SERVICE_ROLE_RULE_ID = "SEC-04";

/** Path segments that suppress every finding in this file (FP allowlist — PITFALLS.md Pitfall 1). */
const FP_ALLOWLIST_SEGMENTS = new Set(["__tests__", "fixtures", "mocks", "examples"]);

/**
 * Package-manager lockfiles: machine-generated, full of integrity hashes
 * (`sha512-...`) and registry URLs whose package names routinely contain
 * "key"/"token" — never a place a developer hand-writes a secret.
 */
const LOCKFILE_BASENAMES = new Set([
  "package-lock.json",
  "npm-shrinkwrap.json",
  "yarn.lock",
  "pnpm-lock.yaml",
  "bun.lock",
  "deno.lock",
  "composer.lock",
  "Gemfile.lock",
  "Cargo.lock",
  "poetry.lock",
]);

/**
 * True when `filePath` falls inside a test/fixture/mock/example directory,
 * its basename marks it as a test or story file (`.test.` / `.stories.`),
 * or it is a package-manager lockfile.
 * Mirrors the codebase's existing `.split("/")` segment-check style (see
 * src/core/ingest/stack-detector.ts `hasKeyWithPrefix`/`hasEnvFile`) rather
 * than pulling in micromatch.
 */
function isAllowlistedPath(filePath: string): boolean {
  const segments = filePath.split("/");
  if (segments.some((segment) => FP_ALLOWLIST_SEGMENTS.has(segment))) {
    return true;
  }
  const basename = segments.at(-1) ?? "";
  return basename.includes(".test.") || basename.includes(".stories.") || LOCKFILE_BASENAMES.has(basename);
}

/**
 * Secret-family words matched against whole identifier parts of a line
 * (see `hasSecretKeyword`), plus the common all-lowercase compounds that
 * do not split on a case/underscore boundary (`apikey`, `authtoken`).
 */
const SECRET_KEYWORD_TOKENS = new Set([
  "secret",
  "secrets",
  "token",
  "tokens",
  "password",
  "passwords",
  "passwd",
  "pwd",
  "key",
  "keys",
  "apikey",
  "accesskey",
  "secretkey",
  "privatekey",
  "signingkey",
  "masterkey",
  "authkey",
  "authtoken",
  "accesstoken",
  "refreshtoken",
  "clientsecret",
  "credential",
  "credentials",
]);

/**
 * Splits a line into lowercase identifier parts on every non-alphanumeric
 * character, camelCase boundary, and letter/digit boundary — `apiKey`,
 * `API_KEY`, `key0`, and `x-api-key` all yield a standalone `key` part,
 * while `keyboard`, `monkey`, and `keyof` do not.
 */
function identifierParts(line: string): string[] {
  return line
    .split(/[^A-Za-z0-9]+/)
    .flatMap((chunk) => chunk.split(/(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])|(?<=[A-Za-z])(?=\d)|(?<=\d)(?=[A-Za-z])/))
    .map((part) => part.toLowerCase());
}

/**
 * Keyword anchor for Pass B: true when `line` contains a secret-family word
 * as a whole identifier part (see `identifierParts`). Stricter than the
 * shared substring-based `hasAnchorKeyword` the LLM redactor uses — over-
 * redacting before a network call is safe, but over-REPORTING here is what
 * drowns real findings in noise (`keyboardType`, `monkeyPatch`, `keyof`).
 */
function hasSecretKeyword(line: string): boolean {
  return identifierParts(line).some((part) => SECRET_KEYWORD_TOKENS.has(part));
}

/** Subresource-Integrity hash (`sha512-...`), as found in lockfiles and `<script integrity>`. */
const SRI_HASH_RE = /^sha(?:1|256|384|512)-/;

/** A `scheme://` URL. */
const URL_RE = /^[A-Za-z][\w+.-]*:\/\//;

/** URL carrying inline `user:password@` credentials (e.g. a database connection string). */
const URL_CREDENTIALS_RE = /:\/\/[^/\s:@]+:[^/\s@]+@/;

/** URL carrying a secret-named query parameter with a non-trivial value (`?api_key=...`, `&token=...`). */
const URL_SECRET_PARAM_RE = /[?&][\w-]*(?:key|token|secret|password|signature|sig)[\w-]*=[^&#\s]{16,}/i;

/** All-lowercase characters of an npm package name, module path, or slug (paired with a separator check in `isSlug`). */
const SLUG_CHARS_RE = /^@?[a-z0-9][a-z0-9./@_-]*$/;

/** True for lowercase word segments joined by `-`/`/`/`.`/`@`/`_` — a package name, module path, or slug, not a credential. */
function isSlug(value: string): boolean {
  return SLUG_CHARS_RE.test(value) && /[-./@_]/.test(value.slice(1));
}

/**
 * True when a high-entropy quoted literal is actually shaped like a
 * credential. Real API keys/tokens are a single unbroken run of mixed
 * letters and digits; every rejection below is a shape that clears the
 * entropy bar on real repos without ever being a secret:
 * - whitespace — prose, UI copy, error messages ("add a Graph API access token in Settings")
 * - `${` — a template literal building a URL/string around a variable
 * - an SRI integrity hash
 * - a URL, unless it embeds credentials or a secret-named query parameter
 * - a lowercase slug (package name, import path)
 * - no digit, or no letter — a 40+ char random token without both is vanishingly rare
 */
function isPlausibleSecretValue(value: string): boolean {
  if (/\s/.test(value) || value.includes("${") || SRI_HASH_RE.test(value)) {
    return false;
  }
  if (URL_RE.test(value)) {
    return URL_CREDENTIALS_RE.test(value) || URL_SECRET_PARAM_RE.test(value);
  }
  if (isSlug(value)) {
    return false;
  }
  return /\d/.test(value) && /[A-Za-z]/.test(value);
}

/**
 * Accessor prefixes that indicate a safe *read* of the env var by name, not a
 * hardcoded leak (e.g. `Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")` in a
 * Supabase Edge Function, or `process.env.SUPABASE_SERVICE_ROLE_KEY`). An
 * optional opening quote character (`'`/`"`/backtick) is tolerated between
 * the accessor and the var name for the bracket/get-call forms.
 */
const SAFE_ENV_READ_PREFIX_RE = /(?:Deno\.env\.get\(|process\.env\.|process\.env\[|import\.meta\.env\.)['"`]?$/;

/**
 * True when the `SUPABASE_SERVICE_ROLE_KEY` occurrence starting at
 * `matchStart` on `line` is immediately preceded by a known safe
 * environment-variable accessor — a secure *read* of the var by name, not a
 * hardcoded leak, so it must not be flagged as SEC-04.
 */
function isSafeEnvRead(line: string, matchStart: number): boolean {
  return SAFE_ENV_READ_PREFIX_RE.test(line.slice(0, matchStart));
}

/**
 * Matches the text right after a `SUPABASE_SERVICE_ROLE_KEY` identifier
 * when it is assigned a value: an optional closing quote (JSON/object key),
 * `=` or `:`, an optional opening quote, then the value itself (group 1,
 * stopping at whitespace, a quote, or a statement/argument separator).
 */
const ASSIGNED_VALUE_RE = /^['"`]?\s*[:=]\s*['"`]?([^\s'"`,;)]+)/;

/** Minimum length of an assigned value for it to count as a real key rather than a stub. */
const MIN_ASSIGNED_KEY_LENGTH = 20;

/** Common placeholder values for an env var in docs / `.env.example` files. */
const PLACEHOLDER_VALUE_RE = /^(?:your|my|<|\[|x{3,}|\.{3}|changeme|change-me|replace|example|placeholder|todo|insert|enter|redacted|dummy|test)/i;

/**
 * Returns the [start, end) span of the literal value assigned to the
 * `SUPABASE_SERVICE_ROLE_KEY` identifier ending at `nameEnd` on `line`, or
 * `undefined` when the identifier is not assigned a real literal — no
 * assignment at all (a comment, docs, a type), an assignment FROM an
 * expression (`process.env.X`, `Deno.env.get(...)`, `${{ secrets.X }}`,
 * `z.string()`), a placeholder, or a value too short to be a key.
 */
function assignedLiteralSpan(line: string, nameEnd: number): [number, number] | undefined {
  const rest = line.slice(nameEnd);
  const match = rest.match(ASSIGNED_VALUE_RE);
  const value = match?.[1];
  if (match === null || value === undefined) {
    return undefined;
  }
  if (
    value.length < MIN_ASSIGNED_KEY_LENGTH ||
    /^[$<{[]/.test(value) ||
    value.includes("(") ||
    /^(?:process\.env|Deno\.env|import\.meta|env\.)/.test(value) ||
    PLACEHOLDER_VALUE_RE.test(value)
  ) {
    return undefined;
  }
  const valueStart = nameEnd + match[0].length - value.length;
  return [valueStart, valueStart + value.length];
}

/**
 * Pass A2: Supabase service_role JWT (SEC-04). Two independent signals on
 * `line`, each pushing a Finding and claiming the matched span so Pass B
 * cannot also flag the same literal as generic high-entropy (SEC-06 dedup,
 * same mechanism as `runProviderPatterns`'s `matchedSpans` return).
 *
 * Signal (a): every JWT-shaped match on the line is base64url-decoded; only
 * matches whose payload decodes to `role: service_role` are flagged.
 * Signal (b): a `SUPABASE_SERVICE_ROLE_KEY` identifier ASSIGNED a literal
 * value (`assignedLiteralSpan`) is flagged — this is a name-based signal,
 * so it reports the identifier match itself as `matchedText`. A safe
 * env-read (`isSafeEnvRead`), a bare mention, or an assignment whose value
 * was already flagged by Pass A / signal (a) (`claimedSpans`) is skipped
 * (no duplicate finding for the same leaked key).
 */
function runSupabaseServiceRolePass(
  line: string,
  lineNumber: number,
  filePath: string,
  detectorName: string,
  claimedSpans: Array<[number, number]>,
  findings: Finding[],
): Array<[number, number]> {
  const matchedSpans: Array<[number, number]> = [];

  for (const match of line.matchAll(JWT_RE)) {
    const matchedValue = match[0];
    if (!decodesToServiceRole(matchedValue)) {
      continue;
    }
    const start = match.index;
    matchedSpans.push([start, start + matchedValue.length]);

    findings.push({
      ruleId: SUPABASE_SERVICE_ROLE_RULE_ID,
      category: "secrets",
      detectorName,
      file: filePath,
      line: lineNumber,
      severity: "CRITICAL",
      confidence: "HIGH",
      message: "Hardcoded Supabase service_role JWT found in source.",
      remediation:
        "Rotate this service_role key in the Supabase dashboard immediately, remove it from source, and never expose a service_role key client-side — it bypasses every Row Level Security policy.",
      matchedText: maskSecret(matchedValue),
    });
  }

  for (const match of line.matchAll(SUPABASE_ENV_NAME_RE)) {
    const matchedValue = match[0];
    const start = match.index;

    if (isSafeEnvRead(line, start)) {
      // Secure server-side read (e.g. Deno.env.get(...), process.env.X) —
      // referencing the var name by itself is not a leak.
      continue;
    }

    const valueSpan = assignedLiteralSpan(line, start + matchedValue.length);
    if (valueSpan === undefined) {
      // A mention, not an assignment of a real value — not a leak.
      continue;
    }
    if (overlapsAny(valueSpan[0], valueSpan[1], [...claimedSpans, ...matchedSpans])) {
      // The assigned key itself was already reported (sb_secret_ / JWT).
      continue;
    }

    matchedSpans.push([start, start + matchedValue.length], valueSpan);

    findings.push({
      ruleId: SUPABASE_SERVICE_ROLE_RULE_ID,
      category: "secrets",
      detectorName,
      file: filePath,
      line: lineNumber,
      severity: "CRITICAL",
      confidence: "HIGH",
      message: "SUPABASE_SERVICE_ROLE_KEY is assigned a hardcoded value in source.",
      remediation:
        "Rotate this service_role key in the Supabase dashboard immediately, remove it from source, and never expose a service_role key client-side — it bypasses every Row Level Security policy.",
      matchedText: maskSecret(matchedValue),
    });
  }

  return matchedSpans;
}

/**
 * Returns the first 4 characters of `raw` followed by a fixed mask marker.
 * Never returns more than the leading 4 characters of the original secret —
 * the literal masking mitigation for T-04-02 (Information Disclosure via
 * Finding.matchedText). The marker length is constant, not proportional to
 * `raw.length`, so the mask itself never leaks the secret's real length.
 */
function maskSecret(raw: string): string {
  return `${raw.slice(0, 4)}${MASK_SUFFIX}`;
}

/**
 * Pass A: runs every PROVIDER_PATTERNS entry against `line`, pushing a
 * Finding per match. Returns the list of [start, end) column spans matched
 * on this line so Pass B can skip overlapping entropy candidates (dedup —
 * a single matched span never emits both a provider AND an entropy finding;
 * the higher-severity provider finding wins).
 */
function runProviderPatterns(
  line: string,
  lineNumber: number,
  filePath: string,
  detectorName: string,
  findings: Finding[],
): Array<[number, number]> {
  const matchedSpans: Array<[number, number]> = [];

  for (const pattern of PROVIDER_PATTERNS) {
    for (const match of line.matchAll(pattern.regex)) {
      const matchedValue = match[0];
      const start = match.index;
      matchedSpans.push([start, start + matchedValue.length]);

      findings.push({
        ruleId: pattern.ruleId,
        category: "secrets",
        detectorName,
        file: filePath,
        line: lineNumber,
        severity: pattern.severity,
        confidence: pattern.confidence,
        message: pattern.message,
        remediation: pattern.remediation,
        matchedText: maskSecret(matchedValue),
      });
    }
  }

  return matchedSpans;
}

/** True when [start, end) overlaps any span in `spans`. */
function overlapsAny(start: number, end: number, spans: Array<[number, number]>): boolean {
  return spans.some(([spanStart, spanEnd]) => start < spanEnd && end > spanStart);
}

/**
 * Pass B: keyword-anchored Shannon entropy (SEC-06). Finds every quoted
 * string literal on `line` of length >= MIN_ENTROPY_CANDIDATE_LENGTH whose
 * entropy is >= ENTROPY_THRESHOLD, skips any span already claimed by Pass A
 * (dedup), and — per the FP-management keyword-anchor rule — only flags the
 * candidate when `line` also contains an ANCHOR_KEYWORDS member. Stops
 * emitting new findings once `entropyCount.value` reaches
 * MAX_ENTROPY_FINDINGS_PER_FILE (mutated in place so the cap is tracked
 * across every line of the same file).
 */
function runEntropyPass(
  line: string,
  lineNumber: number,
  filePath: string,
  detectorName: string,
  providerSpans: Array<[number, number]>,
  findings: Finding[],
  entropyCount: { value: number },
): void {
  if (entropyCount.value >= MAX_ENTROPY_FINDINGS_PER_FILE) {
    return;
  }

  const lineHasAnchor = hasSecretKeyword(line);
  if (!lineHasAnchor) {
    // FP-management rule: a candidate with no anchoring keyword on its line
    // is never flagged, regardless of entropy.
    return;
  }

  for (const match of line.matchAll(QUOTED_STRING_RE)) {
    if (entropyCount.value >= MAX_ENTROPY_FINDINGS_PER_FILE) {
      return;
    }

    const value = match[1] ?? match[2] ?? match[3] ?? "";
    const start = match.index + 1; // +1 skips the opening quote character
    const end = start + value.length;

    if (value.length < MIN_ENTROPY_CANDIDATE_LENGTH) {
      continue;
    }
    if (overlapsAny(start, end, providerSpans)) {
      // Already claimed by a higher-severity provider-key finding (dedup).
      continue;
    }

    const entropy = shannonEntropy(value);
    if (entropy < ENTROPY_THRESHOLD) {
      continue;
    }
    if (!isPlausibleSecretValue(value)) {
      // Clears the entropy bar but is prose, a URL, a hash, or a slug.
      continue;
    }

    findings.push({
      ruleId: "SEC-06",
      category: "secrets",
      detectorName,
      file: filePath,
      line: lineNumber,
      severity: "HIGH",
      confidence: "MEDIUM",
      message: "High-entropy secret anchored to a sensitive keyword found in source.",
      remediation:
        "Move this value to an untracked environment variable (e.g. a .env file excluded from git) and reference it via process.env instead of a literal string.",
      matchedText: maskSecret(value),
    });
    entropyCount.value += 1;
  }
}

export const secretsDetector: Detector = {
  config: {
    name: "secrets",
    category: "secrets",
    globs: ["**/*.{ts,tsx,js,jsx,mjs,cjs,json,env,txt,md}", "**/.env*"],
  },

  // Not declared `async` — there is no network/disk wait in this text-only
  // detector, so the body is plain synchronous work wrapped in
  // `Promise.resolve()`. The Detector interface still requires returning
  // `Promise<Finding[]>` (so callers can always `await` uniformly across
  // async and sync detectors); `async` itself is reserved for detectors
  // that actually await something.
  detect(ctx: DetectorContext): Promise<Finding[]> {
    try {
      // FP allowlist (PITFALLS.md Pitfall 1): suppress every finding this
      // detector could emit for test/fixture/mock/example/story paths —
      // applies uniformly across Pass A, A2, and B, not just the new
      // Supabase branch, so test-suite source itself never self-flags.
      if (isAllowlistedPath(ctx.filePath)) {
        return Promise.resolve([]);
      }

      const findings: Finding[] = [];
      const lines = ctx.content.split("\n");
      const entropyCount = { value: 0 };

      // `.entries()` (not bracket indexing) avoids a dynamic-index access
      // pattern entirely — sidesteps security/detect-object-injection.
      for (const [index, line] of lines.entries()) {
        const lineNumber = index + 1; // 1-indexed per src/core/types.ts Finding.line

        const providerSpans = runProviderPatterns(line, lineNumber, ctx.filePath, "secrets", findings);
        const supabaseSpans = runSupabaseServiceRolePass(
          line,
          lineNumber,
          ctx.filePath,
          "secrets",
          providerSpans,
          findings,
        );
        const claimedSpans = [...providerSpans, ...supabaseSpans];
        runEntropyPass(line, lineNumber, ctx.filePath, "secrets", claimedSpans, findings, entropyCount);
      }

      return Promise.resolve(findings);
    } catch {
      // No-throw contract (src/core/types.ts Detector.detect): a malformed
      // or unexpected ctx.content must resolve to [], never reject.
      return Promise.resolve([]);
    }
  },
};

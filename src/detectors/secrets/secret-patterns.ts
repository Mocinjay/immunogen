/**
 * secret-patterns — single source of truth for provider-key regexes,
 * Shannon-entropy scoring, keyword anchors, and their thresholds.
 *
 * `entropy-detector.ts` (CAT-1 deterministic detector) and `redactor.ts`
 * (SAFE-01 LLM-boundary redaction gate) each used to carry their own copy of
 * this exact regex/entropy/keyword logic — two independently-maintained
 * copies that could silently drift apart (a new provider-key format added to
 * one and forgotten in the other). This module is the extraction target:
 * both files now import from here instead of hand-copying the tables.
 *
 * Behavior is byte-identical to the pre-extraction copies in both files —
 * this is a pure refactor (no threshold, regex, or keyword changed). The
 * pre-existing `entropy-detector.test.ts` and `redactor.test.ts` suites are
 * the regression proof and must pass unchanged against this module.
 *
 * `redactor.ts` layers one extra entry on top of `PROVIDER_KEY_PATTERNS`
 * (the Anthropic `sk-ant-api03-` shape) that `entropy-detector.ts` does not
 * detect as its own SEC-0x rule — see that file's own module comment for why.
 */

/** Minimum Shannon entropy (bits/char) for a quoted literal to be flagged/redacted. */
export const ENTROPY_THRESHOLD = 4.0;

/** Minimum length of a quoted literal considered by any entropy pass. */
export const MIN_ENTROPY_CANDIDATE_LENGTH = 40;

/**
 * Case-insensitive keyword family that must co-occur on the same line as a
 * high-entropy literal before it is flagged/redacted (FP-management keyword
 * anchor — .planning/research/FEATURES.md "False Positive Management
 * Strategy").
 */
export const ANCHOR_KEYWORDS = [
  "secret",
  "apikey",
  "api_key",
  "token",
  "password",
  "passwd",
  "private_key",
  "client_secret",
  "key",
];

/** Matches a single-, double-, or backtick-quoted string literal, non-greedy, no embedded same-quote char. */
export const QUOTED_STRING_RE = /'([^'\\]*)'|"([^"\\]*)"|`([^`\\]*)`/g;

/**
 * Matches a base64url JWT shape: three dot-separated segments, each
 * restricted to the base64url alphabet (`[\w-]+`), with the header segment
 * anchored to the well-known `eyJ` prefix (every JSON JWT header starts with
 * `{"` which base64url-encodes to `eyJ`). Global flag — iterate via
 * `matchAll`, never `.exec()`.
 */
export const JWT_RE = /eyJ[\w-]+\.[\w-]+\.[\w-]+/g;

/** Compact substring the decoded JWT payload must contain to be flagged service_role (tolerates standard JSON spacing). */
export const SERVICE_ROLE_MARKER = '"role":"service_role"';

/** Matches `SUPABASE_SERVICE_ROLE_KEY` as a whole identifier (env-var name signal, no JWT required). */
export const SUPABASE_ENV_NAME_RE = /SUPABASE_SERVICE_ROLE_KEY/g;

/** A single fixed-format provider-key pattern (Stripe/AWS/OpenAI shapes). */
export interface ProviderKeyPattern {
  ruleId: string;
  /**
   * MUST carry the global flag. Iterated via `String.prototype.matchAll`
   * (not a manual `.exec()` loop) — `matchAll` creates its own internal
   * cursor per call, so the same literal `RegExp` is safely reusable across
   * every line and file without a `lastIndex` reset.
   */
  regex: RegExp;
}

/**
 * Provider-key regex table — rigid, low-FP key formats (Stripe `sk_live_`,
 * AWS `AKIA...`, OpenAI `sk-...`) per FEATURES.md CAT-1's "V1 PICK". This is
 * the shared source `entropy-detector.ts`'s Pass A and `redactor.ts`'s
 * fixed-format pass both read from — the ruleId is only meaningful to the
 * detector side; the redactor ignores it and matches on `regex` alone.
 */
export const PROVIDER_KEY_PATTERNS: ProviderKeyPattern[] = [
  {
    ruleId: "SEC-01",
    regex: /sk_live_[\w-]+/g,
  },
  {
    ruleId: "SEC-02",
    regex: /AKIA[0-9A-Z]{16}/g,
  },
  {
    ruleId: "SEC-03",
    regex: /sk-[A-Za-z0-9]{48}/g,
  },
];

/**
 * Shannon entropy of `value` in bits per character: sum over each distinct
 * character c of -p(c) * log2(p(c)), where p(c) is c's frequency in value.
 * Custom implementation per CLAUDE.md's stack guidance ("custom Shannon
 * entropy is intended, not a library") — no dependency required.
 */
export function shannonEntropy(value: string): number {
  if (value.length === 0) {
    return 0;
  }

  const frequencies = new Map<string, number>();
  for (const char of value) {
    frequencies.set(char, (frequencies.get(char) ?? 0) + 1);
  }

  let entropy = 0;
  for (const count of frequencies.values()) {
    const probability = count / value.length;
    entropy -= probability * Math.log2(probability);
  }
  return entropy;
}

/** True when `line` contains any ANCHOR_KEYWORDS member, case-insensitively. */
export function hasAnchorKeyword(line: string): boolean {
  const lower = line.toLowerCase();
  return ANCHOR_KEYWORDS.some((keyword) => lower.includes(keyword));
}

/**
 * Returns true when `jwt`'s middle (payload) segment, once base64url
 * decoded, contains the compact `"role":"service_role"` marker. Decoding
 * happens inside its own try/catch (T-05-01-02): a malformed/non-JSON
 * payload segment yields `false` for that match rather than throwing,
 * keeping one hostile JWT-shaped string from aborting the whole scan.
 */
export function decodesToServiceRole(jwt: string): boolean {
  const segments = jwt.split(".");
  const payloadSegment = segments.at(1);
  if (payloadSegment === undefined) {
    return false;
  }
  try {
    const decoded = Buffer.from(payloadSegment, "base64url").toString("utf8");
    // Collapse all whitespace before the substring check so standard JSON
    // formatting variants (spaces after ':', after ',') still match the
    // compact SERVICE_ROLE_MARKER literal.
    const compact = decoded.replace(/\s+/g, "");
    return compact.includes(SERVICE_ROLE_MARKER);
  } catch {
    return false;
  }
}

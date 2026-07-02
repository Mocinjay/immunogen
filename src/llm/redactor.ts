/**
 * Redactor — the SAFE-01 secret-redaction gate.
 *
 * This module is the network-boundary control for the LLM enrichment stage
 * introduced in Phase 7. `Finding.matchedText`, `Finding.message`, and
 * `Finding.remediation` can all contain fragments of real secrets pulled
 * straight from a scanned repo
 * (the deterministic detectors only mask to first-4-chars — see
 * `maskSecret` in src/detectors/secrets/entropy-detector.ts — which is NOT
 * sufficient once that text is about to be serialized into an LLM request
 * body). Before ANY snippet or Finding text crosses the network boundary to
 * an LLM provider, it MUST pass through `Redactor.redactSnippet` /
 * `redactFinding` so every detectable secret span is replaced with
 * `[REDACTED]` in full — never a partial mask.
 *
 * This is a clean-room reimplementation of known, publicly-documented
 * secret formats (Stripe/AWS/OpenAI/Anthropic key shapes, JWT structure,
 * Shannon entropy) — it adapts no SkillSpector source, so no SPDX header is
 * required (docs/LICENSING.md §3: independently-expressed reuse of
 * publicly-known patterns, same treatment as the gitleaks-style regexes in
 * src/detectors/secrets/entropy-detector.ts).
 *
 * ENG-05 (text-only invariant): this module operates on plain strings only.
 * It never imports a parser, never touches an AST, never imports or calls
 * child_process/eval/require on scanned content, and is a dependency-free
 * leaf — it is not imported by anything else in this plan (07-01). A later
 * plan (07-03) wires it into the provider-adapter request path.
 */
import type { Finding } from "../core/types.js";

/** The fixed replacement token every detected secret span is replaced with. Never proportional to secret length — it must not leak size information either. */
export const REDACTED_PLACEHOLDER = "[REDACTED]";

/**
 * Fixed-format secret patterns (Pass 1), mirroring the provider-key regex
 * literals in src/detectors/secrets/entropy-detector.ts (PROVIDER_PATTERNS
 * @92-120, JWT_RE @151, SUPABASE_ENV_NAME_RE @157). Copied here as exact
 * literals rather than imported — the detector's tables are module-private
 * and not exported, and this module intentionally has zero internal
 * dependencies (leaf module invariant).
 *
 * The Anthropic pattern is NOT present in entropy-detector.ts: the
 * existing OpenAI pattern (`sk-[A-Za-z0-9]{48}`) is fixed at exactly 48
 * trailing characters and does not match the `sk-ant-api03-` prefixed key
 * shape Anthropic issues. This is the SAFE-01 criterion-1 fixture pattern,
 * so it is added explicitly.
 *
 * All entries carry the global flag and are applied via
 * `String.prototype.replaceAll` (not `.exec()` — this project's ENG-05
 * ESLint rule forbids any member call literally named `exec`, matching the
 * child_process.exec/execSync/spawn family regardless of receiver type).
 */
const SECRET_PATTERNS: RegExp[] = [
  // Stripe live secret key (SEC-01 precedent).
  /sk_live_[\w-]+/g,
  // AWS access key ID (SEC-02 precedent).
  /AKIA[0-9A-Z]{16}/g,
  // Anthropic API key — sk-ant-api03-<base64url-ish body>. Checked BEFORE
  // the OpenAI pattern below since both share the `sk-` prefix; ordering
  // does not actually matter for correctness here (the two patterns match
  // disjoint shapes — Anthropic requires the literal `ant-api03-` infix,
  // OpenAI's is exactly 48 trailing chars with no infix) but is kept in
  // this order for readability parity with entropy-detector.ts's own
  // provider ordering.
  /sk-ant-api03-[\w-]+/g,
  // OpenAI API key (SEC-03 precedent) — fixed 48-char trailing body.
  /sk-[A-Za-z0-9]{48}/g,
  // Supabase / generic JWT shape: three dot-separated base64url segments,
  // header segment anchored to the well-known `eyJ` prefix (SEC-04
  // precedent, JWT_RE).
  /eyJ[\w-]+\.[\w-]+\.[\w-]+/g,
  // Bare SUPABASE_SERVICE_ROLE_KEY identifier reference — a name-based
  // signal with no JWT body required (SEC-04 env-name precedent).
  /SUPABASE_SERVICE_ROLE_KEY/g,
];

/**
 * Case-insensitive keyword family that must co-occur on the same line as a
 * high-entropy literal before the generic pass redacts it (Pass 2 anchor
 * gate) — exact copy of entropy-detector.ts's ANCHOR_KEYWORDS list (@64),
 * preventing both under-redaction (real secrets slipping through) and
 * over-redaction (ordinary UUIDs/hashes getting scrubbed unpredictably).
 */
const ANCHOR_KEYWORDS = [
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

/** Minimum Shannon entropy (bits/char) for a quoted literal to be redacted by the generic pass. Mirrors entropy-detector.ts's ENTROPY_THRESHOLD (@54). */
const ENTROPY_THRESHOLD = 4.0;

/** Minimum length of a quoted literal considered by the generic entropy pass. Mirrors entropy-detector.ts's MIN_ENTROPY_CANDIDATE_LENGTH (@57). */
const MIN_ENTROPY_CANDIDATE_LENGTH = 40;

/** Matches a single-, double-, or backtick-quoted string literal, non-greedy, no embedded same-quote char. Exact copy of entropy-detector.ts's QUOTED_STRING_RE (@252). */
const QUOTED_STRING_RE = /'([^'\\]*)'|"([^"\\]*)"|`([^`\\]*)`/g;

/**
 * Shannon entropy of `value` in bits per character: sum over each distinct
 * character c of -p(c) * log2(p(c)), where p(c) is c's frequency in value.
 * Reimplemented inline (no import from entropy-detector.ts, no library) —
 * exact algorithmic mirror of that file's `shannonEntropy` (@271).
 */
function shannonEntropy(value: string): number {
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
function hasAnchorKeyword(line: string): boolean {
  const lower = line.toLowerCase();
  return ANCHOR_KEYWORDS.some((keyword) => lower.includes(keyword));
}

/**
 * Pass 1: replace every fixed-format SECRET_PATTERNS match in `text` with
 * `REDACTED_PLACEHOLDER`, across the whole text (not line-scoped — these
 * are unambiguous, low-FP formats that never need keyword anchoring).
 */
function redactFixedPatterns(text: string): string {
  let result = text;
  for (const pattern of SECRET_PATTERNS) {
    result = result.replaceAll(pattern, REDACTED_PLACEHOLDER);
  }
  return result;
}

/**
 * Pass 2: keyword-anchored generic entropy redaction, applied line by line
 * (anchor keywords are a same-line signal, matching entropy-detector.ts's
 * per-line design). For each quoted-string literal on a line that is
 * >=MIN_ENTROPY_CANDIDATE_LENGTH chars AND has Shannon entropy
 * >=ENTROPY_THRESHOLD, redact it ONLY when the line also contains an
 * ANCHOR_KEYWORDS member — an unanchored high-entropy literal (e.g. a
 * UUID or hash with no nearby secret/key/token/password keyword) is left
 * intact, avoiding unpredictable over-redaction of non-secret data.
 *
 * Runs AFTER redactFixedPatterns so any literal already reduced to
 * REDACTED_PLACEHOLDER is not re-scanned as an entropy candidate — the
 * placeholder itself has far too little entropy/length to match anyway,
 * but line order guarantees idempotency regardless.
 */
/**
 * Replacer for a single QUOTED_STRING_RE match: returns REDACTED_PLACEHOLDER
 * (re-wrapped in the original quote character) when the captured inner
 * value is long enough and high-entropy enough, else returns the match
 * unchanged. Parameters are explicitly typed (rather than relying on
 * inference from `String.prototype.replaceAll`'s replacer-function
 * overload) to avoid an unsafe-`any` assignment from the capture-group
 * parameters, which TypeScript's lib defs type loosely.
 */
function redactEntropyMatch(
  fullMatch: string,
  single: string | undefined,
  double: string | undefined,
  backtick: string | undefined,
): string {
  const value = single ?? double ?? backtick ?? "";
  if (value.length < MIN_ENTROPY_CANDIDATE_LENGTH) {
    return fullMatch;
  }
  if (shannonEntropy(value) < ENTROPY_THRESHOLD) {
    return fullMatch;
  }

  const quoteChar = fullMatch.charAt(0);
  return `${quoteChar}${REDACTED_PLACEHOLDER}${quoteChar}`;
}

function redactAnchoredEntropy(text: string): string {
  const lines = text.split("\n");

  const redactedLines = lines.map((line) => {
    if (!hasAnchorKeyword(line)) {
      // FP-management rule: no anchor keyword on this line means no
      // generic-entropy redaction happens here, regardless of entropy.
      return line;
    }

    return line.replaceAll(QUOTED_STRING_RE, redactEntropyMatch);
  });

  return redactedLines.join("\n");
}

/**
 * Redacts every detectable secret in `text`, replacing the ENTIRE matched
 * span with `REDACTED_PLACEHOLDER` (never a partial/truncated mask). Runs
 * the fixed-format pass first (Stripe/AWS/Anthropic/OpenAI/JWT/Supabase),
 * then the keyword-anchored generic entropy pass. Idempotent: redacting an
 * already-redacted string returns the same string, since
 * `REDACTED_PLACEHOLDER` matches none of the SECRET_PATTERNS and is far
 * too short to satisfy MIN_ENTROPY_CANDIDATE_LENGTH.
 */
function redactSnippet(text: string): string {
  const afterFixedPatterns = redactFixedPatterns(text);
  return redactAnchoredEntropy(afterFixedPatterns);
}

/** The `Redactor` gate. Exposes `redactSnippet` as a namespaced object per the plan's export contract. */
export const Redactor = {
  redactSnippet,
};

/**
 * Returns a shallow copy of `finding` with `matchedText` (if present),
 * `message`, and `remediation` all redacted via `redactSnippet`. `remediation`
 * is included as belt-and-suspenders for SAFE-01: `enricher.ts`'s
 * `buildPrompt` interpolates `remediation` verbatim into the provider
 * prompt, so it must pass through the same redaction gate as
 * `message`/`matchedText` before ever reaching `redactFinding`'s caller.
 * Never mutates the input — every other Finding field passes through
 * unchanged.
 */
export function redactFinding(finding: Finding): Finding {
  const redacted: Finding = {
    ...finding,
    message: redactSnippet(finding.message),
    remediation: redactSnippet(finding.remediation),
  };

  if (finding.matchedText !== undefined) {
    redacted.matchedText = redactSnippet(finding.matchedText);
  }

  return redacted;
}

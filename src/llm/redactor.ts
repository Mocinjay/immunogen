/**
 * Redactor — the SAFE-01 secret-redaction gate.
 *
 * This module is the network-boundary control for the LLM enrichment
 * stage. `Finding.matchedText`, `Finding.message`, and
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
 * child_process/eval/require on scanned content. Its only internal
 * dependency is `secret-patterns.ts` (the shared regex/entropy/keyword
 * source of truth also used by src/detectors/secrets/entropy-detector.ts) —
 * a dependency-free leaf itself, so this remains effectively leaf-level. A
 * later plan (07-03) wires this module into the provider-adapter request
 * path.
 */
import {
  ENTROPY_THRESHOLD,
  hasAnchorKeyword,
  JWT_RE,
  MIN_ENTROPY_CANDIDATE_LENGTH,
  PROVIDER_KEY_PATTERNS,
  QUOTED_STRING_RE,
  shannonEntropy,
  SUPABASE_ENV_NAME_RE,
} from "../detectors/secrets/secret-patterns.js";

import type { Finding } from "../core/types.js";

/** The fixed replacement token every detected secret span is replaced with. Never proportional to secret length — it must not leak size information either. */
export const REDACTED_PLACEHOLDER = "[REDACTED]";

/**
 * Anthropic API key — sk-ant-api03-<base64url-ish body>. Not present in
 * entropy-detector.ts's shared PROVIDER_KEY_PATTERNS table: that table's
 * OpenAI pattern (`sk-[A-Za-z0-9]{48}`) is fixed at exactly 48 trailing
 * characters and does not match this `sk-ant-api03-` prefixed shape
 * Anthropic issues. This is the SAFE-01 criterion-1 fixture pattern, so
 * redactor.ts layers it on top of the shared table as its one extra entry.
 * Checked BEFORE the shared OpenAI pattern below since both share the `sk-`
 * prefix; ordering does not actually matter for correctness (the two
 * patterns match disjoint shapes) but is kept for readability.
 */
const ANTHROPIC_KEY_PATTERN = /sk-ant-api03-[\w-]+/g;

/**
 * Fixed-format secret patterns (Pass 1): the shared PROVIDER_KEY_PATTERNS
 * regex table (Stripe/AWS/OpenAI) plus this module's own Anthropic/JWT/
 * Supabase-env-name entries layered on top. All entries carry the global
 * flag and are applied via `String.prototype.replaceAll` (not `.exec()` —
 * this project's ENG-05 ESLint rule forbids any member call literally named
 * `exec`, matching the child_process.exec/execSync/spawn family regardless
 * of receiver type).
 */
const SECRET_PATTERNS: RegExp[] = [
  ...PROVIDER_KEY_PATTERNS.map((pattern) => pattern.regex),
  // Anthropic API key — this module's one extra entry (see comment above).
  ANTHROPIC_KEY_PATTERN,
  // Supabase / generic JWT shape: three dot-separated base64url segments,
  // header segment anchored to the well-known `eyJ` prefix.
  JWT_RE,
  // Bare SUPABASE_SERVICE_ROLE_KEY identifier reference — a name-based
  // signal with no JWT body required.
  SUPABASE_ENV_NAME_RE,
];

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

/** The `Redactor` gate. Exposes `redactSnippet` as a namespaced object. */
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

/**
 * bundleSecretsDetector — WEB-SEC: live-looking provider secrets served to
 * the browser, found in same-origin `<script src>` bundles OR inline
 * `<script>...</script>` blocks on the fetched page itself.
 *
 * Reuses the shared `PROVIDER_KEY_PATTERNS` table from
 * `src/detectors/secrets/secret-patterns.ts` (Stripe `sk_live_`, AWS `AKIA...`,
 * OpenAI `sk-...`) — the exact same source of truth the static
 * `entropy-detector.ts` and `redactor.ts` already read from, per that file's
 * own header comment ("both files now import from here instead of
 * hand-copying the tables"). This detector is the THIRD consumer, not a
 * fourth hand-copied table.
 *
 * A secret served in a browser-reachable script bundle is unconditionally
 * worse than the same secret sitting in a repo's source file (this project's
 * static `entropy-detector.ts`/`SEC-0x` findings): it is already live in
 * front of every visitor, not merely committed. Severity is therefore
 * CRITICAL for the two highest-confidence live-key shapes (Stripe `sk_live_`,
 * AWS `AKIA...`) and HIGH for the OpenAI shape (still a real, rotate-now
 * finding, but the raw `sk-` shape alone is slightly more prone to
 * false-positive-shaped strings than the other two anchored formats).
 *
 * Redaction (SAFE-01 reuse, not reinvention): every matched secret span is
 * passed through `Redactor.redactSnippet` (src/llm/redactor.ts) before it is
 * ever placed into a Finding's `matchedText`/`message` — the raw secret value
 * must never appear in detector output, mirroring this project's existing
 * SAFE-01 network-boundary redaction gate rather than writing new masking
 * logic here.
 *
 * Inline `<script>` extraction is a simple regex text-pass (no HTML parser
 * dependency, matching this codebase's zero-extra-dependency convention —
 * see fetch-target.ts's own SCRIPT_SRC_RE precedent for the same rationale).
 *
 * `file:line` reporting: `finding.file` is the script's own URL for a
 * `<script src>` bundle, or the page URL for an inline script block;
 * `finding.line` is the 1-indexed line number WITHIN that script's body
 * (computed by counting newlines up to the match's start index) — for an
 * inline block this is the line within the extracted block's own text, not
 * the surrounding page's line number (there is no cheap way to recover the
 * original page-relative line without an HTML parser this project
 * deliberately does not depend on).
 *
 * No-throw contract (mirrors src/core/types.ts `Detector.detect`).
 */
import {
  GOOGLE_GENAI_CONTEXT_RE,
  GOOGLE_PUBLIC_CONTEXT_RE,
  PROVIDER_KEY_PATTERNS,
} from "../../detectors/secrets/secret-patterns.js";
import { Redactor } from "../../llm/redactor.js";

import type { Finding, Severity } from "../../core/types.js";
import type { WebContext, WebDetector } from "../types.js";

/**
 * Matches an inline `<script>...</script>` block with NO `src` attribute
 * (a `src`-bearing tag is handled separately via `target.scripts`, already
 * fetched by `fetchTarget`). Deliberately simple: excludes any `<script`
 * whose attributes contain `src=` via a negative lookahead, and is
 * non-greedy/dotall so it captures exactly one block's body at a time.
 */
const INLINE_SCRIPT_RE = /<script(?![^>]*\bsrc\s*=)[^>]*>([\s\S]*?)<\/script>/gi;

/** Per-ruleId (from PROVIDER_KEY_PATTERNS) severity for a live-looking key served to the browser. */
const SEVERITY_BY_PATTERN_RULE_ID: Record<string, Severity> = {
  "SEC-01": "CRITICAL", // Stripe sk_live_
  "SEC-02": "CRITICAL", // AWS AKIA...
  "SEC-03": "HIGH", // OpenAI sk-...
};

/** Human-readable provider name per shared ruleId (SEC-09 entries carry their own `provider`). */
const PROVIDER_BY_RULE_ID: Record<string, string> = {
  "SEC-01": "Stripe live secret key",
  "SEC-02": "AWS access key ID",
  "SEC-03": "OpenAI API key",
  "SEC-04": "Supabase secret key",
  "SEC-07": "Anthropic API key",
  "SEC-08": "private key",
};

/** Characters of surrounding bundle text examined to classify a Google `AIza...` key. */
const GOOGLE_CONTEXT_CHARS = 600;

/**
 * Google API keys in a browser bundle are almost always public-by-design
 * (Firebase web config, Maps, reCAPTCHA) and restricted by referrer, so one is
 * reported only when the surrounding code names Gemini / the Generative
 * Language API — a paid key that must never ship to the client — and nothing
 * marks it as public client config.
 */
function isReportableGoogleKey(body: string, index: number, length: number): boolean {
  const context = body.slice(Math.max(0, index - GOOGLE_CONTEXT_CHARS), index + length + GOOGLE_CONTEXT_CHARS);
  return GOOGLE_GENAI_CONTEXT_RE.test(context) && !GOOGLE_PUBLIC_CONTEXT_RE.test(context);
}

/** Extracts every inline `<script>` block's body text from `html`, in document order. */
function extractInlineScriptBodies(html: string): string[] {
  const bodies: string[] = [];
  for (const match of html.matchAll(INLINE_SCRIPT_RE)) {
    const body = match[1];
    if (body !== undefined && body.trim().length > 0) {
      bodies.push(body);
    }
  }
  return bodies;
}

/** 1-indexed line number of `index` within `text` (counts newlines up to that offset). */
function lineNumberAt(text: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index && i < text.length; i += 1) {
    // eslint-disable-next-line security/detect-object-injection -- `i` is a bounded numeric loop counter into a string, not attacker-controlled property access
    if (text[i] === "\n") {
      line += 1;
    }
  }
  return line;
}

/**
 * Scans a single source body (a script bundle's text, or one inline
 * `<script>` block's text) for every PROVIDER_KEY_PATTERNS match, returning
 * one Finding per match with the secret redacted.
 */
function scanBodyForSecrets(fileLabel: string, body: string): Finding[] {
  const findings: Finding[] = [];

  for (const pattern of PROVIDER_KEY_PATTERNS) {
    const isGoogle = pattern.provider === "Google";
    for (const match of body.matchAll(pattern.regex)) {
      const matchedRaw = match[0];
      const index = match.index;
      if (isGoogle && !isReportableGoogleKey(body, index, matchedRaw.length)) {
        continue;
      }
      const severity = isGoogle ? "CRITICAL" : (SEVERITY_BY_PATTERN_RULE_ID[pattern.ruleId] ?? "HIGH");
      const redactedMatch = Redactor.redactSnippet(matchedRaw);
      const provider = isGoogle ? "Google Gemini API key" : (pattern.provider ?? PROVIDER_BY_RULE_ID[pattern.ruleId] ?? "provider key");

      findings.push({
        ruleId: "WEB-SEC",
        category: "web",
        detectorName: "bundle-secrets",
        file: fileLabel,
        line: lineNumberAt(body, index),
        severity,
        confidence: "HIGH",
        message: `A live-looking ${provider} is served to the browser in this bundle.`,
        remediation:
          "Remove this key from any client-reachable bundle immediately and rotate it — a key served to the browser is exposed to every visitor, not just anyone with repo access.",
        matchedText: redactedMatch,
      });
    }
  }

  return findings;
}

export const bundleSecretsDetector: WebDetector = {
  id: "bundle-secrets",

  detect(ctx: WebContext): Finding[] {
    try {
      const findings: Finding[] = [];

      for (const script of ctx.target.scripts) {
        findings.push(...scanBodyForSecrets(script.url, script.body));
      }

      for (const inlineBody of extractInlineScriptBodies(ctx.target.body)) {
        findings.push(...scanBodyForSecrets(ctx.target.url, inlineBody));
      }

      return findings;
    } catch {
      return [];
    }
  },
};

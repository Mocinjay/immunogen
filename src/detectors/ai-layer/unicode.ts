// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
/**
 * unicode — ReDoS-safe hidden-content + deceptive-unicode helper shared by
 * the CAT-11 (AI Layer) MCP detectors (AILAYER-03).
 *
 * Reimplements (does not copy verbatim) the signature families documented
 * as NVIDIA SkillSpector's TP1 "Hidden Instructions" and TP2 "Unicode
 * Deception" patterns
 * ($HOME/.claude/skills/safety/skillspector/docs/B.3.2-mcp-tool-poisoning.md).
 * Per docs/LICENSING.md §2, adapting SkillSpector's pattern logic into a new
 * TypeScript expression requires the exact two-line SPDX header above,
 * copied character-for-character.
 *
 * This module is Finding-agnostic: both exported functions return plain
 * primitive-shaped objects (`{kind, snippet}` / `{kind, codepoint}`), never
 * a `Finding`. `mcp-poisoning-detector.ts` is the sole consumer today; any
 * future caller (a `.claude/skills/**` SKILL.md scanner, etc.) can reuse
 * these helpers without depending on the MCP-specific Finding-shaping
 * logic.
 *
 * ReDoS safety (threat T-06-02-02): zero-width / RTL-override /
 * invisible-formatting / homoglyph detection is O(n) codepoint-`Set`/`Map`
 * MEMBERSHIP testing — `for (const ch of text)` + `ch.codePointAt(0)` — NOT
 * a backtracking regex. The HTML/markdown-comment and base64-blob checks
 * DO use `RegExp`, but each pattern is bounded (lazy `*?` with no nested
 * quantifiers) and run with a single non-global `.match()` call (no
 * `matchAll`/global-flag re-entrancy), so a single call's cost is linear in
 * the input length. A co-located test asserts both functions return within
 * a small time budget on a 100_000-char benign string.
 *
 * No-throw contract: both functions are pure, total functions over
 * `string` — there is no I/O, no JSON parsing, and no externally-thrown
 * path here; callers (mcp-poisoning-detector.ts) still wrap their own
 * try/catch per src/core/types.ts `Detector.detect`'s no-throw contract,
 * but that is a property of the CALLER, not this module.
 */

/** A single hidden-content finding: which technique matched, plus a short, bounded snippet (never a decoded payload — threat T-06-02-04). */
export interface HiddenContentHit {
  kind: string;
  snippet: string;
}

/** A single deceptive-unicode finding: which technique matched, plus the offending codepoint formatted as `U+XXXX`. */
export interface DeceptiveUnicodeHit {
  kind: string;
  codepoint: string;
}

/** Maximum length of a `snippet`/source excerpt — bounds output even for a pathologically long input (threat T-06-02-04). */
const SNIPPET_MAX_LENGTH = 80;

/**
 * Truncates `text` to `SNIPPET_MAX_LENGTH` characters. Used for hidden-content
 * snippets so a giant base64 blob or comment body never blows up Finding
 * output, and the raw decoded payload is never re-emitted (threat T-06-02-04).
 */
function truncateSnippet(text: string): string {
  return text.length > SNIPPET_MAX_LENGTH ? `${text.slice(0, SNIPPET_MAX_LENGTH)}…` : text;
}

/**
 * Bounded, NON-global RegExp matching an HTML comment `<!-- ... -->`. Lazy
 * `*?` over a single comment body — no nested quantifiers — keeps this
 * linear per the module-level ReDoS note. NON-global: used once per call
 * via `String.prototype.match` (semantically equivalent to a single
 * `RegExp#exec`, see the project-wide `.exec()`-name-collision note on
 * exfiltration-detector.ts — this project's ENG-05 lint rule bans any
 * `.exec()`-named call regardless of receiver, so `.match()` is the house
 * style for "single, non-global pattern test").
 */
const HTML_COMMENT_RE = /<!--[\s\S]*?-->/;

/**
 * Bounded, NON-global RegExp matching a markdown comment
 * `[//]: # (...)`. The parenthesised body is matched with a bounded
 * non-newline run (`[^)]*?`), not an unbounded `[\s\S]*?`, since markdown
 * comments are conventionally single-line.
 */
const MARKDOWN_COMMENT_RE = /\[\/\/\]:\s*#\s*\([^)]*?\)/;

/**
 * Bounded, NON-global RegExp matching a `data:text/...;base64,...` URI
 * prefix plus its base64 payload. Checked BEFORE the generic base64-blob
 * regex below so a data-URI's payload is reported once as `data-uri`, not
 * double-counted as a second `base64-blob` hit (mirrors SkillSpector TP1's
 * documented ordering).
 */
const DATA_URI_RE = /data:text\/[\w.+-]+;base64,[A-Za-z0-9+/=]+/;

/**
 * Bounded, NON-global RegExp matching a 50+ character base64-alphabet run.
 * `{50,}` is a single fixed-floor quantifier on a flat character class — no
 * nesting, no ambiguity between adjacent alternatives — so this stays
 * linear and is not flagged by eslint-plugin-security's detect-unsafe-regex
 * heuristic.
 */
const BASE64_BLOB_RE = /[A-Za-z0-9+/=]{50,}/;

/** Zero-width / invisible-join characters (SkillSpector TP1 zero-width class: U+200B/U+200C/U+200D, plus the BOM/ZWNBSP U+FEFF used the same way). */
const ZERO_WIDTH_CODEPOINTS: ReadonlySet<number> = new Set([
  0x200b, // ZERO WIDTH SPACE
  0x200c, // ZERO WIDTH NON-JOINER
  0x200d, // ZERO WIDTH JOINER
  0xfeff, // ZERO WIDTH NO-BREAK SPACE / BOM
]);

/** RTL / directional-override / isolate characters (SkillSpector TP2 RTL class: U+202A-U+202E embeddings/overrides, U+2066-U+2069 isolates). */
const RTL_OVERRIDE_CODEPOINTS: ReadonlySet<number> = new Set([
  0x202a, // LEFT-TO-RIGHT EMBEDDING
  0x202b, // RIGHT-TO-LEFT EMBEDDING
  0x202c, // POP DIRECTIONAL FORMATTING
  0x202d, // LEFT-TO-RIGHT OVERRIDE
  0x202e, // RIGHT-TO-LEFT OVERRIDE
  0x2066, // LEFT-TO-RIGHT ISOLATE
  0x2067, // RIGHT-TO-LEFT ISOLATE
  0x2068, // FIRST STRONG ISOLATE
  0x2069, // POP DIRECTIONAL ISOLATE
]);

/** Invisible-formatting characters (SkillSpector TP2 "invisible formatting" class: soft hyphen, word joiner; CGJ — combining grapheme joiner — included for the same family). */
const INVISIBLE_FORMATTING_CODEPOINTS: ReadonlySet<number> = new Set([
  0x00ad, // SOFT HYPHEN
  0x2060, // WORD JOINER
  0x034f, // COMBINING GRAPHEME JOINER
]);

/**
 * Curated homoglyph confusables map (SkillSpector TP2's documented set):
 * Cyrillic lowercase а→a, е→e, о→o, р→p, с→c, у→y, і→i; Cyrillic uppercase
 * А→A, В→B, Е→E, К→K, М→M, Н→H, О→O, Р→P, С→C, Т→T, Х→X; Greek lowercase
 * α→a, ε→e, ο→o. Keyed by codepoint so lookup is a single `Map.has`/`Map.get`
 * — O(1) per character, no regex involved.
 */
const HOMOGLYPH_CONFUSABLES: ReadonlyMap<number, string> = new Map([
  // Cyrillic lowercase
  [0x0430, "a"], // а
  [0x0435, "e"], // е
  [0x043e, "o"], // о
  [0x0440, "p"], // р
  [0x0441, "c"], // с
  [0x0443, "y"], // у
  [0x0456, "i"], // і
  // Cyrillic uppercase
  [0x0410, "A"], // А
  [0x0412, "B"], // В
  [0x0415, "E"], // Е
  [0x041a, "K"], // К
  [0x041c, "M"], // М
  [0x041d, "H"], // Н
  [0x041e, "O"], // О
  [0x0420, "P"], // Р
  [0x0421, "C"], // С
  [0x0422, "T"], // Т
  [0x0425, "X"], // Х
  // Greek lowercase
  [0x03b1, "a"], // α
  [0x03b5, "e"], // ε
  [0x03bf, "o"], // ο
]);

/** Formats a numeric codepoint as a `U+XXXX` string (uppercase hex, zero-padded to at least 4 digits). */
function formatCodepoint(codepoint: number): string {
  return `U+${codepoint.toString(16).toUpperCase().padStart(4, "0")}`;
}

/**
 * Returns a non-empty list of hidden-content hits found in `text`: an HTML
 * comment, a markdown comment, a zero-width character, a
 * `data:text/...;base64,` URI, or a 50+ char base64 run. Returns `[]` for
 * plain visible text.
 *
 * Detection order matters: data-URI is checked before the generic
 * base64-blob pattern so its payload is reported once (as `data-uri`), not
 * double-counted as a second `base64-blob` hit (SkillSpector TP1's
 * documented ordering, B.3.2-mcp-tool-poisoning.md §3 TP1).
 */
export function findHiddenContent(text: string): HiddenContentHit[] {
  const hits: HiddenContentHit[] = [];

  const htmlCommentMatch = text.match(HTML_COMMENT_RE);
  if (htmlCommentMatch !== null) {
    hits.push({ kind: "html-comment", snippet: truncateSnippet(htmlCommentMatch[0]) });
  }

  const markdownCommentMatch = text.match(MARKDOWN_COMMENT_RE);
  if (markdownCommentMatch !== null) {
    hits.push({ kind: "markdown-comment", snippet: truncateSnippet(markdownCommentMatch[0]) });
  }

  // Zero-width characters: O(n) codepoint-Set membership, NOT a regex.
  for (const ch of text) {
    const codepoint = ch.codePointAt(0);
    if (codepoint !== undefined && ZERO_WIDTH_CODEPOINTS.has(codepoint)) {
      hits.push({ kind: "zero-width", snippet: formatCodepoint(codepoint) });
      break; // one hit per technique is sufficient signal; caller dedupes per field anyway
    }
  }

  const dataUriMatch = text.match(DATA_URI_RE);
  if (dataUriMatch !== null) {
    hits.push({ kind: "data-uri", snippet: truncateSnippet(dataUriMatch[0]) });
  } else {
    // Only check the generic base64-blob pattern when no data-URI already
    // claimed this text, so a data URI's own payload is never
    // double-counted as a second, separate base64-blob hit.
    const base64Match = text.match(BASE64_BLOB_RE);
    if (base64Match !== null) {
      hits.push({ kind: "base64-blob", snippet: truncateSnippet(base64Match[0]) });
    }
  }

  return hits;
}

/**
 * Returns a non-empty list of deceptive-unicode hits found in `text`: a
 * curated homoglyph, an RTL/directional-override character, or an
 * invisible-formatting character. Returns `[]` for pure ASCII / unicode
 * text with no deceptive characters.
 *
 * Iterates codepoints once (`for (const ch of text)`) and tests `Set`/`Map`
 * membership per character — O(n), no backtracking regex (threat
 * T-06-02-02).
 */
export function findDeceptiveUnicode(text: string): DeceptiveUnicodeHit[] {
  const hits: DeceptiveUnicodeHit[] = [];
  let foundHomoglyph = false;
  let foundRtlOverride = false;
  let foundInvisibleFormatting = false;

  for (const ch of text) {
    const codepoint = ch.codePointAt(0);
    if (codepoint === undefined) {
      continue;
    }

    if (!foundHomoglyph && HOMOGLYPH_CONFUSABLES.has(codepoint)) {
      hits.push({ kind: "homoglyph", codepoint: formatCodepoint(codepoint) });
      foundHomoglyph = true;
    }

    if (!foundRtlOverride && RTL_OVERRIDE_CODEPOINTS.has(codepoint)) {
      hits.push({ kind: "rtl-override", codepoint: formatCodepoint(codepoint) });
      foundRtlOverride = true;
    }

    if (!foundInvisibleFormatting && INVISIBLE_FORMATTING_CODEPOINTS.has(codepoint)) {
      hits.push({ kind: "invisible-formatting", codepoint: formatCodepoint(codepoint) });
      foundInvisibleFormatting = true;
    }

    // Early exit once every technique has reported at least one hit —
    // bounds the loop without weakening detection (each technique still
    // gets its first occurrence reported).
    if (foundHomoglyph && foundRtlOverride && foundInvisibleFormatting) {
      break;
    }
  }

  return hits;
}

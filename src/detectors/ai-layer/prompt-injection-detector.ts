// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
/**
 * promptInjectionDetector — CAT-11 (AI Layer) text detector, AILAYER-01.
 *
 * No competitor scans `.cursor/rules`, `.claude/skills/**\/*.md`, `AGENTS.md`,
 * or system-prompt files for embedded jailbreaks. A file in any of these
 * locations is read by an AI coding agent as part of its operating
 * instructions; if it contains an instruction-override directive ("ignore
 * previous instructions", "disregard safety", "you must now", "forget your
 * guidelines"...) that directive is a live jailbreak sitting in the
 * repository, not a hypothetical risk (.planning/research/FEATURES.md
 * AILAYER-01 row: severity CRITICAL, FP risk LOW).
 *
 * This module REIMPLEMENTS (does not copy verbatim) the signature family
 * documented as NVIDIA SkillSpector's P1 "Instruction Override" pattern and
 * TP3's "Instruction override phrases" sub-pattern
 * ($HOME/.claude/skills/safety/skillspector/docs/B.3.2-mcp-tool-poisoning.md)
 * as a curated set of bounded, case-insensitive, non-global RegExp constants
 * — one per phrase family. Per docs/LICENSING.md §2, adapting SkillSpector's
 * pattern logic into a new TypeScript expression requires the exact
 * two-line SPDX header above, copied character-for-character.
 *
 * FP allowlist (.planning/research/PITFALLS.md Pitfall 1): `detect()` opens
 * with the same path-segment check against `__tests__`, `fixtures`,
 * `mocks`, `examples`, plus a `.test.`/`.stories.` basename check, mirroring
 * src/detectors/storage/firebase-rules-detector.ts `isAllowlistedPath`.
 *
 * ENG-05 (text-only invariant, threat T-06-01-01): this module reads
 * `ctx.content` as a plain string only. It never reads `ctx.ast`, never
 * imports a parser, and never evaluates, requires, `new Function`s, or
 * spawns a subprocess from scanned content — these are TEXT detectors.
 *
 * ReDoS safety (threat T-06-01-02): every pattern below is bounded — no
 * nested quantifiers, no unbounded `.*` spanning the whole line — and each
 * regex is run per-line (content is split on `\n` first), so the input to
 * any single `.test()` call is bounded by that line's own length.
 *
 * Information-disclosure safety (threat T-06-01-03): `matchedText` is the
 * trimmed line, truncated to a fixed 120-character cap, so a hostile file
 * with a giant line cannot blow up output or leak more than a short
 * snippet.
 *
 * No-throw contract (src/core/types.ts `Detector.detect`): the entire body
 * runs inside try/catch returning `[]` on any failure.
 */
import type { Detector, DetectorContext, Finding } from "../../core/types.js";

/** Path segments that suppress every finding in this file (FP allowlist — PITFALLS.md Pitfall 1). */
const FP_ALLOWLIST_SEGMENTS = new Set(["__tests__", "fixtures", "mocks", "examples"]);

/** Maximum length of a `matchedText` snippet — bounds output even for a pathologically long line (threat T-06-01-03). */
const MATCHED_TEXT_MAX_LENGTH = 120;

/**
 * True when `filePath` falls inside a test/fixture/mock/example directory,
 * or its basename marks it as a test or story file (`.test.` / `.stories.`).
 * Mirrors src/detectors/storage/firebase-rules-detector.ts `isAllowlistedPath`.
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
 * Truncates `line` (already trimmed) to `MATCHED_TEXT_MAX_LENGTH` characters,
 * so a hostile file with a giant single line cannot blow up Finding output
 * (threat T-06-01-03).
 */
function truncateMatchedText(line: string): string {
  return line.length > MATCHED_TEXT_MAX_LENGTH ? line.slice(0, MATCHED_TEXT_MAX_LENGTH) : line;
}

/**
 * Curated instruction-override phrase families, reimplemented (not copied)
 * from the publicly documented SkillSpector P1/TP3 signature description.
 * Each entry is a bounded, case-insensitive, NON-global RegExp — NO global
 * flag, because every pattern is only ever used with `.test()` inside a
 * per-line loop, never `matchAll`; a global-flagged regex used with `.test()`
 * is stateful (`lastIndex` persists on the shared module-level instance
 * across calls), which would silently skip matches on later lines — the
 * same gotcha documented on firebase-rules-detector.ts's ALLOW_IF_TRUE_RE.
 *
 * Bounded character classes / fixed-cardinality groups only — no
 * `.*`/unbounded-quantifier spans — keeps each pattern ReDoS-safe
 * (threat T-06-01-02).
 */
const INSTRUCTION_OVERRIDE_PATTERNS: readonly RegExp[] = [
  // ignore (previous|prior|all|above) (instructions|prompts|rules)
  /ignore\s+(previous|prior|all|above)\s+(instructions|prompts|rules)/i,
  // ignore all/every (previous|prior|above) (instructions|prompts|rules)
  // — a SEPARATE pattern (not an optional prefix on the one above) so the
  // two alternations never overlap on the literal "all": the prior combined
  // form `(?:all|every)?\s*(previous|prior|all|above)` let the engine reach
  // the same input position via two different paths when the qualifier and
  // the following alternative were both "all", which is the classic
  // ambiguous-backtracking shape eslint-plugin-security's
  // detect-unsafe-regex heuristic flags. Splitting into two fixed,
  // non-overlapping patterns keeps full phrase coverage ("ignore all
  // previous instructions") while eliminating the ambiguity outright.
  /ignore\s+(?:all|every)\s+(previous|prior|above)\s+(instructions|prompts|rules)/i,
  // disregard (safety|previous|all|the) ...
  /disregard\s+(safety|previous|all|the)\s+\w+/i,
  // forget (your|the|all) (guidelines|instructions|rules|training)
  /forget\s+(your|the|all)\s+(guidelines|instructions|rules|training)/i,
  // you (must|will|are to) now
  /you\s+(must|will|are\s+to)\s+now/i,
  // you are now (a|an|in) ...
  /you\s+are\s+now\s+(a|an|in)\s+\w+/i,
  // override (your|the|all|safety)
  /override\s+(your|the|all|safety)\s+\w+/i,
  // bypass (your|the|all|safety)
  /bypass\s+(your|the|all|safety)\s+\w+/i,
  // do not follow (your|the|previous)
  /do\s+not\s+follow\s+(your|the|previous)\s+\w+/i,
];

export const promptInjectionDetector: Detector = {
  config: {
    name: "prompt-injection",
    category: "ai-layer",
    globs: [
      "**/.cursor/rules",
      "**/.cursor/rules/**",
      "**/.cursorrules",
      "**/.claude/skills/**/*.md",
      "**/AGENTS.md",
      "**/CLAUDE.md",
      "**/system-prompt.md",
      "**/system_prompt.md",
      "**/.github/copilot-instructions.md",
    ],
  },

  // Not declared `async` — no network/disk wait in this text-only detector;
  // the body is plain synchronous work wrapped in `Promise.resolve()`,
  // matching firebase-rules-detector.ts's convention.
  detect(ctx: DetectorContext): Promise<Finding[]> {
    try {
      // FP allowlist (PITFALLS.md Pitfall 1): suppress every finding for
      // test/fixture/mock/example/story paths.
      if (isAllowlistedPath(ctx.filePath)) {
        return Promise.resolve([]);
      }

      const findings: Finding[] = [];
      const lines = ctx.content.split("\n");

      // `.entries()` (not bracket indexing) avoids a dynamic-index access
      // pattern entirely — sidesteps security/detect-object-injection.
      for (const [index, line] of lines.entries()) {
        // Emit at most ONE finding per line: stop at the first pattern that
        // matches, do not check the remaining patterns against this line.
        const matched = INSTRUCTION_OVERRIDE_PATTERNS.find((pattern) => pattern.test(line));
        if (!matched) {
          continue;
        }

        const trimmedLine = line.trim();
        findings.push({
          ruleId: "AILAYER-01",
          category: "ai-layer",
          detectorName: "prompt-injection",
          file: ctx.filePath,
          line: index + 1, // 1-indexed per src/core/types.ts Finding.line
          severity: "CRITICAL",
          confidence: "HIGH",
          message:
            "Prompt-injection / instruction-override directive found in an agent config file (.cursor/rules, .claude/skills, AGENTS.md, CLAUDE.md, or a system-prompt file).",
          remediation:
            "Remove this instruction-override directive from the agent/rules/skill file; agent config must never contain jailbreak or guideline-bypass instructions.",
          matchedText: truncateMatchedText(trimmedLine),
        });
      }

      return Promise.resolve(findings);
    } catch {
      // No-throw contract (src/core/types.ts Detector.detect): a malformed
      // or unexpected ctx.content must resolve to [], never reject.
      return Promise.resolve([]);
    }
  },
};

// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
/**
 * mcpPoisoningDetector — CAT-11 (AI Layer) MCP/JSON detector, AILAYER-03.
 *
 * MCP tool manifests (`.mcp.json`, `.cursor/mcp.json`) declare server/tool
 * metadata — names, descriptions, parameter descriptions — that an AI
 * coding agent reads as part of its tool-use context when deciding which
 * tool to invoke and how. This metadata is a first-class attack surface
 * (CVE-2025-54136-class MCP tool poisoning): a hidden HTML comment or
 * zero-width run in a `description` field can steer agent behavior without
 * the user ever seeing it, and a homoglyph in a tool `name` can make a
 * malicious tool visually indistinguishable from a trusted one.
 *
 * This module REIMPLEMENTS (does not copy verbatim) the signature families
 * documented as NVIDIA SkillSpector's TP1 "Hidden Instructions" and TP2
 * "Unicode Deception" patterns
 * ($HOME/.claude/skills/safety/skillspector/docs/B.3.2-mcp-tool-poisoning.md),
 * delegating the actual character/pattern scanning to the shared
 * `src/detectors/ai-layer/unicode.ts` helper (Plan 06-02 Task 1). Per
 * docs/LICENSING.md §2, adapting SkillSpector's pattern logic into a new
 * TypeScript expression requires the exact two-line SPDX header above,
 * copied character-for-character.
 *
 * SEVERITY TIERING (this plan's own must_haves + REQUIREMENTS.md AILAYER-03
 * checklist text, authoritative over FEATURES.md's older AILAYER-03/04 row
 * split — same "plan's literal naming is authoritative" precedent already
 * used in 05-02/05-03/05-05): TP1 hidden-content hits (comments, zero-width,
 * data-URI, base64 blob) are CRITICAL — an agent-readable directive hiding
 * in plain sight is the strongest, least-ambiguous signal. TP2
 * deceptive-unicode hits (homoglyph, RTL-override, invisible-formatting)
 * are HIGH — visually deceptive but not necessarily an active instruction.
 * Both tiers share confidence HIGH: these are literal character-level
 * matches on scanned text, not absence-based inference (contrast with
 * AILAYER-04's MEDIUM/MEDIUM absence-evidence discipline in the sibling
 * mcp-least-privilege-detector.ts).
 *
 * PARSE-AS-DATA INVARIANT (ENG-05, threat T-06-02-01): `JSON.parse` is the
 * ONLY operation ever applied to `ctx.content`. The parsed object's string
 * fields are read and pattern-matched; the parsed data is never evaluated,
 * dynamically imported, wrapped in a constructed function body, or handed
 * to a subprocess. A declared `command`/`args` string (if present on a
 * server entry) is treated as inert text for pattern-matching only, never
 * executed — this detector doesn't even read those fields (that's
 * mcp-least-privilege-detector.ts's job).
 *
 * SHAPE TOLERANCE (threat T-06-02-03): the parsed JSON's shape is walked
 * defensively with `typeof` guards at every step. The canonical shape is
 * `{ mcpServers: { [serverName]: { tools: [{ name, description,
 * parameters }] } } }`, but a top-level `tools`/`servers` variant is also
 * tolerated. Any unexpected shape yields "no strings found" (zero
 * findings), never a throw.
 *
 * FP allowlist (.planning/research/PITFALLS.md Pitfall 1): same
 * `__tests__`/`fixtures`/`mocks`/`examples` + `.test.`/`.stories.` guard as
 * firebase-rules-detector.ts's `isAllowlistedPath`.
 *
 * Information-disclosure safety (threat T-06-02-04): `matchedText` never
 * echoes a decoded payload — it names the technique kind plus the shared
 * helper's own already-bounded/masked snippet (unicode.ts's
 * `SNIPPET_MAX_LENGTH` truncation), further capped here.
 *
 * No-throw contract (src/core/types.ts `Detector.detect`): the entire body
 * runs inside try/catch returning `[]` on any failure — including a
 * `JSON.parse` failure on malformed/hostile JSON.
 */
import { findDeceptiveUnicode, findHiddenContent } from "./unicode.js";

import type { Detector, DetectorContext, Finding, Severity } from "../../core/types.js";
import { isTestOrFixturePath } from "../shared/test-paths.js";

/** Maximum length of a `matchedText` snippet — bounds output even for a pathologically long field value. */
const MATCHED_TEXT_MAX_LENGTH = 120;

/** A single collected metadata string plus which field it came from, used for line-resolution + message wording. */
interface MetadataString {
  value: string;
  field: string;
}

/**
 * Pushes `value` onto `out` as a `MetadataString` tagged with `field`, but
 * only when `value` is a non-empty string — every call site below reads an
 * `unknown`-typed property off a freshly `JSON.parse`d object, so this is
 * the single point where the "collect strings defensively" contract
 * (threat T-06-02-03) is enforced.
 */
function collectIfString(out: MetadataString[], value: unknown, field: string): void {
  if (typeof value === "string" && value.length > 0) {
    out.push({ value, field });
  }
}

/**
 * Collects every `name`/`description` metadata string out of one tool
 * object (`unknown`-typed — straight off `JSON.parse`). Tolerates a
 * `parameters` array, each entry contributing its own `description`.
 * Every property access is guarded so an unexpected tool shape simply
 * contributes zero strings rather than throwing.
 */
function collectToolStrings(tool: unknown, serverLabel: string): MetadataString[] {
  const strings: MetadataString[] = [];
  if (typeof tool !== "object" || tool === null) {
    return strings;
  }
  const toolRecord = tool as Record<string, unknown>;

  collectIfString(strings, toolRecord["name"], `${serverLabel} tool name`);
  collectIfString(strings, toolRecord["description"], `${serverLabel} tool description`);

  const parameters = toolRecord["parameters"];
  if (Array.isArray(parameters)) {
    for (const parameter of parameters) {
      if (typeof parameter !== "object" || parameter === null) {
        continue;
      }
      const parameterRecord = parameter as Record<string, unknown>;
      collectIfString(
        strings,
        parameterRecord["description"],
        `${serverLabel} parameter description`,
      );
    }
  }

  return strings;
}

/**
 * Collects every tool-metadata string out of one server object (`unknown`
 * -typed). A server may declare its own top-level `description` in
 * addition to a `tools` array; both are collected. Tolerates a `tools`
 * array being absent entirely (a docs-only / no-tool server contributes
 * only its own description, if any).
 */
function collectServerStrings(server: unknown, serverLabel: string): MetadataString[] {
  const strings: MetadataString[] = [];
  if (typeof server !== "object" || server === null) {
    return strings;
  }
  const serverRecord = server as Record<string, unknown>;

  collectIfString(strings, serverRecord["description"], `${serverLabel} description`);

  const tools = serverRecord["tools"];
  if (Array.isArray(tools)) {
    for (const tool of tools) {
      strings.push(...collectToolStrings(tool, serverLabel));
    }
  }

  return strings;
}

/**
 * Walks the parsed `.mcp.json` object (already `JSON.parse`d — DATA only,
 * never executed, ENG-05) and collects every tool/server metadata string
 * found. Tolerates three shape variants, checked in order:
 *   1. Canonical: `{ mcpServers: { [name]: server } }`
 *   2. Top-level `servers` map variant: `{ servers: { [name]: server } }`
 *   3. Top-level `tools` array variant (no server wrapper at all):
 *      `{ tools: [...] }`
 * Any other top-level shape (or a non-object root) contributes zero
 * strings — the defensive "unknown shape yields no strings found"
 * contract (threat T-06-02-03), never a throw.
 */
function collectMetadataStrings(parsed: unknown): MetadataString[] {
  const strings: MetadataString[] = [];
  if (typeof parsed !== "object" || parsed === null) {
    return strings;
  }
  const root = parsed as Record<string, unknown>;

  const serverMap = root["mcpServers"] ?? root["servers"];
  if (typeof serverMap === "object" && serverMap !== null) {
    for (const [serverName, server] of Object.entries(serverMap as Record<string, unknown>)) {
      strings.push(...collectServerStrings(server, `server "${serverName}"`));
    }
  }

  const topLevelTools = root["tools"];
  if (Array.isArray(topLevelTools)) {
    for (const tool of topLevelTools) {
      strings.push(...collectToolStrings(tool, "top-level"));
    }
  }

  return strings;
}

/**
 * Truncates `text` to `MATCHED_TEXT_MAX_LENGTH` characters — a second,
 * detector-level cap on top of unicode.ts's own already-bounded snippet
 * output (threat T-06-02-04).
 */
function truncateMatchedText(text: string): string {
  return text.length > MATCHED_TEXT_MAX_LENGTH ? text.slice(0, MATCHED_TEXT_MAX_LENGTH) : text;
}

/**
 * Resolves the 1-indexed `line` at which `value` (a collected metadata
 * string) first appears in the RAW `rawContent`. Splits `rawContent` into
 * lines and finds the first line whose text includes `value` as a literal
 * substring — this only works for values short enough to plausibly appear
 * on one JSON line, which is true of every field this detector reads
 * (tool names, descriptions, parameter descriptions are all JSON string
 * literals). Falls back to line 1 if the value cannot be located (e.g. a
 * pretty-printer wrapped it across lines, or minified JSON puts everything
 * on one line — the line-1 fallback keeps the finding meaningful either
 * way, per this plan's own line-resolution spec).
 */
function resolveLine(rawContent: string, value: string): number {
  const lines = rawContent.split("\n");
  for (const [index, line] of lines.entries()) {
    if (line.includes(value)) {
      return index + 1; // 1-indexed per src/core/types.ts Finding.line
    }
  }
  return 1;
}

/** De-dup key: one finding per (field-string, technique-tier) pair (this plan's own de-dup spec). */
function dedupeKey(fieldValue: string, tier: "hidden-content" | "deceptive-unicode"): string {
  return `${tier}:${fieldValue}`;
}

export const mcpPoisoningDetector: Detector = {
  config: {
    name: "mcp-poisoning",
    category: "ai-layer",
    globs: ["**/.mcp.json", "**/.cursor/mcp.json"],
  },

  // Not declared `async` — no network/disk wait in this JSON-only detector;
  // body is plain synchronous work wrapped in `Promise.resolve()`, matching
  // firebase-rules-detector.ts's convention.
  detect(ctx: DetectorContext): Promise<Finding[]> {
    try {
      // FP allowlist (PITFALLS.md Pitfall 1): suppress every finding for
      // test/fixture/mock/example/story paths.
      if (isTestOrFixturePath(ctx.filePath)) {
        return Promise.resolve([]);
      }

      // Parse-as-DATA only (ENG-05, threat T-06-02-01): JSON.parse is the
      // ONLY operation applied to ctx.content. A parse failure on
      // malformed/hostile JSON falls through to the outer catch -> [].
      const parsed: unknown = JSON.parse(ctx.content);
      const metadataStrings = collectMetadataStrings(parsed);

      const findings: Finding[] = [];
      const seen = new Set<string>();

      for (const { value, field } of metadataStrings) {
        const hiddenContentHits = findHiddenContent(value);
        if (hiddenContentHits.length > 0) {
          const key = dedupeKey(value, "hidden-content");
          if (!seen.has(key)) {
            seen.add(key);
            const firstHit = hiddenContentHits[0];
            const severity: Severity = "CRITICAL";
            findings.push({
              ruleId: "AILAYER-03",
              category: "ai-layer",
              detectorName: "mcp-poisoning",
              file: ctx.filePath,
              line: resolveLine(ctx.content, value),
              severity,
              confidence: "HIGH",
              message: `Hidden instruction (${firstHit?.kind ?? "hidden-content"}) found in an MCP ${field} — an AI agent reads this metadata as context.`,
              remediation:
                "Remove hidden or deceptive content from MCP tool metadata; tool names and descriptions must be plain visible ASCII text — an agent reads these as instructions.",
              matchedText: truncateMatchedText(
                `${firstHit?.kind ?? "hidden-content"}: ${firstHit?.snippet ?? ""}`,
              ),
            });
          }
        }

        const deceptiveUnicodeHits = findDeceptiveUnicode(value);
        if (deceptiveUnicodeHits.length > 0) {
          const key = dedupeKey(value, "deceptive-unicode");
          if (!seen.has(key)) {
            seen.add(key);
            const firstHit = deceptiveUnicodeHits[0];
            const severity: Severity = "HIGH";
            findings.push({
              ruleId: "AILAYER-03",
              category: "ai-layer",
              detectorName: "mcp-poisoning",
              file: ctx.filePath,
              line: resolveLine(ctx.content, value),
              severity,
              confidence: "HIGH",
              message: `Deceptive unicode (${firstHit?.kind ?? "deceptive-unicode"}, ${firstHit?.codepoint ?? ""}) found in an MCP ${field} — visually spoofs a trusted tool.`,
              remediation:
                "Remove hidden or deceptive content from MCP tool metadata; tool names and descriptions must be plain visible ASCII text — an agent reads these as instructions.",
              matchedText: truncateMatchedText(
                `${firstHit?.kind ?? "deceptive-unicode"}: ${firstHit?.codepoint ?? ""}`,
              ),
            });
          }
        }
      }

      return Promise.resolve(findings);
    } catch {
      // No-throw contract (src/core/types.ts Detector.detect): a malformed
      // JSON.parse (or any other unexpected failure) must resolve to [],
      // never reject.
      return Promise.resolve([]);
    }
  },
};

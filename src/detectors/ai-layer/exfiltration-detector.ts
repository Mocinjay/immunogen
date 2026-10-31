// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
/**
 * exfiltrationDetector — CAT-11 (AI Layer) text detector, AILAYER-02.
 *
 * The sibling of AILAYER-01 (prompt-injection-detector.ts): a skill/rules
 * file scanned by an AI coding agent that instructs sending conversation
 * context, environment variables, or secrets to an external destination is
 * a live data-exfiltration directive sitting in the repository (severity
 * CRITICAL; false-positive risk is low, see the triple gate below).
 *
 * This module REIMPLEMENTS (does not copy verbatim) the signature family
 * documented as NVIDIA SkillSpector's P3 "Exfiltration Commands" pattern
 * and TP3's "Exfiltration instructions" sub-pattern ("send to", "transmit",
 * "upload conversation";
 * $HOME/.claude/skills/safety/skillspector/docs/B.3.2-mcp-tool-poisoning.md)
 * as bounded regex clauses. Per docs/LICENSING.md §2, adapting
 * SkillSpector's pattern logic requires the exact two-line SPDX header
 * above, copied character-for-character.
 *
 * FP-DISCIPLINE MECHANISM (the core design decision of this detector): a
 * finding fires ONLY on the CO-OCCURRENCE, on a single line, of all three:
 *   (a) an exfiltration ACTION verb — send/transmit/upload/exfiltrate/POST/
 *       curl/wget/fetch
 *   (b) a CONTEXT/SECRET reference — process.env, os.environ, env,
 *       conversation, context, history, secret, token, api key, credentials
 *   (c) an EXTERNAL destination — an https?:// URL whose host is NOT
 *       localhost/127.0.0.1/0.0.0.0, OR a `| base64` / `| base32` pipe
 *       encoding a harvested value
 * A bare URL alone, or a bare "send" alone, never fires — this triple-gate
 * is what keeps FP risk LOW (Test 4:
 * "See the docs at https://nextjs.org/docs" has a URL but no action/context
 * and must stay silent; Test 5: "send the result to http://localhost:3000"
 * has an action but no context-ref AND is localhost, so it must also stay
 * silent).
 *
 * FP allowlist: same
 * `__tests__`/`fixtures`/`mocks`/`examples` + `.test.`/`.stories.` guard as
 * prompt-injection-detector.ts's `isAllowlistedPath`.
 *
 * ENG-05 (text-only invariant): reads `ctx.content` as a
 * plain string only — never `ctx.ast`, never a parser, never eval/require/
 * `new Function`/subprocess on scanned content.
 *
 * ReDoS safety: every clause below is bounded — no
 * nested quantifiers, no unbounded `.*` spanning the whole line — and all
 * are run per-line (content split on `\n` first).
 *
 * Information-disclosure safety: `matchedText` is the
 * trimmed line, truncated to a fixed 120-character cap; the detector never
 * decodes or re-emits the secret value itself, only the directive line that
 * names it.
 *
 * No-throw contract (src/core/types.ts `Detector.detect`): the entire body
 * runs inside try/catch returning `[]` on any failure.
 */
import type { Detector, DetectorContext, Finding } from "../../core/types.js";
import { isTestOrFixturePath } from "../shared/test-paths.js";

/** Maximum length of a `matchedText` snippet — bounds output even for a pathologically long line. */
const MATCHED_TEXT_MAX_LENGTH = 120;

/**
 * Truncates `line` (already trimmed) to `MATCHED_TEXT_MAX_LENGTH`
 * characters.
 */
function truncateMatchedText(line: string): string {
  return line.length > MATCHED_TEXT_MAX_LENGTH ? line.slice(0, MATCHED_TEXT_MAX_LENGTH) : line;
}

/**
 * Clause (a): exfiltration ACTION verb. Bounded word-boundary alternation,
 * no unbounded quantifiers. `\b` boundaries avoid
 * matching inside unrelated identifiers (e.g. "depostal" must not match
 * "post"); the alternation itself stays short and fixed.
 */
const ACTION_RE = /\b(send|transmit|upload|exfiltrate|post|curl|wget|fetch)\b/i;

/**
 * Clause (b): CONTEXT/SECRET reference. `process\.env`/`os\.environ` are
 * literal dotted identifiers (escaped `.`); `\benv\b` is boundary-anchored
 * so it doesn't match inside "environment" by accident while still
 * matching the literal word "env" (e.g. "env | base64"); the remaining
 * alternatives are common English words for the same concept. All
 * fixed-cardinality, no nested quantifiers.
 */
const CONTEXT_REF_RE =
  /(process\.env|os\.environ|\benv\b|conversation|context|history|secret|token|api[_-]?key|credentials)/i;

/**
 * Clause (c) external-URL half: an `http(s)://` URL. Host capture group is
 * a bounded run of non-whitespace/non-slash characters (no unbounded `.*`),
 * checked against the localhost/loopback denylist by `isExternalHost`
 * below. NON-global — used with `.exec()` once per line inside the loop.
 */
const URL_RE = /https?:\/\/([^\s/]+)/i;

/**
 * Clause (c) base64/base32-pipe half: a `|` pipe into `base64` or `base32`,
 * the classic "harvest then encode for exfil" shell idiom. Bounded
 * whitespace runs only.
 */
const BASE_ENCODE_PIPE_RE = /\|\s*base(?:32|64)\b/i;

/** Loopback/local hostnames that do NOT count as an "external" destination for clause (c). */
const LOCAL_HOSTS = new Set(["localhost", "127.0.0.1", "0.0.0.0", "[::1]", "::1"]);

/**
 * True when `host` (the captured URL authority, e.g. "evil.example.com" or
 * "localhost:3000") is an external (non-loopback) destination. Strips an
 * optional trailing `:port` before checking against `LOCAL_HOSTS`, and
 * additionally excludes the loopback IP range `127.0.0.0/8` written as
 * `127.x.x.x` (not just the canonical `127.0.0.1`).
 */
function isExternalHost(host: string): boolean {
  const hostnameOnly = host.split(":")[0] ?? host;
  if (LOCAL_HOSTS.has(hostnameOnly)) {
    return false;
  }
  if (/^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostnameOnly)) {
    return false;
  }
  return true;
}

/**
 * True when `line` contains clause (c): either an external (non-loopback)
 * `http(s)://` URL, or a `| base64`/`| base32` harvest-and-encode pipe.
 *
 * Uses `String.prototype.match` (not `RegExp.prototype.exec`) deliberately:
 * this project's ESLint config (eslint.config.js, ENG-05 enforcement) bans
 * any call whose member name is literally `exec` — a blunt, name-based AST
 * selector that cannot distinguish `RegExp#exec` from `child_process.exec`.
 * `.match()` on a non-global RegExp is semantically equivalent to `.exec()`
 * here (single match, same capture-group result shape) and sidesteps the
 * name collision without weakening the real ENG-05 rule.
 */
function hasExternalDestination(line: string): boolean {
  if (BASE_ENCODE_PIPE_RE.test(line)) {
    return true;
  }
  const urlMatch = line.match(URL_RE);
  if (urlMatch === null) {
    return false;
  }
  const host = urlMatch[1];
  return host !== undefined && isExternalHost(host);
}

export const exfiltrationDetector: Detector = {
  config: {
    name: "exfiltration",
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
  // body is plain synchronous work wrapped in `Promise.resolve()`, matching
  // prompt-injection-detector.ts's convention.
  detect(ctx: DetectorContext): Promise<Finding[]> {
    try {
      // FP allowlist: suppress every finding for
      // test/fixture/mock/example/story paths.
      if (isTestOrFixturePath(ctx.filePath)) {
        return Promise.resolve([]);
      }

      const findings: Finding[] = [];
      const lines = ctx.content.split("\n");

      // `.entries()` (not bracket indexing) avoids a dynamic-index access
      // pattern entirely — sidesteps security/detect-object-injection.
      for (const [index, line] of lines.entries()) {
        // Triple-gate: action AND context-ref AND external-destination must
        // ALL match the same line. Any single missing clause means no
        // finding — this is the FP-discipline mechanism.
        if (!ACTION_RE.test(line)) {
          continue;
        }
        if (!CONTEXT_REF_RE.test(line)) {
          continue;
        }
        if (!hasExternalDestination(line)) {
          continue;
        }

        const trimmedLine = line.trim();
        findings.push({
          ruleId: "AILAYER-02",
          category: "ai-layer",
          detectorName: "exfiltration",
          file: ctx.filePath,
          line: index + 1, // 1-indexed per src/core/types.ts Finding.line
          severity: "CRITICAL",
          confidence: "HIGH",
          message:
            "Context/credential exfiltration directive found in an agent config file: instructs sending conversation context, environment variables, or secrets to an external destination.",
          remediation:
            "Remove this exfiltration directive; agent/skill/rules files must not instruct sending conversation context, environment variables, or secrets to an external URL.",
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

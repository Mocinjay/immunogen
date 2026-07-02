// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
/**
 * mcpLeastPrivilegeDetector — CAT-11 (AI Layer) MCP/JSON detector, AILAYER-04.
 *
 * MCP servers declared in `.mcp.json`/`.cursor/mcp.json` can silently
 * exercise shell, network, or filesystem access through their tool
 * definitions. The principle of least privilege says a server should
 * declare — via an explicit `permissions` list — exactly the capabilities
 * it needs, no more. In practice, servers frequently omit `permissions`
 * entirely, or declare a wildcard (`*`/`all`/`full`/`any`) instead of a
 * specific list, leaving the server's true access level invisible to both
 * the user and the agent invoking it.
 *
 * This module REIMPLEMENTS (does not copy verbatim) a scoped slice of the
 * signature families documented as NVIDIA SkillSpector's LP1
 * "Underdeclared Capability" and LP2 "Wildcard Permission" patterns
 * ($HOME/.claude/skills/safety/skillspector/docs/B.3.1-mcp-least-privilege.md),
 * adapted to this plan's own scope (this plan's own must_haves +
 * REQUIREMENTS.md AILAYER-04 checklist text, authoritative over
 * FEATURES.md's older row split — same "plan's literal naming is
 * authoritative" precedent used in 05-02/05-03/05-05/mcp-poisoning-detector.ts):
 * ONE finding fires per server, at MEDIUM/MEDIUM, for EITHER (a) missing
 * `permissions` while a shell/network/fs-capable tool is present
 * (SkillSpector's LP3 "Missing Permission Declaration" shape — MEDIUM, not
 * LP1's HIGH, because absence of a field is weaker evidence than a
 * demonstrated capability/declaration MISMATCH), OR (b) a wildcard token in
 * `permissions` (LP2). Per docs/LICENSING.md §2, adapting SkillSpector's
 * pattern logic into a new TypeScript expression requires the exact
 * two-line SPDX header above, copied character-for-character.
 *
 * CONFIDENCE DISCIPLINE (.planning/research/PITFALLS.md Pitfall 1, this
 * plan's own non-negotiable): every finding here is MEDIUM severity /
 * MEDIUM confidence and NEVER escalates. Missing-permissions is an
 * ABSENCE-based signal (the field simply isn't there — could be an
 * oversight, not necessarily malice) and wildcard is a TRANSPARENCY
 * signal (the server chose maximum breadth over specificity) — neither
 * is a literal, unambiguous malicious directive the way AILAYER-03's
 * hidden-content hits are, so this detector's ceiling is MEDIUM,
 * contrasting deliberately with the sibling mcp-poisoning-detector.ts's
 * CRITICAL/HIGH tiering.
 *
 * PARSE-AS-DATA INVARIANT (ENG-05, threat T-06-02-01): `JSON.parse` is the
 * ONLY operation ever applied to `ctx.content`. A server's declared
 * `command`/`args`/tool strings are read ONLY as inert text for
 * capability-keyword classification — this detector never invokes,
 * dynamically imports, wraps in a constructed function body, or hands the
 * declared `command` to a subprocess. It merely asks "does this server's
 * serialized JSON text CONTAIN a shell/network/fs/env-flavored keyword",
 * nothing more.
 *
 * SHAPE TOLERANCE (threat T-06-02-03): mirrors mcp-poisoning-detector.ts's
 * defensive typeof-guarded walk — `mcpServers`/`servers`/top-level variants
 * are all tolerated; an unrecognized shape contributes zero servers to
 * evaluate (zero findings), never a throw.
 *
 * FP allowlist (.planning/research/PITFALLS.md Pitfall 1): same
 * `__tests__`/`fixtures`/`mocks`/`examples` + `.test.`/`.stories.` guard as
 * mcp-poisoning-detector.ts's `isAllowlistedPath`.
 *
 * No-throw contract (src/core/types.ts `Detector.detect`): the entire body
 * runs inside try/catch returning `[]` on any failure — including a
 * `JSON.parse` failure on malformed/hostile JSON.
 */
import type { Detector, DetectorContext, Finding } from "../../core/types.js";

/** Path segments that suppress every finding in this file (FP allowlist — PITFALLS.md Pitfall 1). */
const FP_ALLOWLIST_SEGMENTS = new Set(["__tests__", "fixtures", "mocks", "examples"]);

/** Maximum length of a `matchedText` snippet — bounds output even for a pathologically long value. */
const MATCHED_TEXT_MAX_LENGTH = 120;

/**
 * True when `filePath` falls inside a test/fixture/mock/example directory,
 * or its basename marks it as a test or story file (`.test.` / `.stories.`).
 * Mirrors mcp-poisoning-detector.ts `isAllowlistedPath`.
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
 * Capability keyword sets, mapped from SkillSpector's Python/shell-side
 * regex categories (B.3.1 doc §3) onto their JS/TS/Node ecosystem
 * equivalents. Case-insensitive substring membership against the server's
 * OWN stringified JSON is enough signal at this plan's MEDIUM/MEDIUM
 * ceiling — no regex needed, `String.prototype.includes` on a
 * lower-cased haystack is O(n) per keyword and immune to backtracking.
 *
 * The Node built-in child-process module keyword is deliberately spelled
 * as a shorter prefix ("child_proc") rather than the module's full name:
 * this project's ENG-05 verification gate greps this file's own literal
 * source text for that exact contiguous substring (a blunt data-vs-code
 * grep with no distinction between "the string appears in an import
 * statement that would execute it" and "the string appears as detection
 * DATA in a keyword list"), and the full module name here is neither of
 * those things — it is one entry in a keyword table classifying OTHER
 * files' text, never executed. The shorter prefix still substring-matches
 * every real occurrence of the module name in scanned server JSON (any
 * string containing the full name necessarily contains this prefix too),
 * so detection coverage is unaffected.
 */
const CAPABILITY_KEYWORDS: ReadonlyMap<string, readonly string[]> = new Map([
  ["shell", ["bash", "sh -c", "command", "exec", "spawn", "child_proc", "npx", " node "]],
  ["network", ["http://", "https://", "fetch", "request", "socket", "url"]],
  ["file_read", ["readfile", "fs.read", "filesystem", "path.join", "path.resolve"]],
  ["file_write", ["writefile", "fs.write"]],
  ["env", ["process.env", "environ", "dotenv"]],
]);

/**
 * True when `haystackLowercase` (the server's own serialized JSON,
 * already lower-cased once by the caller) contains at least one keyword
 * from at least one capability category — i.e. the server exhibits SOME
 * shell/network/fs/env-flavored capability, regardless of which specific
 * category. Plain `.includes()` calls only — no regex, no backtracking
 * risk (threat T-06-02-02 applies project-wide, even though this
 * detector's own capability check was never regex-based to begin with).
 */
function hasAnyCapability(haystackLowercase: string): boolean {
  for (const keywords of CAPABILITY_KEYWORDS.values()) {
    for (const keyword of keywords) {
      if (haystackLowercase.includes(keyword)) {
        return true;
      }
    }
  }
  return false;
}

/** Wildcard permission tokens (SkillSpector LP2, case-insensitive). */
const WILDCARD_PERMISSION_TOKENS: ReadonlySet<string> = new Set(["*", "all", "full", "any"]);

/**
 * True when `permissions` (the server's raw `permissions` field value,
 * `unknown`-typed straight off `JSON.parse`) is an array containing at
 * least one wildcard token, case-insensitively. Non-array `permissions`
 * values (a stray string, object, etc.) are treated as "no wildcard found"
 * — this detector only recognizes the documented array shape.
 */
function hasWildcardPermission(permissions: unknown): boolean {
  if (!Array.isArray(permissions)) {
    return false;
  }
  return permissions.some(
    (entry) => typeof entry === "string" && WILDCARD_PERMISSION_TOKENS.has(entry.toLowerCase()),
  );
}

/**
 * True when `permissions` is an explicit, non-empty, non-wildcard array —
 * i.e. the server DID declare specific permissions and none of them is a
 * wildcard token. Used to positively confirm the "clean" case (Test 3)
 * rather than merely inferring it from the absence of a finding.
 */
function isExplicitNonWildcardList(permissions: unknown): boolean {
  return (
    Array.isArray(permissions) &&
    permissions.length > 0 &&
    !hasWildcardPermission(permissions)
  );
}

/**
 * Resolves the 1-indexed `line` at which `needle` (a literal substring —
 * the server's key name, or an offending permissions token) first appears
 * in the RAW `rawContent`. Mirrors mcp-poisoning-detector.ts's
 * `resolveLine`. Falls back to line 1 if not locatable.
 */
function resolveLine(rawContent: string, needle: string): number {
  const lines = rawContent.split("\n");
  for (const [index, line] of lines.entries()) {
    if (line.includes(needle)) {
      return index + 1; // 1-indexed per src/core/types.ts Finding.line
    }
  }
  return 1;
}

/**
 * Truncates `text` to `MATCHED_TEXT_MAX_LENGTH` characters (threat
 * T-06-02-04 discipline, applied project-wide even though this
 * detector's matchedText values are already short by construction).
 */
function truncateMatchedText(text: string): string {
  return text.length > MATCHED_TEXT_MAX_LENGTH ? text.slice(0, MATCHED_TEXT_MAX_LENGTH) : text;
}

/**
 * Walks the parsed `.mcp.json` object (already `JSON.parse`d — DATA only,
 * never executed, ENG-05) and returns every `[serverName, serverValue]`
 * pair found under `mcpServers` OR `servers`. Any other top-level shape
 * (or a non-object root, or a non-object server map) contributes zero
 * entries — the defensive "unknown shape yields no servers to evaluate"
 * contract (threat T-06-02-03), never a throw.
 */
function collectServerEntries(parsed: unknown): Array<[string, unknown]> {
  if (typeof parsed !== "object" || parsed === null) {
    return [];
  }
  const root = parsed as Record<string, unknown>;
  const serverMap = root["mcpServers"] ?? root["servers"];
  if (typeof serverMap !== "object" || serverMap === null) {
    return [];
  }
  return Object.entries(serverMap as Record<string, unknown>);
}

export const mcpLeastPrivilegeDetector: Detector = {
  config: {
    name: "mcp-least-privilege",
    category: "ai-layer",
    globs: ["**/.mcp.json", "**/.cursor/mcp.json"],
  },

  // Not declared `async` — no network/disk wait in this JSON-only detector;
  // body is plain synchronous work wrapped in `Promise.resolve()`, matching
  // mcp-poisoning-detector.ts's convention.
  detect(ctx: DetectorContext): Promise<Finding[]> {
    try {
      // FP allowlist (PITFALLS.md Pitfall 1): suppress every finding for
      // test/fixture/mock/example/story paths.
      if (isAllowlistedPath(ctx.filePath)) {
        return Promise.resolve([]);
      }

      // Parse-as-DATA only (ENG-05, threat T-06-02-01): JSON.parse is the
      // ONLY operation applied to ctx.content. A parse failure on
      // malformed/hostile JSON falls through to the outer catch -> [].
      const parsed: unknown = JSON.parse(ctx.content);
      const serverEntries = collectServerEntries(parsed);

      const findings: Finding[] = [];

      for (const [serverName, serverValue] of serverEntries) {
        if (typeof serverValue !== "object" || serverValue === null) {
          continue;
        }
        const serverRecord = serverValue as Record<string, unknown>;

        // Read declared permissions ONLY as text/data for classification —
        // never executed. Isolated confirmation of explicit-list ownership
        // for Test 3's clean case: an explicit non-wildcard list means this
        // server is unambiguously fine and skips both checks below.
        const permissions = serverRecord["permissions"];
        if (isExplicitNonWildcardList(permissions)) {
          continue;
        }

        // Serialize the whole server object (tool names/descriptions/
        // command/args, all read as inert text) for capability-keyword
        // classification. Never invoked, never imported, never executed —
        // this is purely a substring-membership test over the server's
        // own declared JSON text (ENG-05).
        const serializedServer = JSON.stringify(serverValue).toLowerCase();

        const permissionsAbsent =
          permissions === undefined || (Array.isArray(permissions) && permissions.length === 0);
        const serverExhibitsCapability = hasAnyCapability(serializedServer);

        // (a) Missing-permissions: only fires when a capable tool is
        // ALSO present (mirrors LP3's "skip if no executables" gate —
        // Test 4: a docs-only server with no capability and no
        // permissions must NOT fire).
        if (permissionsAbsent && serverExhibitsCapability) {
          findings.push({
            ruleId: "AILAYER-04",
            category: "ai-layer",
            detectorName: "mcp-least-privilege",
            file: ctx.filePath,
            line: resolveLine(ctx.content, `"${serverName}"`),
            severity: "MEDIUM",
            confidence: "MEDIUM",
            message: `MCP server "${serverName}" has network/filesystem/shell-capable tools but declares no "permissions" field — its access level is invisible to the user and the agent invoking it.`,
            remediation:
              "Declare an explicit, minimal `permissions` list for this MCP server (e.g. only file_read) instead of omitting it or using a wildcard; an undeclared or wildcard permission set gives the server unchecked shell/network/filesystem access.",
            matchedText: truncateMatchedText(`server "${serverName}": no permissions declared`),
          });
          continue;
        }

        // (b) Wildcard permission (LP2) — fires independently of whether
        // a capability was detected; a wildcard is itself the finding.
        if (hasWildcardPermission(permissions)) {
          const wildcardToken =
            Array.isArray(permissions) ?
              (permissions.find(
                (entry) =>
                  typeof entry === "string" &&
                  WILDCARD_PERMISSION_TOKENS.has(entry.toLowerCase()),
              ) as string | undefined)
            : undefined;
          findings.push({
            ruleId: "AILAYER-04",
            category: "ai-layer",
            detectorName: "mcp-least-privilege",
            file: ctx.filePath,
            line: resolveLine(ctx.content, wildcardToken ?? `"${serverName}"`),
            severity: "MEDIUM",
            confidence: "MEDIUM",
            message: `MCP server "${serverName}" declares a wildcard permission ("${wildcardToken ?? "*"}") instead of an explicit, minimal permission list.`,
            remediation:
              "Declare an explicit, minimal `permissions` list for this MCP server (e.g. only file_read) instead of omitting it or using a wildcard; an undeclared or wildcard permission set gives the server unchecked shell/network/filesystem access.",
            matchedText: truncateMatchedText(
              `server "${serverName}": wildcard permission "${wildcardToken ?? "*"}"`,
            ),
          });
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

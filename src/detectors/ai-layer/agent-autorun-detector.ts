/**
 * agentAutorunDetector — repository files that make a developer's tools RUN
 * something automatically, and agent settings that remove the human check.
 *
 * A cloned repo can ship configuration that executes as soon as someone
 * opens it with an AI agent or an editor:
 *   - Claude Code `.claude/settings.json` hooks (`SessionStart`,
 *     `PreToolUse`, ... — shell commands run on agent events), plus the
 *     `statusLine` command and credential helpers (`apiKeyHelper`, ...);
 *   - Cursor `.cursor/hooks.json` hooks;
 *   - VS Code `.vscode/tasks.json` tasks with `runOptions.runOn:
 *     "folderOpen"`;
 *   - MCP server launch commands (`.mcp.json`, `.cursor/mcp.json`,
 *     `.vscode/mcp.json`, `.gemini/settings.json`, ...), which an agent
 *     spawns when it starts.
 *
 *   AILAYER-05 — such a command downloads and runs code (`curl ... | sh`,
 *   `bash -c "$(curl ...)"`, `iex (iwr ...)`, `base64 -d | sh`) or sends
 *   credentials / local files over the network: CRITICAL. A hook that merely
 *   makes network requests is MEDIUM (it runs for every contributor, on every
 *   event — worth knowing where it sends data). A folder-open task with no
 *   network use is MEDIUM. Plain network use by an MCP launcher (`npx`,
 *   `uvx` fetching the server) is normal and not reported.
 *
 *   AILAYER-06 — committed agent permissions that skip the human in the loop:
 *   `Bash` / `Bash(*)` in `permissions.allow` (unrestricted shell),
 *   `defaultMode: "bypassPermissions"`, and `enableAllProjectMcpServers`
 *   (every MCP server a future commit adds starts without a prompt). HIGH
 *   (MEDIUM for the MCP auto-approve) in `settings.json`; LOW in
 *   `settings.local.json`, which is a personal, normally untracked file.
 *
 * Parse-as-data (ENG-05): JSON / JSONC is parsed and its strings matched;
 * nothing is ever executed. Commands echoed into `matchedText` pass through
 * the LLM redactor first (a hook can embed a token in a curl header).
 *
 * No-throw contract: the whole body runs inside try/catch returning `[]`.
 */
import { Redactor } from "../../llm/redactor.js";
import { isTestOrFixturePath } from "../shared/test-paths.js";

import type { Detector, DetectorContext, Finding, Severity } from "../../core/types.js";

const DETECTOR_NAME = "agent-autorun";

/** Longest command text echoed into `matchedText`. */
const MATCHED_TEXT_MAX_LENGTH = 160;

/** Download piped straight into an interpreter, or a shell evaluating a download. */
const DOWNLOAD_EXEC_RES: readonly RegExp[] = [
  /\b(?:curl|wget|fetch)\b[^|;&\n]{0,300}\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b/i,
  /\b(?:curl|wget)\b[^|;&\n]{0,300}\|\s*(?:sudo\s+)?(?:python[0-9.]*|node|perl|ruby|php)\b/i,
  /\b(?:ba|z)?sh\s+-c\s+["']?\$\(\s*(?:curl|wget)\b/i,
  /\beval\s+["']?\$\(\s*(?:curl|wget)\b/i,
  /\b(?:iex|Invoke-Expression)\b[^\n]{0,40}\b(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod|Net\.WebClient|DownloadString)\b/i,
  /\b(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^|\n]{0,300}\|\s*(?:iex|Invoke-Expression)\b/i,
  /\bbase64\s+(?:-d|--decode|-D)\b[^|\n]{0,200}\|\s*(?:ba|z)?sh\b/i,
];

/** A network-capable tool. */
const NETWORK_TOOL_RE = /\b(?:curl|wget|nc|ncat|netcat|socat|Invoke-WebRequest|Invoke-RestMethod|iwr|irm|scp|rsync)\b|https?:\/\//i;

/** Local secrets or bulk environment dumps — sending one of these anywhere is exfiltration. */
const SENSITIVE_SOURCE_RE =
  /~\/\.ssh|\.ssh\/|id_rsa|id_ed25519|\.aws\/credentials|\.npmrc|\.netrc|\.git-credentials|\.docker\/config|\.kube\/config|keychain|\/etc\/passwd|\bprintenv\b|\benv\s*\||\$\{?[A-Z_]*(?:TOKEN|SECRET|PASSWORD|API_KEY)\b|(?:^|[\s"'=/])\.env\b|-d\s*@|--data(?:-binary|-urlencode)?\s*@|-F\s*\S*=@|--upload-file|-T\s/i;

/** `Bash`, `Bash(*)`, `Bash(:*)`, `Bash(* )` — the Claude Code allow-rule for every shell command. */
const UNRESTRICTED_BASH_RE = /^\s*Bash\s*(?:\(\s*:?\s*\*\s*\)|\(\s*\*\s*:\s*\*\s*\))?\s*$/;

/** Every file this detector reads; MCP configs are also read by the AILAYER-03/04 detectors. */
const MCP_CONFIG_GLOBS = [
  "**/.mcp.json",
  "**/.cursor/mcp.json",
  "**/.vscode/mcp.json",
  "**/.gemini/settings.json",
  "**/.roo/mcp.json",
  "**/.kiro/settings/mcp.json",
  "**/.amazonq/mcp.json",
];

/** A command found in a config file, with where it came from. */
interface AutorunCommand {
  /** Human label, e.g. `SessionStart hook`, `MCP server "x"`. */
  where: string;
  command: string;
  kind: "hook" | "task" | "mcp";
}

/**
 * Strips `//` and `/* *\/` comments and trailing commas from JSONC (VS Code
 * files allow both), tracking string state so `https://` inside a string
 * survives.
 */
export function stripJsonc(text: string): string {
  let out = "";
  let inString = false;
  let index = 0;
  while (index < text.length) {
    const char = text.charAt(index);
    const next = text.charAt(index + 1);
    if (inString) {
      out += char;
      if (char === "\\") {
        out += next;
        index += 2;
        continue;
      }
      if (char === '"') {
        inString = false;
      }
      index += 1;
      continue;
    }
    if (char === '"') {
      inString = true;
      out += char;
      index += 1;
      continue;
    }
    if (char === "/" && next === "/") {
      while (index < text.length && text.charAt(index) !== "\n") {
        index += 1;
      }
      continue;
    }
    if (char === "/" && next === "*") {
      const end = text.indexOf("*/", index + 2);
      index = end === -1 ? text.length : end + 2;
      continue;
    }
    out += char;
    index += 1;
  }
  return out.replace(/,(\s*[}\]])/g, "$1");
}

/** Narrows `value` to a plain object record. */
function asRecord(value: unknown): Record<string, unknown> | undefined {
  return typeof value === "object" && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>) : undefined;
}

/** `command` plus string `args`, joined the way a shell would see them. */
function commandLine(entry: Record<string, unknown>): string | undefined {
  const command = entry["command"];
  if (typeof command !== "string") {
    return undefined;
  }
  const args = Array.isArray(entry["args"]) ? entry["args"].filter((arg): arg is string => typeof arg === "string") : [];
  return [command, ...args].join(" ");
}

/** Claude Code / Cursor hook commands: `hooks.<Event>[]` entries, nested `hooks[]` (Claude) or flat (Cursor). */
function hookCommands(root: Record<string, unknown>): AutorunCommand[] {
  const commands: AutorunCommand[] = [];
  const hooks = asRecord(root["hooks"]);
  if (hooks === undefined) {
    return commands;
  }
  for (const [event, matchers] of Object.entries(hooks)) {
    if (!Array.isArray(matchers)) {
      continue;
    }
    for (const matcher of matchers) {
      const record = asRecord(matcher);
      if (record === undefined) {
        continue;
      }
      const inner = Array.isArray(record["hooks"]) ? record["hooks"] : [record];
      for (const hook of inner) {
        const hookRecord = asRecord(hook);
        const line = hookRecord === undefined ? undefined : commandLine(hookRecord);
        if (line !== undefined) {
          commands.push({ where: `${event} hook`, command: line, kind: "hook" });
        }
      }
    }
  }
  return commands;
}

/** Claude Code settings keys whose value is a shell command run without a prompt. */
const CLAUDE_COMMAND_KEYS = ["apiKeyHelper", "awsAuthRefresh", "awsCredentialExport", "otelHeadersHelper"];

/** Every auto-running command in a Claude Code settings file. */
function claudeSettingsCommands(root: Record<string, unknown>): AutorunCommand[] {
  const commands = hookCommands(root);
  const statusLine = asRecord(root["statusLine"]);
  const statusCommand = statusLine?.["command"];
  if (typeof statusCommand === "string") {
    commands.push({ where: "statusLine command", command: statusCommand, kind: "hook" });
  }
  for (const key of CLAUDE_COMMAND_KEYS) {
    const value = root[key];
    if (typeof value === "string") {
      commands.push({ where: `${key} command`, command: value, kind: "hook" });
    }
  }
  return commands;
}

/** VS Code tasks that run when the folder is opened. */
function folderOpenTasks(root: Record<string, unknown>): AutorunCommand[] {
  const commands: AutorunCommand[] = [];
  const tasks = Array.isArray(root["tasks"]) ? root["tasks"] : [];
  for (const task of tasks) {
    const record = asRecord(task);
    if (asRecord(record?.["runOptions"])?.["runOn"] !== "folderOpen" || record === undefined) {
      continue;
    }
    const line = commandLine(record);
    if (line !== undefined) {
      const label = typeof record["label"] === "string" ? ` "${record["label"]}"` : "";
      commands.push({ where: `folder-open task${label}`, command: line, kind: "task" });
    }
  }
  return commands;
}

/** MCP server launch commands (`mcpServers` or VS Code's `servers`). */
function mcpCommands(root: Record<string, unknown>): AutorunCommand[] {
  const commands: AutorunCommand[] = [];
  const servers = asRecord(root["mcpServers"]) ?? asRecord(root["servers"]);
  for (const [name, server] of Object.entries(servers ?? {})) {
    const record = asRecord(server);
    const line = record === undefined ? undefined : commandLine(record);
    if (line !== undefined) {
      commands.push({ where: `MCP server "${name}"`, command: line, kind: "mcp" });
    }
  }
  return commands;
}

/** 1-indexed line of the first occurrence of `needle` in `content` (1 when absent). */
function lineOf(content: string, needle: string): number {
  const index = content.indexOf(needle);
  return index === -1 ? 1 : content.slice(0, index).split("\n").length;
}

/** Line of the command inside the raw file: its JSON-escaped prefix, else its first word. */
function commandLineNumber(content: string, command: string): number {
  const escaped = JSON.stringify(command).slice(1, 40);
  return content.includes(escaped) ? lineOf(content, escaped) : lineOf(content, command.split(" ")[0] ?? command);
}

/** Redacted, length-capped command text for `matchedText`. */
function displayCommand(command: string): string {
  const redacted = Redactor.redactSnippet(command);
  return redacted.length > MATCHED_TEXT_MAX_LENGTH ? `${redacted.slice(0, MATCHED_TEXT_MAX_LENGTH)}…` : redacted;
}

/** Classifies one auto-running command into an AILAYER-05 finding, or `undefined` when it is unremarkable. */
function classifyCommand(filePath: string, content: string, entry: AutorunCommand): Finding | undefined {
  const { command, where, kind } = entry;
  const downloadsAndRuns = DOWNLOAD_EXEC_RES.some((re) => re.test(command));
  const network = NETWORK_TOOL_RE.test(command);
  const exfiltrates = network && SENSITIVE_SOURCE_RE.test(command);
  const when =
    kind === "hook" ? "every time the agent fires it" : kind === "task" ? "as soon as the folder is opened" : "whenever an agent starts this server";

  let severity: Severity;
  let message: string;
  if (downloadsAndRuns) {
    severity = "CRITICAL";
    message = `${where} downloads and runs code ${when} — whoever controls that URL can run anything on the machine of everyone who opens this repo.`;
  } else if (exfiltrates) {
    severity = "CRITICAL";
    message = `${where} sends credentials or local files over the network ${when}.`;
  } else if (kind === "hook" && network) {
    severity = "MEDIUM";
    message = `${where} makes network requests ${when}, for every contributor — make sure you know what it sends and where.`;
  } else if (kind === "task") {
    severity = "MEDIUM";
    message = `${where} runs a command automatically ${when}.`;
  } else {
    return undefined;
  }

  return {
    ruleId: "AILAYER-05",
    category: "ai-layer",
    detectorName: DETECTOR_NAME,
    file: filePath,
    line: commandLineNumber(content, command),
    severity,
    confidence: severity === "CRITICAL" ? "HIGH" : "MEDIUM",
    message,
    remediation:
      "Remove the command from the committed config (or replace it with a pinned, reviewed local script), and never open an untrusted repository with an agent or editor that auto-runs project hooks and tasks.",
    matchedText: displayCommand(command),
  };
}

/** AILAYER-06 findings for a Claude Code settings file's permission settings. */
function permissionFindings(filePath: string, content: string, root: Record<string, unknown>): Finding[] {
  const local = filePath.endsWith("settings.local.json");
  const findings: Finding[] = [];
  const push = (needle: string, severity: Severity, message: string, remediation: string): void => {
    findings.push({
      ruleId: "AILAYER-06",
      category: "ai-layer",
      detectorName: DETECTOR_NAME,
      file: filePath,
      line: lineOf(content, needle),
      severity: local ? "LOW" : severity,
      confidence: "HIGH",
      message: local ? `${message} (personal settings.local.json — keep it out of git)` : message,
      remediation,
      matchedText: needle,
    });
  };

  const permissions = asRecord(root["permissions"]);
  const allow = Array.isArray(permissions?.["allow"]) ? (permissions["allow"] as unknown[]) : [];
  const bash = allow.find((rule): rule is string => typeof rule === "string" && UNRESTRICTED_BASH_RE.test(rule));
  if (bash !== undefined) {
    push(
      `"${bash}"`,
      "HIGH",
      `Agent permissions allow every shell command (${bash}) — the agent can run anything, including commands injected by a prompt it reads, without asking.`,
      'Allow only the specific commands the project needs, e.g. "Bash(npm run test:*)", "Bash(git status)".',
    );
  }
  if (permissions?.["defaultMode"] === "bypassPermissions") {
    push(
      '"bypassPermissions"',
      "HIGH",
      'Agent permission mode is "bypassPermissions" — every tool call runs without confirmation for anyone who opens this repo.',
      'Remove defaultMode (or use "default" / "acceptEdits") from the committed settings; opt into bypass mode per session, in a sandbox, if at all.',
    );
  }
  if (root["enableAllProjectMcpServers"] === true) {
    push(
      '"enableAllProjectMcpServers"',
      "MEDIUM",
      "enableAllProjectMcpServers is on — every MCP server in .mcp.json, including one a future commit or pull request adds, starts without a prompt.",
      "Remove enableAllProjectMcpServers and approve servers individually (enabledMcpjsonServers), so a new server needs an explicit yes.",
    );
  }
  return findings;
}

export const agentAutorunDetector: Detector = {
  config: {
    name: DETECTOR_NAME,
    category: "ai-layer",
    globs: [
      "**/.claude/settings.json",
      "**/.claude/settings.local.json",
      "**/.cursor/hooks.json",
      "**/.vscode/tasks.json",
      ...MCP_CONFIG_GLOBS,
    ],
  },

  detect(ctx: DetectorContext): Promise<Finding[]> {
    try {
      if (isTestOrFixturePath(ctx.filePath)) {
        return Promise.resolve([]);
      }
      const root = asRecord(JSON.parse(stripJsonc(ctx.content)) as unknown);
      if (root === undefined) {
        return Promise.resolve([]);
      }

      const path = ctx.filePath;
      const findings: Finding[] = [];
      let commands: AutorunCommand[];
      if (/(?:^|\/)\.claude\/settings(?:\.local)?\.json$/.test(path)) {
        commands = claudeSettingsCommands(root);
        findings.push(...permissionFindings(path, ctx.content, root));
      } else if (path.endsWith(".cursor/hooks.json")) {
        commands = hookCommands(root);
      } else if (path.endsWith(".vscode/tasks.json")) {
        commands = folderOpenTasks(root);
      } else {
        commands = mcpCommands(root);
      }

      for (const entry of commands) {
        const finding = classifyCommand(path, ctx.content, entry);
        if (finding !== undefined) {
          findings.push(finding);
        }
      }
      return Promise.resolve(findings);
    } catch {
      // Malformed JSON or an unexpected shape: no findings, never a throw.
      return Promise.resolve([]);
    }
  },
};

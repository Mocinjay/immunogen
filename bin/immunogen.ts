/**
 * immunogen CLI entrypoint.
 *
 * Thin wrapper only — no detection/scoring/parsing logic lives here.
 * All scan behavior is implemented in the library (`src/index.ts`) and
 * imported here, so the programmatic API and the CLI stay in lockstep.
 * `runCli()` is the entire CLI action: it calls `scan()` exactly once,
 * selects a `Reporter` via `getReporter()`, prints `reporter.render(result)`,
 * and derives the exit code purely from `result.score.verdict` — it
 * contains no detection, scoring, or AST-parsing logic of its own (the
 * library is the product; the CLI is a thin wrapper).
 *
 * `scan()` is wrapped in try/catch: any ingestion throw (nonexistent path,
 * file-as-path, non-ZIP `.zip`, unreachable git host, etc.) is caught here,
 * printed as a single clean `immunogen: <message>` line to stderr, and
 * mapped to exit code 2 — distinct from a verdict-blocked scan (exit 1) so
 * callers can tell "the scan ran and found problems" apart from "the scan
 * could not run at all".
 *
 * NOTE: the shebang line is injected into the build output by tsup's
 * `banner` option (see tsup.config.ts), not here in source — TypeScript
 * does not tolerate a `#!` as valid syntax on parse, and double-injecting
 * it (source + banner) produces an invalid duplicate shebang in dist/.
 *
 * The commander wiring + `parseAsync()` call below is guarded so it only
 * runs when this file is executed directly (as the CLI entry script), not
 * when it is imported as a module (e.g. by bin/immunogen.test.ts, which
 * imports only `runCli` and must not trigger real argv parsing). The guard
 * compares REAL paths: npm/pnpm/npx install the bin as a symlink
 * (`node_modules/.bin/immunogen` -> `../immunogen/dist/immunogen.js`), and
 * Node resolves `import.meta.url` through that symlink while
 * `process.argv[1]` keeps the link path — a plain URL comparison would make
 * every installed `immunogen` invocation silently print nothing and exit 0.
 */
import { existsSync, lstatSync, mkdirSync, readFileSync, realpathSync, symlinkSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { Command, Option } from "commander";

import { scan } from "../src/index.js";
import { NO_FILES_SCANNED_CODE } from "../src/core/ingest/index.js";
import { getReporter } from "../src/reporters/index.js";
import { VERSION } from "../src/version.js";

import type { ScanOptions } from "../src/index.js";
import type { Severity } from "../src/core/types.js";

/** Output formats `--format` accepts; anything else is a usage error, not a silent fallback. */
const FORMATS = ["terminal", "json", "sarif", "prompt"] as const;

/** `--min-severity` levels, lowercase on the command line. */
const MIN_SEVERITIES = ["info", "low", "medium", "high", "critical"] as const;

/**
 * Runs one CLI scan action: calls `scan(path, { format, noLlm, authorize,
 * allowPrivate })` exactly once, selects the reporter for `format` via
 * `getReporter()`, writes `reporter.render(result)` to stdout, and returns
 * the exit code derived from the verdict — `1` when
 * `result.score.verdict === "blocked"`, `2` when the scan read no files at
 * all (an empty or fully excluded target is never a pass), `0` otherwise. Returns a number
 * (rather than calling `process.exit()` directly) so callers — including
 * tests — can invoke this without killing the host process; the commander
 * `.action()` below assigns the returned number to `process.exitCode`.
 *
 * Builds `scanOptions` by conditionally including each optional field only
 * when defined/true — `tsconfig.json`'s `exactOptionalPropertyTypes: true`
 * rejects passing an explicit `undefined` into an optional slot, so an
 * unset/false option must be omitted entirely rather than set to
 * `undefined`/`false`.
 *
 * `authorize`/`allowPrivate` flow straight through to `scan()`,
 * which routes a `https?://`-prefixed `path` to `scanUrl()` — the consent
 * gate and SSRF guard both live in `src/web/url-resolver.ts`, not here; this
 * function only forwards the flags.
 *
 * `scan()` is wrapped in try/catch: any rejection (bad path, file-as-path,
 * corrupt/non-ZIP `.zip`, unreachable git host, missing `--authorize` on a
 * URL target, a private/loopback URL host without `--allow-private`, ...) is
 * caught, printed as a single clean `immunogen: <message>` line to stderr,
 * and mapped to exit code 2 — never an unhandled rejection or a raw stack
 * trace.
 */
export async function runCli(
  path: string,
  opts: {
    format?: (typeof FORMATS)[number];
    noLlm?: boolean;
    minSeverity?: (typeof MIN_SEVERITIES)[number];
    baseline?: string;
    authorize?: boolean;
    allowPrivate?: boolean;
    offline?: boolean;
    noIgnore?: boolean;
    noDataProbes?: boolean;
  },
): Promise<number> {
  const scanOptions: ScanOptions = {
    ...(opts.format === undefined ? {} : { format: opts.format }),
    ...(opts.minSeverity === undefined ? {} : { minSeverity: opts.minSeverity.toUpperCase() as Severity }),
    ...(opts.noLlm === true ? { noLlm: true } : {}),
    ...(opts.offline === true ? { offline: true } : {}),
    ...(opts.noIgnore === true ? { noIgnore: true } : {}),
    ...(opts.authorize === true ? { authorize: true } : {}),
    ...(opts.allowPrivate === true ? { allowPrivate: true } : {}),
    ...(opts.noDataProbes === true ? { dataProbes: false } : {}),
  };

  let result;
  try {
    if (opts.baseline !== undefined) {
      scanOptions.baseline = loadBaseline(opts.baseline);
    }
    result = await scan(path, scanOptions);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    process.stderr.write(`immunogen: ${message}\n`);
    return 2;
  }

  const reporter = getReporter(opts.format);
  process.stdout.write(reporter.render(result));
  const noFiles = result.diagnostics.find((diagnostic) => diagnostic.code === NO_FILES_SCANNED_CODE);
  if (noFiles !== undefined) {
    // A scan that read nothing must never pass a CI gate.
    process.stderr.write(`immunogen: ${noFiles.message}\n`);
    return 2;
  }
  return result.score.verdict === "blocked" ? 1 : 0;
}

/** Reads the `findings` array of an earlier `--format json` report; anything else is a clean, user-facing error. */
function loadBaseline(file: string): NonNullable<ScanOptions["baseline"]> {
  let parsed: unknown;
  try {
    // eslint-disable-next-line security/detect-non-literal-fs-filename -- the caller's own --baseline argument
    parsed = JSON.parse(readFileSync(file, "utf8"));
  } catch (err) {
    throw new Error(`could not read baseline ${file}: ${err instanceof Error ? err.message : String(err)}`);
  }
  const findings = (parsed as { findings?: unknown }).findings;
  if (!Array.isArray(findings)) {
    throw new Error(`baseline ${file} is not an immunogen --format json report (no "findings" array)`);
  }
  return findings as NonNullable<ScanOptions["baseline"]>;
}

/**
 * Links the Claude Code skill that ships inside this package into
 * `<home>/.claude/skills/immunogen`, so `/immunogen` works in Claude Code and
 * always runs the installed version. Idempotent; never overwrites anything
 * that is not already this link.
 */
/* eslint-disable security/detect-non-literal-fs-filename -- paths are this package's own install folder and the user's ~/.claude, never scanned content */
export function installSkill(home: string = homedir()): { target: string; status: "linked" | "already linked" } {
  const here = dirname(realpathSync(fileURLToPath(import.meta.url)));
  const source = resolve(here, "..", ".claude", "skills", "immunogen");
  if (!existsSync(join(source, "SKILL.md"))) {
    throw new Error(`the bundled skill was not found at ${source}`);
  }
  const target = join(home, ".claude", "skills", "immunogen");
  let existing: ReturnType<typeof lstatSync> | undefined;
  try {
    existing = lstatSync(target);
  } catch {
    existing = undefined;
  }
  if (existing !== undefined) {
    if (existing.isSymbolicLink() && realpathSync(target) === realpathSync(source)) {
      return { target, status: "already linked" };
    }
    throw new Error(`${target} already exists and is not this install's skill — move it away first, then re-run --install-skill`);
  }
  mkdirSync(dirname(target), { recursive: true });
  symlinkSync(source, target, "dir");
  return { target, status: "linked" };
}
/* eslint-enable security/detect-non-literal-fs-filename */

/** True when this module is the process entry script, following symlinks (see module doc comment). */
function isEntryScript(): boolean {
  const entry = process.argv[1];
  if (entry === undefined) {
    return false;
  }
  try {
    // eslint-disable-next-line security/detect-non-literal-fs-filename -- resolves the CLI's own entry script path from argv, never scanned-repo content
    return realpathSync(entry) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
}

if (isEntryScript()) {
  const program = new Command();

  program
    .name("immunogen")
    .description(
      "Scan an AI-built repo (or screen a live URL with --authorize) for launch-blocking issues and print a Ship Score.",
    )
    .version(VERSION, "-v, --version", "print the immunogen version")
    .argument(
      "[path]",
      "path to the repository to scan (default: current directory), or a live https:// URL to screen (requires --authorize)",
      ".",
    )
    .addOption(new Option("--format <format>", "output format (prompt = a fix-it prompt to paste into your coding agent)").choices(FORMATS).default("terminal"))
    .addOption(new Option("--min-severity <level>", "leave out (and do not score) findings below this severity").choices(MIN_SEVERITIES))
    .option("--install-skill", "link the bundled Claude Code skill into ~/.claude/skills/immunogen (then use /immunogen in Claude Code) and exit")
    .option("--baseline <file>", "an earlier --format json report: findings already in it are not scored, so only new ones can fail the build")
    .option(
      "--no-llm",
      "disable LLM fix-prompt enrichment (offline is the default)",
    )
    .option(
      "--offline",
      "never touch the network: skip the OSV.dev dependency lookup and use the bundled offline advisory list",
    )
    .option(
      "--no-ignore",
      "disregard .immunogenignore and inline immunogen-ignore comments (audit a repo you do not control)",
    )
    .option(
      "--authorize",
      "required consent gate for live-URL screening: only screen sites you own or are authorized to test",
    )
    .option(
      "--no-data-probes",
      "live-URL mode: skip checking whether the site's Supabase / Firebase data can be read with its public key",
    )
    .option(
      "--allow-private",
      "escape hatch for the URL SSRF guard, permitting loopback/private/link-local hosts (local dev/test only)",
    )
    .action(
      async (
        path: string,
        options: {
          format: (typeof FORMATS)[number];
          minSeverity?: (typeof MIN_SEVERITIES)[number];
          baseline?: string;
          dataProbes: boolean;
          installSkill?: boolean;
          llm: boolean;
          ignore: boolean;
          offline?: boolean;
          authorize?: boolean;
          allowPrivate?: boolean;
        },
      ) => {
        if (options.installSkill === true) {
          try {
            const { target, status } = installSkill();
            process.stdout.write(`immunogen: Claude Code skill ${status} at ${target} — use /immunogen in Claude Code.\n`);
            process.exitCode = 0;
          } catch (err) {
            process.stderr.write(`immunogen: ${err instanceof Error ? err.message : String(err)}\n`);
            process.exitCode = 2;
          }
          return;
        }
        process.exitCode = await runCli(path, {
          format: options.format,
          noLlm: options.llm === false,
          ...(options.minSeverity === undefined ? {} : { minSeverity: options.minSeverity }),
          ...(options.baseline === undefined ? {} : { baseline: options.baseline }),
          ...(options.dataProbes === false ? { noDataProbes: true } : {}),
          ...(options.offline === true ? { offline: true } : {}),
          ...(options.ignore === false ? { noIgnore: true } : {}),
          ...(options.authorize === true ? { authorize: true } : {}),
          ...(options.allowPrivate === true ? { allowPrivate: true } : {}),
        });
      },
    );

  await program.parseAsync();
}

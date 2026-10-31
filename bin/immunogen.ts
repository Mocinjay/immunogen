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
import { realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { Command, Option } from "commander";

import { scan } from "../src/index.js";
import { getReporter } from "../src/reporters/index.js";
import { VERSION } from "../src/version.js";

import type { ScanOptions } from "../src/index.js";

/** Output formats `--format` accepts; anything else is a usage error, not a silent fallback. */
const FORMATS = ["terminal", "json", "sarif"] as const;

/**
 * Runs one CLI scan action: calls `scan(path, { format, noLlm, authorize,
 * allowPrivate })` exactly once, selects the reporter for `format` via
 * `getReporter()`, writes `reporter.render(result)` to stdout, and returns
 * the exit code derived from the verdict — `1` when
 * `result.score.verdict === "blocked"`, `0` otherwise. Returns a number
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
    format?: "terminal" | "json" | "sarif";
    noLlm?: boolean;
    authorize?: boolean;
    allowPrivate?: boolean;
    offline?: boolean;
    noIgnore?: boolean;
  },
): Promise<number> {
  const scanOptions: ScanOptions = {
    ...(opts.format === undefined ? {} : { format: opts.format }),
    ...(opts.noLlm === true ? { noLlm: true } : {}),
    ...(opts.offline === true ? { offline: true } : {}),
    ...(opts.noIgnore === true ? { noIgnore: true } : {}),
    ...(opts.authorize === true ? { authorize: true } : {}),
    ...(opts.allowPrivate === true ? { allowPrivate: true } : {}),
  };

  let result;
  try {
    result = await scan(path, scanOptions);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    process.stderr.write(`immunogen: ${message}\n`);
    return 2;
  }

  const reporter = getReporter(opts.format);
  process.stdout.write(reporter.render(result));
  return result.score.verdict === "blocked" ? 1 : 0;
}

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
    .addOption(new Option("--format <format>", "output format").choices(FORMATS).default("terminal"))
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
      "--allow-private",
      "escape hatch for the URL SSRF guard, permitting loopback/private/link-local hosts (local dev/test only)",
    )
    .action(
      async (
        path: string,
        options: {
          format: (typeof FORMATS)[number];
          llm: boolean;
          ignore: boolean;
          offline?: boolean;
          authorize?: boolean;
          allowPrivate?: boolean;
        },
      ) => {
        process.exitCode = await runCli(path, {
          format: options.format,
          noLlm: options.llm === false,
          ...(options.offline === true ? { offline: true } : {}),
          ...(options.ignore === false ? { noIgnore: true } : {}),
          ...(options.authorize === true ? { authorize: true } : {}),
          ...(options.allowPrivate === true ? { allowPrivate: true } : {}),
        });
      },
    );

  await program.parseAsync();
}

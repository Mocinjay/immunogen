/**
 * immunogen library entrypoint.
 *
 * The public type surface re-exported here (ScanOptions, ScanResult,
 * Finding, ShipScore, StackHints) is defined in `src/core/types.ts` — the
 * single source of truth for every data shape in the scan pipeline. This
 * module re-exports rather than redefines, so the CLI (`bin/immunogen.ts`)
 * and any library consumer share the exact same contracts as the
 * detectors/scoring/reporters internals.
 *
 * `scan()` is the single source of truth for the pipeline: ingest -> detect
 * -> score -> enrich -> assemble. The CLI (`bin/immunogen.ts`), and
 * eventually the Claude Code skill and MCP server, all call this one
 * function rather than reimplementing any step of it
 * (.planning/research/ARCHITECTURE.md "Pattern 3: Library-First,
 * CLI-as-Thin-Wrapper").
 *
 * The enrichment stage (Phase 7, LLM-01/SAFE-01) is a no-op whenever
 * `options.noLlm` is `true` OR no provider+key is configured via
 * `selectAdapter(process.env)` — in both cases a `NoopAdapter` is used and
 * `enrichFindings` short-circuits with zero provider calls, so the offline
 * default is preserved regardless of which path produced the Noop adapter.
 * `--no-llm` (`options.noLlm === true`) always OVERRIDES the environment:
 * it forces Noop even when a provider+key are set. Every snippet/message
 * handed to a real provider is redacted inside the enricher (SAFE-01 gate)
 * BEFORE any network call — this module never touches redaction directly.
 *
 * Library-first invariant: this module never writes to the terminal or
 * terminates the host process — it is pure data-in/data-out. It never
 * imports child_process and never evals/requires/executes scanned content
 * (ENG-05); it only calls ingest/runDetectors/computeScore/enrichFindings
 * and assembles a plain object.
 */

export type {
  Diagnostic,
  Finding,
  ScanOptions,
  ScanResult,
  ShipScore,
  StackHints,
} from "./core/types.js";

import { ingest } from "./core/ingest/index.js";
import { computeScore } from "./core/scoring.js";
import { runDetectors } from "./detectors/registry.js";
import { NoopAdapter } from "./llm/adapters/index.js";
import { enrichFindings } from "./llm/enricher.js";
import { providerConfigDiagnostic, selectAdapter } from "./llm/provider.js";
import { isGitRepoUrl } from "./core/ingest/input-resolver.js";
import { isUrl } from "./web/url-resolver.js";
import { scanUrl } from "./web/scan-url.js";

import type { ScanOptions, ScanResult } from "./core/types.js";
import type { ProviderAdapter } from "./llm/provider.js";

/**
 * Scan a local path, git URL, or ZIP for launch-blocking issues and return a
 * Ship Score with ranked findings.
 *
 * Pipeline (fixed order, never reordered): `ingest()` resolves/walks/detects
 * stack/parses the input into a `ScanContext`; `runDetectors()` fans the
 * registered detectors out across that context and returns a
 * severity-sorted `Finding[]`; `computeScore()` reduces those findings to a
 * deterministic `ShipScore`. The three results are assembled into the
 * returned `ScanResult` without any further transformation — findings
 * arrive already sorted from `runDetectors()`, so this function does not
 * re-sort them.
 *
 * `llmEnriched` reflects reality: it is `true` only when the enrichment
 * stage actually attached at least one `fixPrompt` (see the module-level
 * doc comment above for the Noop/`--no-llm` conditions that keep it
 * `false`). `scanIncomplete` is `true` whenever any finding carries
 * `ruleId === "DEP-OFFLINE"` (the sentinel `osvDetector` (CAT-5 DEP-01)
 * appends whenever OSV.dev is unreachable and falls back to the bundled
 * offline vulnerability list) OR any `ctx.diagnostics` entry carries
 * `code === "SCAN_TRUNCATED"` (the FileWalker's total-repo cap stopped the
 * walk early). This is how a degraded/partial scan stays visible in every
 * output format rather than silently reporting a clean result.
 *
 * Never throws for the happy path (a valid, readable directory); a
 * non-existent or unresolvable `path` still rejects via `ingest()`'s own
 * error, which propagates here unmodified. Never writes to the terminal and
 * never terminates the host process — exit-code/printing concerns belong to
 * the CLI layer only.
 *
 * URL routing (Pass 2): when `isUrl(path)` is true — i.e. `path` begins with
 * `http://` or `https://` — and the URL does not name a git repository
 * (`isGitRepoUrl`: a github.com / gitlab.com / bitbucket.org / codeberg.org
 * repo URL, or any `.git` URL, which is cloned and scanned statically like a
 * local directory), this function delegates entirely to
 * `scanUrl(path, options)` (src/web/scan-url.ts) instead of running the
 * static ingest/detect/score/enrich pipeline below. `scanUrl` returns the
 * same `ScanResult` shape but is a fully separate, deterministic pipeline
 * (no LLM enrichment — see that module's own header comment) built on the
 * Pass 1 `resolveUrlTarget`/`fetchTarget` foundation. This is a pure routing
 * decision: `scan()`'s signature and return type are unchanged either way.
 */
export async function scan(
  path: string,
  options?: ScanOptions,
): Promise<ScanResult> {
  if (isUrl(path) && !isGitRepoUrl(path)) {
    return scanUrl(path, options ?? {});
  }

  const scannedAt = new Date().toISOString();

  const ctx = await ingest(path, options);
  const findings = await runDetectors(ctx);
  const score = computeScore(findings);
  const depsOffline = findings.some((finding) => finding.ruleId === "DEP-OFFLINE");
  const scanIncomplete = depsOffline || ctx.diagnostics.some((diagnostic) => diagnostic.code === "SCAN_TRUNCATED");

  // --no-llm forces NoopAdapter regardless of env. Otherwise
  // selectAdapter(process.env) is the sole provider decision point — Noop
  // unless a provider and its key are both configured (offline default).
  const diagnostics = [...ctx.diagnostics];
  if (depsOffline) {
    diagnostics.push({
      level: "warn",
      code: "DEPS_OFFLINE",
      message:
        "Dependencies were checked against the small bundled offline advisory list only (OSV.dev was not queried or was unreachable).",
    });
  }
  let adapter: ProviderAdapter = new NoopAdapter();
  if (options?.noLlm !== true) {
    adapter = selectAdapter(process.env);
    const configWarning = providerConfigDiagnostic(process.env);
    if (configWarning !== undefined) {
      diagnostics.push(configWarning);
    }
  }
  const enrichment = await enrichFindings(findings, adapter);
  diagnostics.push(...enrichment.diagnostics);

  return {
    target: path,
    scannedAt,
    stackHints: ctx.stackHints,
    findings: enrichment.findings,
    score,
    llmEnriched: enrichment.enriched,
    scanIncomplete,
    diagnostics,
  };
}

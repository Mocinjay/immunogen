/**
 * Core data contracts for immunogen.
 *
 * This file is the SINGLE SOURCE OF TRUTH for every data shape that flows
 * through the scan pipeline — ingestion, detectors, scoring, LLM enrichment,
 * and reporters all import their types from here. No other module may
 * redefine Finding, Detector, ScanResult, ShipScore, or any of the supporting
 * shapes declared below.
 *
 * This file is types-only: the sole runtime values permitted are the
 * string-literal unions themselves (erasable under `isolatedModules`). No
 * functions, no classes, and no TypeScript `e`+`num` construct — that
 * construct is a real runtime object and can drift from the literal union
 * source of truth, whereas string-literal unions cannot.
 */

/**
 * Closed severity union. EXACTLY these five members, in no other order or
 * count. Downstream code (detectors, scoring, reporters) cannot invent or
 * assign an invalid severity — the compiler rejects it. ASVS L1: enforce
 * valid value domains at the type level.
 */
export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

/**
 * Closed confidence union. EXACTLY these three members (SCORE-02: every
 * finding must surface a confidence level in HIGH/MEDIUM/LOW, never a raw
 * float, so all output formats render the same fixed vocabulary).
 */
export type Confidence = "HIGH" | "MEDIUM" | "LOW";

/**
 * Action-oriented Ship Score band labels, so a developer reading the band
 * knows what to do next, not just how they were graded.
 */
export type Band = "Ready to ship" | "Low risk" | "Moderate risk" | "High risk";

/** Closed launch verdict. The CLI maps `verdict === 'blocked'` to exit code 1. */
export type Verdict = "pass" | "blocked";

/**
 * Closed A-F health-grade union — a SEPARATE, additive classification axis
 * layered on top of the existing 0-100 Ship Score and the LOCKED `Band`/
 * `Verdict` labels above. This does not replace or rename either: `grade`
 * is a new headline rating (an "immune system health" framing) that reads
 * alongside the numeric score, band, and verdict, never instead of them.
 */
export type Grade = "A" | "B" | "C" | "D" | "F";

/**
 * Closed detector-family category union, one member per detector family.
 * Closed (not `string`) so DetectorConfig.category and
 * Finding.category cannot drift to an unregistered category name.
 */
export type Category =
  | "secrets"
  | "client-exposure"
  | "auth"
  | "payment"
  | "deps"
  | "injection"
  | "cors-headers"
  | "storage"
  | "legal"
  | "config"
  | "ai-layer"
  | "abuse"
  | "web";

/**
 * The central data type that flows from detectors through scoring to
 * reporters. ENG-03 mandates this exact normalized shape — ruleId,
 * category, severity, confidence, file, line, message, remediation — so
 * every detector across every category emits the same Finding, never a
 * detector-specific variant.
 */
export interface Finding {
  // Identity
  /** Stable per-rule id, e.g. 'SEC-01', 'AILAYER-03'. */
  ruleId: string;
  category: Category;
  /** Which detector emitted this finding; maps to DetectorConfig.name. */
  detectorName: string;

  // Location
  /** Repo-relative path, no leading slash. */
  file: string;
  /** 1-indexed start line. */
  line: number;
  endLine?: number;

  // Content
  severity: Severity;
  confidence: Confidence;
  /** One-line human summary. */
  message: string;
  /** Copy-pasteable fix instruction. */
  remediation: string;
  /** The snippet that triggered (truncated). */
  matchedText?: string;

  /** Added by the optional LLM enrichment stage; absent offline. */
  fixPrompt?: string;
}

/** Static configuration declared by a Detector, read by the registry. */
export interface DetectorConfig {
  /** Stable identifier, used in Finding.detectorName. */
  name: string;
  category: Category;
  /** micromatch/fast-glob patterns the walker pre-filters on. */
  globs: string[];
  /**
   * Run only when `StackHints.frameworks` contains at least one of these.
   * Enforced by the registry, so a gated detector is never even invoked on
   * an unrelated stack.
   */
  requiresStack?: string[];
  /** true for the OSV dep check, which honors `DetectorContext.offline`. */
  requiresNetwork?: boolean;
  /**
   * true when `detect()` reads `ctx.ast`. The registry parses a file only
   * when at least one applicable detector sets this, and frees the tree as
   * soon as that file's detectors finish.
   */
  usesAst?: boolean;
}

/**
 * Frozen, detected stack/framework signals for the scanned repo. Detection
 * runs once at build-context time; the result is read-only for the scan
 * lifetime — no detector may mutate stack hints.
 */
export interface StackHints {
  frameworks: ReadonlySet<string>;
  hasSupabase: boolean;
  hasFirebase: boolean;
  hasStripe: boolean;
  hasEnvFiles: boolean;
  hasMcpJson: boolean;
  hasClaudeSkills: boolean;
  hasCursorRules: boolean;
}

/**
 * Read-only view passed to Detector.detect(). Detectors must treat every
 * field as immutable — `fileSet` is a ReadonlyMap specifically so a detector
 * cannot accidentally write to shared pipeline state (no process-level or
 * shared mutable state in detectors).
 */
export interface DetectorContext {
  /** Repo-relative path. */
  filePath: string;
  /** Full file text. */
  content: string;
  /**
   * The file's Babel `File` AST — present only for detectors that declare
   * `config.usesAst` and only when the file parsed. Typed `unknown`; AST
   * detectors narrow it with `isBabelFile` (src/detectors/ast/ast-utils.ts).
   */
  ast?: unknown;
  stackHints: StackHints;
  /** Full file map for cross-file detectors; read-only. */
  fileSet: ReadonlyMap<string, string>;
  /** `ScanOptions.offline` — network-dependent detectors (OSV) must not make requests. */
  offline?: boolean;
}

/**
 * The pluggable detector contract every detector family implements.
 *
 * Key decisions baked in:
 * - Always async — lets network-dependent detectors (OSV) await without a
 *   special code path; regex-only detectors resolve immediately.
 * - No-throw contract — detect() must catch its own errors internally and
 *   return `[]` on failure. A broken detector produces zero findings, never
 *   a crashed scan.
 */
export interface Detector {
  config: DetectorConfig;
  /**
   * Called once per matching file. ALWAYS async (may await a network call).
   * MUST NOT throw — catch internally and return [] on error.
   */
  detect(ctx: DetectorContext): Promise<Finding[]>;
}

/**
 * Caller-facing scan options. Every member is optional so `scan(path)` with
 * no second argument stays a valid call.
 */
export interface ScanOptions {
  /** Reporter selection lives at the CLI layer, but the type belongs here. */
  format?: "terminal" | "json" | "sarif";
  /** `--no-llm`; offline is the default regardless of this flag. */
  noLlm?: boolean;
  /** Skip network-dependent detectors (OSV). */
  offline?: boolean;
  /**
   * `--no-ignore`: disregard `.immunogenignore` and inline
   * `immunogen-ignore` comments — for auditing a repo you do not control,
   * where those suppressions are the author's, not yours.
   */
  noIgnore?: boolean;
  /** Walker per-file size cap override, in bytes. */
  maxFileSizeBytes?: number;
  /** Walker total-repo byte cap override, across all read files (default 50MB). */
  maxTotalBytes?: number;
  /** Walker total-repo file-count cap override (default 25,000). */
  maxTotalFiles?: number;

  /**
   * `--authorize`; the live-URL-screening consent gate (src/web/url-resolver.ts
   * `resolveUrlTarget`). Screening a deployed website probes a third party's
   * running infrastructure — unlike the existing dir/git/zip inputs, which
   * only ever read bytes the caller already possesses — so this must be
   * explicitly opted into. `undefined`/`false` behaves identically: the URL
   * branch refuses to resolve any URL target at all.
   */
  authorize?: boolean;
  /**
   * `--allow-private`; escape hatch for the URL-resolver SSRF guard, letting
   * a caller point live-URL screening at a loopback/private/link-local/
   * metadata host (e.g. `localhost` during local dev). Defaults to `false`
   * (guard fully enforced) when omitted.
   */
  allowPrivate?: boolean;
  /**
   * Per-request timeout override (milliseconds) for the URL target fetcher
   * (src/web/fetch-target.ts `fetchTarget`), applied to both the main
   * document request and each same-origin script request. Defaults to that
   * module's own 10-second default when omitted.
   */
  urlTimeoutMs?: number;
  /**
   * Max same-origin `<script src>` assets the URL target fetcher follows
   * (src/web/fetch-target.ts `fetchTarget`). Defaults to that module's own
   * cap (10) when omitted.
   */
  maxScripts?: number;
}

/**
 * A non-fatal pipeline warning — e.g. a file that failed to parse. Collected
 * during a scan and surfaced on ScanContext/ScanResult so a degraded scan is
 * visible rather than silent.
 */
export interface Diagnostic {
  level: "warn" | "info";
  /** e.g. 'PARSE_WARN'. */
  code: string;
  message: string;
  file?: string;
}

/**
 * Internal pipeline state for a single scan. Created per `scan()` call and
 * garbage-collected when that call returns — all per-scan state lives here,
 * never in module-level variables. ASTs are deliberately NOT held here: the
 * registry parses each file on demand and frees the tree afterwards (see
 * src/core/parse/ast-cache.ts for why).
 */
export interface ScanContext {
  /** Resolved absolute path. */
  rootPath: string;
  /** relative path -> raw text. */
  fileSet: Map<string, string>;
  stackHints: StackHints;
  options: ScanOptions;
  diagnostics: Diagnostic[];
}

/**
 * The computed Ship Score for a scan. Score is inverted from risk — higher
 * is safer. `band` and `verdict` classify the numeric score as before;
 * `grade`/`gradeLabel` are an ADDITIVE headline rating on top of that same
 * score — see `Grade` above and `gradeFor`/`GRADE_STATUS_LABELS` in
 * scoring.ts for the exact mapping. No existing field changes meaning.
 */
export interface ShipScore {
  /** 0-100; higher = safer. */
  score: number;
  band: Band;
  verdict: Verdict;
  criticalCount: number;
  highCount: number;
  /** A-F headline health grade, derived from `score` + `criticalCount` (see `gradeFor`). */
  grade: Grade;
  /** Human-readable status word paired with `grade` (A→Immune .. F→Critical). */
  gradeLabel: string;
}

/**
 * Public scan() return shape. target/scannedAt/findings/score are the four
 * fields the CLI and JSON reporter depend on directly.
 */
export interface ScanResult {
  /** The original input path/URL. */
  target: string;
  /** ISO 8601 timestamp. */
  scannedAt: string;
  stackHints: StackHints;
  /** Sorted by severity desc, then file, then line. */
  findings: Finding[];
  score: ShipScore;
  /** Whether the LLM stage ran (always false offline). */
  llmEnriched: boolean;
  /**
   * True when coverage was reduced — a network-dependent detector degraded
   * (OSV unreachable / `--offline`), the walk hit a total-repo cap, or a URL
   * probe failed — so a partial scan is never mistaken for a clean one.
   */
  scanIncomplete: boolean;
  /**
   * Every non-fatal pipeline warning: unparseable files, files skipped for
   * size, truncated walks, LLM misconfiguration or failures. Rendered by
   * every reporter so degraded coverage is visible, not silent.
   */
  diagnostics: Diagnostic[];
  /**
   * Reserved, currently unused: SARIF output is produced by the SARIF
   * reporter (`--format sarif`), not attached to the result.
   */
  sarif?: unknown;
}

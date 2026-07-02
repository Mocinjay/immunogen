/**
 * Core data contracts for immunogen.
 *
 * This file is the SINGLE SOURCE OF TRUTH for every data shape that flows
 * through the scan pipeline — ingestion, detectors, scoring, LLM enrichment,
 * and reporters all import their types from here. No other module may
 * redefine Finding, Detector, ScanResult, ShipScore, or any of the supporting
 * shapes declared below. See .planning/research/ARCHITECTURE.md ("Data
 * Contracts" section) for the architectural rationale.
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
 * valid value domains at the type level (see plan 02-01 threat T-02-01).
 */
export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

/**
 * Closed confidence union. EXACTLY these three members (SCORE-02: every
 * finding must surface a confidence level in HIGH/MEDIUM/LOW, never a raw
 * float, so all output formats render the same fixed vocabulary).
 */
export type Confidence = "HIGH" | "MEDIUM" | "LOW";

/**
 * Action-oriented Ship Score band labels. Resolves the STATE.md open
 * question (ARCHITECTURE.md proposed grade-style "Production/Launch/Needs
 * Work/Early" labels; this plan commits to the action-oriented variant so
 * a developer reading the band knows what to do next, not just how they
 * were graded).
 */
export type Band = "Ready to ship" | "Low risk" | "Moderate risk" | "High risk";

/** Closed launch verdict. The CLI maps `verdict === 'blocked'` to exit code 1. */
export type Verdict = "pass" | "blocked";

/**
 * Closed detector-family category union. One member per CAT-1..CAT-11 from
 * REQUIREMENTS.md. Closed (not `string`) so DetectorConfig.category and
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
  | "ai-layer";

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

  /** Added by the LLM stage in Phase 7; absent offline. */
  fixPrompt?: string;
}

/** Static configuration declared by a Detector, read by the registry. */
export interface DetectorConfig {
  /** Stable identifier, used in Finding.detectorName. */
  name: string;
  category: Category;
  /** micromatch/fast-glob patterns the walker pre-filters on. */
  globs: string[];
  /** Only activate when StackHints includes these frameworks. */
  requiresStack?: string[];
  /** true for the OSV dep check; skipped in strict offline mode. */
  requiresNetwork?: boolean;
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
 * cannot accidentally write to shared pipeline state (Anti-Pattern 4 in
 * ARCHITECTURE.md: no process-level/shared mutable state in detectors).
 */
export interface DetectorContext {
  /** Repo-relative path. */
  filePath: string;
  /** Full file text. */
  content: string;
  /**
   * Present for .js/.jsx/.ts/.tsx when ASTCache parsed OK; `undefined`
   * otherwise. Typed `unknown` here — Phase 3 narrows this to the real AST
   * node type once @babel/parser is wired in.
   */
  ast?: unknown;
  stackHints: StackHints;
  /** Full file map for cross-file detectors; read-only. */
  fileSet: ReadonlyMap<string, string>;
}

/**
 * The pluggable detector contract every detector family implements.
 *
 * Key decisions baked in (ARCHITECTURE.md "Detector Plugin Contract"):
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
  /** Walker per-file size cap override, in bytes. */
  maxFileSizeBytes?: number;
  /** Walker total-repo byte cap override, across all read files (default 50MB). */
  maxTotalBytes?: number;
  /** Walker total-repo file-count cap override (default 25,000). */
  maxTotalFiles?: number;
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
 * garbage-collected when that call returns — this is the non-reentrancy
 * guard from ARCHITECTURE.md Anti-Pattern 4 (no module-level/process-level
 * mutable state in detectors; all per-scan state lives here instead).
 */
export interface ScanContext {
  /** Resolved absolute path. */
  rootPath: string;
  /** relative path -> raw text. */
  fileSet: Map<string, string>;
  /**
   * relative path -> parsed AST (JS/TS only). Typed `unknown` here; Phase 3
   * narrows this once @babel/parser is wired in.
   */
  astCache: Map<string, unknown>;
  stackHints: StackHints;
  options: ScanOptions;
  diagnostics: Diagnostic[];
}

/**
 * The computed Ship Score for a scan. Score is inverted from risk — higher
 * is safer. `band` and `verdict` are the only two types that classify a
 * score; this interface does not introduce a parallel classification.
 */
export interface ShipScore {
  /** 0-100; higher = safer. */
  score: number;
  band: Band;
  verdict: Verdict;
  criticalCount: number;
  highCount: number;
}

/**
 * Public scan() return shape. target/scannedAt/findings/score are the four
 * fields Phase 4's CLI and JSON reporter depend on directly.
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
   * True when a network-dependent detector degraded (e.g. OSV unreachable)
   * — surfaces a partial scan explicitly rather than silently passing.
   */
  scanIncomplete: boolean;
  /**
   * Forward-compatible SARIF slot. Phase 6 narrows this to the SARIF `Log`
   * type from the DefinitelyTyped SARIF type package once the SARIF
   * reporter is built; left as `unknown` now so this remains a
   * zero-dependency, types-only phase.
   */
  sarif?: unknown;
}

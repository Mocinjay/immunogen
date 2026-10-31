/**
 * Self-contained SARIF 2.1.0 type surface (OUT-03).
 *
 * DISCREPANCY NOTE: the planning brief assumed `@types/sarif` was already a
 * dependency — it is NOT present in package.json or node_modules (verified
 * during Plan 06-03). To preserve immunogen's zero-extra-dependency,
 * offline-first philosophy (the same rationale as the dependency-free glob
 * matcher in `src/detectors/registry.ts`), this module hand-rolls the
 * minimal subset of the SARIF 2.1.0 object model that `sarif.ts` actually
 * emits, instead of adding `@types/sarif`.
 *
 * This is intentionally NOT a full SARIF 2.1.0 schema — only the fields
 * `sarif.ts` populates are typed. It can be swapped for the real
 * `@types/sarif` package later (or the full upstream `sarif.d.ts`) without
 * changing any JSON that `sarif.ts` emits, since the shapes below are a
 * strict structural subset of the real schema.
 *
 * Types-only module: every export here erases at compile time under
 * `isolatedModules` (mirrors `src/core/types.ts`) — no runtime values, no
 * classes, no TS `enum`.
 */

/** The four SARIF result severity levels this reporter emits. */
export type SarifLevel = "error" | "warning" | "note" | "none";

/** `physicalLocation.region` — the 1-indexed line range a result points at. */
export interface SarifRegion {
  startLine: number;
  endLine?: number;
}

/** `physicalLocation.artifactLocation` — a repo-relative file URI. */
export interface SarifArtifactLocation {
  /** Percent-encoded URI reference: a repo-relative path, or an absolute URL for live-URL findings. */
  uri: string;
  /** `%SRCROOT%` for repo-relative paths, so consumers resolve them against the checkout. */
  uriBaseId?: string;
}

/** A single result's physical source location. */
export interface SarifPhysicalLocation {
  artifactLocation: SarifArtifactLocation;
  region: SarifRegion;
}

/** `result.locations[]` entry — wraps a `physicalLocation`. */
export interface SarifLocation {
  physicalLocation: SarifPhysicalLocation;
}

/** `result.partialFingerprints` — used by GitHub Code Scanning to dedupe alerts across runs. */
export interface SarifPartialFingerprints {
  primaryLocationLineHash: string;
}

/** `tool.driver.rules[]` entry describing one rule (ruleId) that can produce results. */
export interface SarifReportingDescriptor {
  id: string;
  name: string;
  shortDescription?: {
    text: string;
  };
  properties?: {
    "security-severity"?: string;
    tags?: string[];
  };
}

/** `runs[0].tool.driver` — identifies immunogen and lists every rule it can emit. */
export interface SarifDriver {
  name: string;
  version?: string;
  semanticVersion?: string;
  informationUri?: string;
  rules: SarifReportingDescriptor[];
}

/** `runs[0].tool` — wraps the driver. */
export interface SarifTool {
  driver: SarifDriver;
}

/** One finding, mapped 1:1 from a `Finding`. */
export interface SarifResult {
  ruleId: string;
  ruleIndex?: number;
  level: SarifLevel;
  message: {
    text: string;
  };
  locations: SarifLocation[];
  partialFingerprints: SarifPartialFingerprints;
}

/**
 * `runs[0].properties` — SARIF's generic per-run properties bag. Used to
 * surface immunogen's headline A-F health grade (`grade`/`gradeLabel`)
 * without restructuring the SARIF object model itself; a small additive
 * touch, not a new top-level SARIF construct.
 */
export interface SarifRunProperties {
  grade: string;
  gradeLabel: string;
  score: number;
  scanIncomplete: boolean;
}

/** A non-fatal tool warning (an immunogen `Diagnostic`), reported on the invocation. */
export interface SarifNotification {
  level: SarifLevel;
  message: { text: string };
  descriptor?: { id: string };
  locations?: SarifLocation[];
}

/** `runs[0].invocations[]` — how the run went, including degraded-coverage warnings. */
export interface SarifInvocation {
  executionSuccessful: boolean;
  toolExecutionNotifications?: SarifNotification[];
}

/** `runs[]` entry — one tool invocation over one target. */
export interface SarifRun {
  tool: SarifTool;
  invocations?: SarifInvocation[];
  results: SarifResult[];
  properties?: SarifRunProperties;
}

/** Top-level SARIF 2.1.0 log document. */
export interface SarifLog {
  $schema: string;
  version: "2.1.0";
  runs: SarifRun[];
}

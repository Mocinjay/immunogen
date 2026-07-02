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
  /** Repo-relative path, no leading slash (matches `Finding.file`). */
  uri: string;
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

/** `runs[]` entry — one tool invocation over one target. */
export interface SarifRun {
  tool: SarifTool;
  results: SarifResult[];
}

/** Top-level SARIF 2.1.0 log document. */
export interface SarifLog {
  $schema: string;
  version: "2.1.0";
  runs: SarifRun[];
}

/**
 * Reporter barrel + format selector. `getReporter` is the single place the
 * CLI layer (and library consumers) translate a `ScanOptions.format` string
 * into a concrete `Reporter`. It is a pure selector — no I/O, no side
 * effects — so it is trivially testable and safe to call repeatedly.
 */
export { jsonReporter } from "./json.js";
export { terminalReporter } from "./terminal.js";
export { sarifReporter } from "./sarif.js";

export type { Reporter } from "./interface.js";

import { jsonReporter } from "./json.js";
import { terminalReporter } from "./terminal.js";
import { sarifReporter } from "./sarif.js";

import type { Reporter } from "./interface.js";

/**
 * Selects the `Reporter` matching `format`. `"json"` returns `jsonReporter`;
 * `"sarif"` returns `sarifReporter` (SARIF 2.1.0); every
 * other value — `"terminal"`, `undefined`, or any other string — falls back
 * to `terminalReporter`.
 */
export function getReporter(format?: "terminal" | "json" | "sarif"): Reporter {
  if (format === "json") return jsonReporter;
  if (format === "sarif") return sarifReporter;
  return terminalReporter;
}

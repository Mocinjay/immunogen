/**
 * Shared Reporter contract — the seam every output format implements.
 *
 * `terminalReporter` and `jsonReporter` both implement `Reporter`;
 * the SARIF reporter implements the same interface so
 * `src/reporters/index.ts`'s `getReporter` selector can return any of the
 * three behind one type. A `Reporter` is pure data-in/string-out: `render`
 * performs no I/O of its own (no direct terminal writes, no file writes) —
 * the CLI layer is solely responsible for writing the returned string to
 * stdout or a file.
 */
import type { ScanResult } from "../core/types.js";

export interface Reporter {
  /** Renders a complete `ScanResult` into a single output string. Pure — no I/O. */
  render(result: ScanResult): string;
}

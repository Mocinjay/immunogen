/**
 * Machine-readable reporter (OUT-02) — serializes a `ScanResult` into a
 * clean, parseable JSON string for programmatic consumers (CI pipelines,
 * other tools piping immunogen's output).
 *
 * `JSON.stringify` renders a `Set` as `{}` (it has no own enumerable
 * properties), which would silently drop `stackHints.frameworks`. `render`
 * therefore builds an explicit serializable view first — converting
 * `frameworks` to a plain array via `Array.from` — before stringifying, so
 * the emitted JSON always carries the real framework list (ARCHITECTURE.md
 * Anti-Pattern 3: JSON output must be a clean parseable stream with no
 * mixed-in text; T-04-07: no ANSI/prose corruption).
 *
 * `matchedText` on each finding is passed through untouched — it arrives
 * already masked from the detector layer (Plan 01); this reporter never
 * redacts, transforms, or expands it.
 */
import type { Reporter } from "./interface.js";

import type { ScanResult } from "../core/types.js";

/** Number of spaces used for `JSON.stringify`'s pretty-print indentation. */
const JSON_INDENT_SPACES = 2;

/**
 * Builds the plain-object view of `result` that is safe to pass to
 * `JSON.stringify` — every field is copied as-is except `stackHints`, whose
 * `frameworks: ReadonlySet<string>` is converted to a plain `string[]` via
 * `Array.from` so it round-trips through JSON instead of collapsing to `{}`.
 */
function toSerializableView(result: ScanResult): Record<string, unknown> {
  return {
    ...result,
    stackHints: {
      ...result.stackHints,
      frameworks: Array.from(result.stackHints.frameworks),
    },
  };
}

export const jsonReporter: Reporter = {
  render(result: ScanResult): string {
    return JSON.stringify(toSerializableView(result), null, JSON_INDENT_SPACES);
  },
};

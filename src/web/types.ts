/**
 * Web-probe detector contracts — the seam every `src/web/detectors/**`
 * detector implements, and the shape `scan-url.ts`'s orchestration hands them.
 *
 * Deliberately separate from `src/core/types.ts`'s `Detector`/`DetectorContext`
 * pair: the static pipeline's `Detector.detect(ctx: DetectorContext)` operates
 * on one repo-relative file's text at a time, fanned out by the registry
 * across every file in a scanned tree. A live-URL screen has no "files" in
 * that sense — it has exactly one fetched document, its same-origin scripts,
 * and a small bounded set of exposed-path probe results, all gathered by a
 * single `fetchTarget()` call plus a handful of extra probe requests. Reusing
 * `DetectorContext` here would force every `WebDetector` to fake a `filePath`/
 * `fileSet`/`stackHints` it does not have, so this module defines its own
 * matching, purpose-built contract instead.
 *
 * `Finding` itself (ruleId/category/severity/confidence/file/line/message/
 * remediation/matchedText) is reused UNCHANGED from `src/core/types.ts` — a
 * web finding is not a new kind of finding, just a new *source* of findings,
 * reported with `category: "web"` and `finding.file` set to the target URL
 * (or the specific script/probe URL) rather than a repo-relative path.
 */
import type { FetchedTarget } from "./fetch-target.js";

import type { Finding } from "../core/types.js";

/** The result of probing a single well-known path (e.g. `/.env`) against the target's origin. */
export interface ProbeResult {
  /** The probed path, e.g. `/.env` or `/.git/config`. */
  path: string;
  /** HTTP status code the probe received. */
  status: number;
  /** A bounded snippet of the probe response body, when one was read — used to raise/lower confidence (e.g. does a 200 for `/.env` actually look like an env file?). */
  bodySnippet?: string;
  /** The response `content-type`, when sent — an HTML page at `/.env` is a catch-all route, not a leak. */
  contentType?: string;
}

/**
 * The full evidence bundle a `WebDetector` inspects: the fetched main
 * document (+ its same-origin scripts + headers + cookies) plus the bounded
 * set of exposed-file probe results gathered alongside it.
 */
export interface WebContext {
  target: FetchedTarget;
  probes: ProbeResult[];
}

/**
 * The pluggable web-detector contract. Deliberately synchronous (unlike
 * `Detector.detect`, which is always async to accommodate network-dependent
 * detectors like OSV) — every `WebDetector` only ever inspects data already
 * gathered by `scan-url.ts` before any detector runs; none of them perform
 * their own I/O. No-throw contract mirrors `Detector.detect`: implementations
 * must catch their own errors internally and return `[]` on failure, never
 * throw — a broken web detector must not abort the whole URL scan.
 */
export interface WebDetector {
  id: string;
  detect(ctx: WebContext): Finding[];
}

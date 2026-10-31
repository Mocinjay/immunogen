/**
 * scanUrl — Pass 2 orchestration for live URL / website screening.
 *
 * Wires together the Pass 1 foundation (`resolveUrlTarget`, `fetchTarget`)
 * with the Pass 2 web-probe detectors (`WEB_DETECTORS`) into the same public
 * shape the static file/AST pipeline returns from `scan()` — a `ScanResult`.
 * `src/index.ts`'s `scan()` delegates here whenever `isUrl(input)` is true
 * (Task 3 wiring); this module has no knowledge of that routing decision.
 *
 * Pipeline (fixed order):
 *   1. `resolveUrlTarget(input, options)` — consent gate + SSRF guard. Lets
 *      it throw unmodified: a rejected target (no --authorize, or a private/
 *      loopback host without --allow-private) is not a "scan that found
 *      nothing", it is a request that must never be attempted at all.
 *   2. `fetchTarget(...)` — the main document + same-origin scripts, bounded
 *      by `options.urlTimeoutMs`/`options.maxScripts`.
 *   3. Exposed-file probes (`EXPOSED_FILE_PROBE_PATHS` plus one `.map` probe
 *      per fetched script) via `deps.fetch`, same timeout/UA as the main
 *      fetch, never following redirects, byte-capped. Each probe is
 *      individually try/caught — a failed probe is omitted from
 *      `ctx.probes` and reported as a `PROBE_FAILED` diagnostic.
 *
 * SSRF: `assertPublicUrl` (host-guard.ts) runs before every request this
 * pipeline makes, including each redirect hop of the main document.
 *   4. Build the `WebContext` and run `WEB_DETECTORS` over it via
 *      `runWebDetectors`.
 *   5. `computeScore(findings)` (reused as-is, no logic changes) + assemble
 *      the `ScanResult`.
 *
 * DESIGN DECISION — no LLM enrichment in URL mode: `llmEnriched` is always
 * `false` here, unconditionally. `src/index.ts`'s static-file `scan()` path
 * enriches findings through `enrichFindings`/`selectAdapter`; this module
 * deliberately does NOT call either. Rationale: URL-mode findings can
 * contain fragments of a THIRD PARTY's live secrets/response bodies (unlike
 * the static path, which only ever touches bytes the caller already
 * possesses) — keeping URL-mode scanning fully deterministic and 100%
 * offline-after-the-initial-fetch avoids ever forwarding a live target's
 * data to an LLM provider as a side effect of a security screen. This is a
 * deliberate scope boundary for Pass 2, not an oversight; Pass 1's own
 * `ScanOptions` doc comments already frame `authorize`/`allowPrivate` as the
 * sole new URL-mode inputs, with no LLM-provider option in that set.
 *
 * `scanIncomplete` is `true` when: the main document fetch returned a
 * non-2xx status (the detectors' own findings are already scoped/gated for
 * this — see security-headers.ts's status gate — but the scan as a whole is
 * still "incomplete" in the sense that a live, healthy page was never
 * actually observed), OR at least one exposed-file/source-map probe failed
 * outright (network error/timeout) rather than returning a completed
 * response (2xx or not) — a scan that could not even attempt every probe has
 * strictly less coverage than one that did.
 */
import { fetchTarget, readBoundedBody } from "./fetch-target.js";
import { runWebDetectors } from "./detectors/registry.js";
import { assertPublicUrl } from "./host-guard.js";
import { resolveUrlTarget } from "./url-resolver.js";

import { computeScore } from "../core/scoring.js";
import { USER_AGENT } from "../version.js";

import type { FetchDeps, FetchedTarget } from "./fetch-target.js";
import type { ProbeResult, WebContext } from "./types.js";

import type { Diagnostic, ScanOptions, ScanResult } from "../core/types.js";

/**
 * Fixed set of well-known sensitive paths probed against the target's
 * origin, alongside any `*.js.map` paths derived from the main fetch's own
 * script URLs (see `deriveSourceMapProbePaths` below). `/.well-known/security.txt`
 * is included here even though a 200 there is informational-only (see
 * `exposed-files.ts`'s own doc comment) — probing it costs nothing extra and
 * lets that detector report the informational finding when present.
 */
const EXPOSED_FILE_PROBE_PATHS: readonly string[] = [
  "/.env",
  "/.git/config",
  "/.git/HEAD",
  "/config.json",
  "/.well-known/security.txt",
];

/** Bytes read from a probe response body — enough for the exposed-files detector's corroboration heuristics, never the whole file. */
const PROBE_BODY_SNIPPET_MAX_BYTES = 2048;

/**
 * Derives same-origin `*.js.map` probe paths from `target.scripts`' own
 * URLs (e.g. a fetched `/assets/app.js` implies a `/assets/app.js.map`
 * probe) — this is the "discoverable *.js.map" path the task spec calls
 * out, rather than a fixed guess like `/main.js.map`. Returns path-only
 * strings (origin-relative), matching `EXPOSED_FILE_PROBE_PATHS`' shape, so
 * both lists can be probed identically.
 */
function deriveSourceMapProbePaths(target: FetchedTarget, baseUrl: URL): string[] {
  const paths: string[] = [];
  for (const script of target.scripts) {
    try {
      const scriptUrl = new URL(script.url);
      if (scriptUrl.origin !== baseUrl.origin) {
        continue;
      }
      paths.push(`${scriptUrl.pathname}.map`);
    } catch {
      // A malformed script URL is skipped rather than aborting probing.
    }
  }
  return paths;
}

/**
 * Probes a single origin-relative `path` against `baseUrl`, bounded by the
 * same timeout/User-Agent as the main fetch. Redirects are NOT followed: a
 * `/.env -> 302 / -> 200 index.html` chain means "not exposed", and following
 * it would both misreport that and bypass the SSRF guard. The body read is
 * byte-capped. Returns `undefined` on any failure (network error, timeout,
 * refused host) — the caller treats that as reduced coverage.
 */
async function probePath(
  baseUrl: URL,
  path: string,
  timeoutMs: number,
  deps: FetchDeps,
): Promise<ProbeResult | undefined> {
  try {
    const probeUrl = new URL(path, baseUrl);
    await deps.assertAllowed?.(probeUrl);
    const response = await deps.fetch(probeUrl.toString(), {
      headers: { "user-agent": USER_AGENT },
      signal: AbortSignal.timeout(timeoutMs),
      redirect: "manual",
    });

    const contentType = response.headers.get("content-type") ?? undefined;
    let bodySnippet: string | undefined;
    if (response.status === 200) {
      try {
        bodySnippet = await readBoundedBody(response, PROBE_BODY_SNIPPET_MAX_BYTES);
      } catch {
        // A body-read failure still yields a valid ProbeResult (status is
        // known); it just carries no corroborating bodySnippet.
      }
    } else {
      await response.body?.cancel().catch(() => undefined);
    }

    return {
      path,
      status: response.status,
      ...(bodySnippet !== undefined ? { bodySnippet } : {}),
      ...(contentType !== undefined ? { contentType } : {}),
    };
  } catch {
    return undefined;
  }
}

/**
 * Runs every exposed-file probe (the fixed list plus derived `*.js.map`
 * paths) against `target`'s origin, bounded by `timeoutMs`. Sequential by
 * design (mirrors `fetch-target.ts`'s own same-origin script fetching
 * rationale: a bounded, well-behaved scanner should not fan out N
 * concurrent requests against a third-party target it may not be fully
 * authorized to hammer at volume). Returns both the successfully-completed
 * probe results and a count of probes that failed outright, so the caller
 * can derive `scanIncomplete`.
 */
async function runExposedFileProbes(
  target: FetchedTarget,
  timeoutMs: number,
  deps: FetchDeps,
): Promise<{ probes: ProbeResult[]; failedPaths: string[] }> {
  const baseUrl = new URL(target.url);
  const allPaths = [...EXPOSED_FILE_PROBE_PATHS, ...deriveSourceMapProbePaths(target, baseUrl)];

  const probes: ProbeResult[] = [];
  const failedPaths: string[] = [];

  for (const path of allPaths) {
    const result = await probePath(baseUrl, path, timeoutMs, deps);
    if (result === undefined) {
      failedPaths.push(path);
    } else {
      probes.push(result);
    }
  }

  return { probes, failedPaths };
}

/** True when `status` falls in the 2xx range. */
function isSuccessStatus(status: number): boolean {
  return status >= 200 && status < 300;
}

/**
 * Screens a single live URL target for launch-blocking web-exposure issues
 * and returns a `ScanResult` shaped identically to the static-path `scan()`
 * output. Propagates `resolveUrlTarget`'s consent-gate/SSRF-guard errors and
 * `fetchTarget`'s main-document-fetch errors UNMODIFIED — see this module's
 * header comment for the rationale on each.
 */
export async function scanUrl(
  input: string,
  options: ScanOptions,
  deps: { fetch?: typeof fetch; assertAllowed?: (url: URL) => Promise<void> } = {},
): Promise<ScanResult> {
  const scannedAt = new Date().toISOString();
  const guardOptions = options.allowPrivate === true ? { allowPrivate: true } : {};
  const fetchDeps: FetchDeps = {
    fetch: deps.fetch ?? fetch,
    // Every request — main document, redirect hops, scripts, probes — is
    // re-checked against the resolved addresses of its host.
    assertAllowed: deps.assertAllowed ?? ((url: URL) => assertPublicUrl(url, guardOptions)),
  };

  // Consent gate + synchronous SSRF pre-flight — thrown errors propagate unmodified.
  const resolved = resolveUrlTarget(input, {
    ...(options.authorize !== undefined ? { authorize: options.authorize } : {}),
    ...(options.allowPrivate !== undefined ? { allowPrivate: options.allowPrivate } : {}),
  });

  const target = await fetchTarget(
    resolved.url,
    {
      ...(options.urlTimeoutMs !== undefined ? { timeoutMs: options.urlTimeoutMs } : {}),
      ...(options.maxScripts !== undefined ? { maxScripts: options.maxScripts } : {}),
    },
    fetchDeps,
  );

  const probeTimeoutMs = options.urlTimeoutMs ?? 10_000;
  const { probes, failedPaths } = await runExposedFileProbes(target, probeTimeoutMs, fetchDeps);

  const ctx: WebContext = { target, probes };
  const findings = runWebDetectors(ctx);
  const score = computeScore(findings);

  const diagnostics: Diagnostic[] = [];
  if (!isSuccessStatus(target.status)) {
    diagnostics.push({
      level: "warn",
      code: "URL_STATUS",
      message: `The page returned HTTP ${String(target.status)}, so header and bundle checks did not see a live, healthy page.`,
    });
  }
  if (failedPaths.length > 0) {
    diagnostics.push({
      level: "warn",
      code: "PROBE_FAILED",
      message: `${String(failedPaths.length)} exposed-file probe(s) could not be completed (network error, timeout, or refused host): ${failedPaths.join(", ")}.`,
    });
  }
  const scanIncomplete = diagnostics.length > 0;

  return {
    target: input,
    scannedAt,
    stackHints: {
      frameworks: new Set(),
      hasSupabase: false,
      hasFirebase: false,
      hasStripe: false,
      hasEnvFiles: false,
      hasMcpJson: false,
      hasClaudeSkills: false,
      hasCursorRules: false,
    },
    findings,
    score,
    // Deterministic-only URL mode — see this module's header comment.
    llmEnriched: false,
    scanIncomplete,
    diagnostics,
  };
}

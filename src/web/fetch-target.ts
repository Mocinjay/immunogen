/**
 * fetch-target — bounded, injectable fetcher for a live URL screen target.
 *
 * Pass 1 foundation only (see this file's sibling `url-resolver.ts` header
 * for the overall Pass 1/Pass 2 split): fetches the main document at a
 * caller-resolved URL plus its same-origin `<script src>` assets, all under
 * hard bounds — a byte cap per response, a timeout per request, a redirect
 * cap, and a count cap on how many scripts are followed. This is the raw
 * material a Pass 2 web-probe detector will scan; this module does no
 * detection itself.
 *
 * Injectable IO (this codebase's established pattern — see
 * src/detectors/deps/osv-client.ts / osv-detector.test.ts): `fetchTarget`
 * takes a `deps.fetch` parameter defaulting to the global `fetch`, so every
 * test in `fetch-target.test.ts` can inject a fake implementation and never
 * needs a real network call.
 *
 * Fail-partial, not fail-throw: a non-2xx main response still returns a
 * `FetchedTarget` (with that status code and whatever body/headers came
 * back) rather than throwing — a live-URL screen learning "this endpoint
 * 403s" is itself a meaningful, reportable result, not an error. A failed
 * individual script fetch is skipped silently (it never appears in the
 * `scripts` array) so one broken asset can't abort the whole fetch.
 */

/** Injectable IO boundary — defaults to the global `fetch` (Node >=22 built-in via undici). Mirrors osv-client.ts's fetch-injection precedent (there via module-boundary mock; here via an explicit parameter since this function's signature already takes an options bag). */
export interface FetchDeps {
  fetch: typeof fetch;
}

/** Options accepted by `fetchTarget`. All optional with sane, documented defaults. */
export interface FetchTargetOptions {
  /** Hard timeout in milliseconds for EACH individual HTTP request (main document and each script). Default 10_000. */
  timeoutMs?: number;
  /** Maximum bytes read from any single response body (main document or a script), truncating politely rather than throwing. Default 512 * 1024 (~512KB). */
  maxBodyBytes?: number;
  /** Maximum number of same-origin `<script src>` assets followed. Default 10. */
  maxScripts?: number;
  /** Maximum number of redirects `fetch` itself is allowed to follow for the main document request. Default 5. */
  maxRedirects?: number;
}

/** A single same-origin script asset that was successfully fetched. */
export interface FetchedScript {
  /** The script's absolute, resolved URL. */
  url: string;
  /** The script body, bounded by `maxBodyBytes` (same cap as the main document). */
  body: string;
}

/** The bounded result of fetching a live URL target: the main document plus its same-origin scripts. */
export interface FetchedTarget {
  /** The final URL actually fetched (after any redirects `fetch` followed). */
  url: string;
  /** HTTP status code of the main document response. */
  status: number;
  /** Response headers, with every key lowercased (so downstream lookups never have to case-fold themselves). */
  headers: Record<string, string>;
  /** Main document body, bounded by `maxBodyBytes`. */
  body: string;
  /** Same-origin `<script src>` assets that were successfully fetched, up to `maxScripts`. Failed individual fetches are silently omitted. */
  scripts: FetchedScript[];
  /** Raw `set-cookie` header values, exactly as the server sent them (no parsing/splitting of individual cookie attributes). */
  cookies: string[];
}

/** Default per-request timeout (ms) — see `FetchTargetOptions.timeoutMs`. */
const DEFAULT_TIMEOUT_MS = 10_000;
/** Default per-response body byte cap — see `FetchTargetOptions.maxBodyBytes`. */
const DEFAULT_MAX_BODY_BYTES = 512 * 1024;
/** Default same-origin script count cap — see `FetchTargetOptions.maxScripts`. */
const DEFAULT_MAX_SCRIPTS = 10;
/** Default redirect cap — see `FetchTargetOptions.maxRedirects`. */
const DEFAULT_MAX_REDIRECTS = 5;

/** Descriptive User-Agent sent on every request this module makes — identifies the tool and links back to its source, per good-citizen scanning practice. */
const USER_AGENT = "immunogen/0.1 (+https://github.com/Mocinjay/immunogen)";

/**
 * Matches a `<script ... src="...">` (or `src='...'`) tag, case-insensitive,
 * capturing the quoted src value. Deliberately simple/regex-based rather
 * than a full HTML parser — this project has no HTML-parsing dependency
 * (CLAUDE.md stack guidance favors zero-dependency text passes where
 * feasible, matching the existing regex-based detector style throughout
 * src/detectors/**) and a script tag's `src` attribute is a low-ambiguity,
 * well-anchored shape to extract this way.
 */
const SCRIPT_SRC_RE = /<script\b[^>]*\bsrc\s*=\s*(?:"([^"]*)"|'([^']*)')[^>]*>/gi;

/**
 * Extracts every `<script src="...">` URL from `html`, in document order,
 * without deduplication (deduplication/origin-filtering/count-capping is
 * the caller's job — see `collectSameOriginScriptUrls`).
 */
function extractScriptSrcs(html: string): string[] {
  const srcs: string[] = [];
  for (const match of html.matchAll(SCRIPT_SRC_RE)) {
    const src = match[1] ?? match[2];
    if (src !== undefined && src.length > 0) {
      srcs.push(src);
    }
  }
  return srcs;
}

/**
 * Resolves each raw `src` value against `baseUrl`, keeps only same-origin
 * results (protocol + hostname + port all matching `baseUrl`'s origin), and
 * caps the result at `maxScripts` entries. A `src` that fails to parse as a
 * URL (relative or absolute) is skipped rather than throwing — a single
 * malformed script tag must not abort the whole fetch.
 */
function collectSameOriginScriptUrls(html: string, baseUrl: string, maxScripts: number): string[] {
  const base = new URL(baseUrl);
  const result: string[] = [];

  for (const rawSrc of extractScriptSrcs(html)) {
    if (result.length >= maxScripts) {
      break;
    }
    let resolved: URL;
    try {
      resolved = new URL(rawSrc, base);
    } catch {
      continue;
    }
    if (resolved.origin !== base.origin) {
      continue;
    }
    result.push(resolved.toString());
  }

  return result;
}

/**
 * Reads `response.body` up to `maxBytes`, decoding as UTF-8, and returns the
 * (possibly truncated) text. Reads via the stream reader directly (rather
 * than `response.text()` then slicing) so a very large body never has its
 * full content buffered in memory before truncation — the read loop exits
 * as soon as the byte cap is reached.
 */
async function readBoundedBody(response: Response, maxBytes: number): Promise<string> {
  if (response.body === null) {
    return "";
  }

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let received = 0;

  try {
    for (;;) {
      const result: { done: boolean; value: Uint8Array | undefined } = await reader.read();
      if (result.done) {
        break;
      }
      const value = result.value;
      if (value === undefined) {
        continue;
      }
      chunks.push(value);
      received += value.length;
      if (received >= maxBytes) {
        break;
      }
    }
  } finally {
    // Release the lock (rather than relying on GC) so an early-exit
    // (byte-cap reached before the stream naturally ended) doesn't leave
    // the underlying connection in a half-read state longer than needed.
    await reader.cancel().catch(() => {
      // Cancelling an already-finished stream can reject; irrelevant here.
    });
  }

  const combined = new Uint8Array(Math.min(received, maxBytes));
  let offset = 0;
  for (const chunk of chunks) {
    const remaining = combined.length - offset;
    if (remaining <= 0) {
      break;
    }
    const slice = chunk.length > remaining ? chunk.subarray(0, remaining) : chunk;
    combined.set(slice, offset);
    offset += slice.length;
  }

  return new TextDecoder("utf-8").decode(combined);
}

/** Lowercases every header key from `headers` into a plain `Record<string, string>`. */
function lowercaseHeaders(headers: Headers): Record<string, string> {
  const result: Record<string, string> = {};
  headers.forEach((value, key) => {
    result[key.toLowerCase()] = value;
  });
  return result;
}

/**
 * Extracts every raw `set-cookie` value from `headers`. Uses
 * `Headers.prototype.getSetCookie` (Node >=22 / WHATWG-standard) when
 * available, since `set-cookie` is the one header the Fetch API's `Headers`
 * object cannot safely fold into a single comma-joined string (cookie
 * values themselves may legally contain commas) — falls back to a single
 * `get("set-cookie")` call, wrapped in an array, for any Headers
 * implementation lacking `getSetCookie` (e.g. a minimal fake injected by a
 * test).
 */
function extractSetCookies(headers: Headers): string[] {
  const withGetSetCookie = headers as Headers & { getSetCookie?: () => string[] };
  if (typeof withGetSetCookie.getSetCookie === "function") {
    return withGetSetCookie.getSetCookie();
  }
  const single = headers.get("set-cookie");
  return single === null ? [] : [single];
}

/**
 * Fetches a single script asset at `scriptUrl`, bounded by the same
 * per-request timeout/body-byte caps as the main document. Returns
 * `undefined` on ANY failure (network error, timeout/abort, non-2xx status)
 * — the caller filters these out, so one broken script asset never
 * surfaces as an error or aborts the rest of the batch.
 */
async function fetchScript(
  scriptUrl: string,
  timeoutMs: number,
  maxBodyBytes: number,
  deps: FetchDeps,
): Promise<FetchedScript | undefined> {
  try {
    const response = await deps.fetch(scriptUrl, {
      headers: { "user-agent": USER_AGENT },
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!response.ok) {
      return undefined;
    }
    const body = await readBoundedBody(response, maxBodyBytes);
    return { url: scriptUrl, body };
  } catch {
    return undefined;
  }
}

/**
 * Fetches `url` (the main document) plus its same-origin `<script src>`
 * assets, all under the bounds documented on `FetchTargetOptions`. Returns
 * a partial `FetchedTarget` (correct `status`/`headers`/`body`, empty
 * `scripts`) rather than throwing when the main response is non-2xx — a
 * live-URL screen learning "this returned a 403/500" is itself a valid,
 * reportable outcome. Network failures on the MAIN request (DNS failure,
 * connection refused, timeout/abort) DO still throw — there is no
 * meaningful partial result when the main document could not be fetched at
 * all; the caller (Pass 2's pipeline wiring) is expected to catch this.
 */
export async function fetchTarget(
  url: string,
  opts: FetchTargetOptions = {},
  deps: FetchDeps = { fetch },
): Promise<FetchedTarget> {
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const maxBodyBytes = opts.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES;
  const maxScripts = opts.maxScripts ?? DEFAULT_MAX_SCRIPTS;
  const maxRedirects = opts.maxRedirects ?? DEFAULT_MAX_REDIRECTS;

  const response = await deps.fetch(url, {
    headers: { "user-agent": USER_AGENT },
    signal: AbortSignal.timeout(timeoutMs),
    redirect: maxRedirects > 0 ? "follow" : "manual",
  });

  const headers = lowercaseHeaders(response.headers);
  const cookies = extractSetCookies(response.headers);
  const body = await readBoundedBody(response, maxBodyBytes);
  const finalUrl = response.url.length > 0 ? response.url : url;

  const scripts: FetchedScript[] = [];
  if (response.ok) {
    const scriptUrls = collectSameOriginScriptUrls(body, finalUrl, maxScripts);
    for (const scriptUrl of scriptUrls) {
      // Sequential by design (not Promise.all): a bounded, well-behaved
      // crawler should not fan out N concurrent requests against a
      // third-party target it may not be fully authorized to hammer.
      const fetched = await fetchScript(scriptUrl, timeoutMs, maxBodyBytes, deps);
      if (fetched !== undefined) {
        scripts.push(fetched);
      }
    }
  }

  return {
    url: finalUrl,
    status: response.status,
    headers,
    body,
    scripts,
    cookies,
  };
}

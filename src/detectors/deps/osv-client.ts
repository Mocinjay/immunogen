/**
 * osv-client — OSV.dev batch vulnerability query client (DEP-01).
 *
 * `queryOsvBatch` is the ONLY function in this codebase that POSTs to
 * OSV.dev (api.osv.dev/v1/querybatch); `fetchVulnSeverities` GETs the full
 * record of advisories that query already returned (public advisory ids
 * only) to rate them. Both live in their own module
 * specifically so `osv-detector.ts`'s tests can stub it at the module
 * boundary (`vi.mock("./osv-client.js", ...)`) rather than reaching for
 * global fetch directly.
 *
 * Privacy contract: the
 * request body is built from ONLY `{ package: { name, ecosystem: "npm" },
 * version }` per query — no other package.json field (scripts, author,
 * etc.) is ever read by this module, because this module never sees the
 * raw package.json at all; it only receives the already-narrowed
 * `{ name, version }` pairs the caller (`osv-detector.ts`) constructed.
 *
 * `queryOsvBatch` uses the global `fetch` (Node >=22 built-in) with a
 * 10-second hard timeout.
 *
 * Fail-safe contract: ANY failure mode — network error, non-2xx HTTP
 * status, the 10-second timeout firing, or a response body that is not
 * valid JSON in the expected shape — causes this function to THROW an
 * `OsvUnavailableError`. It NEVER returns a value on failure (no
 * `[[] for _ in packages]`-style silent-empty return, which is exactly the
 * anti-pattern that hides an outage as "no vulnerabilities"). The caller
 * (`osv-detector.ts`) catches this error and switches to the bundled
 * offline fallback list, always appending a visible DEP-OFFLINE sentinel.
 *
 * An in-memory `Map` keyed by `name@version` caches successful per-query
 * results across calls within the same process (avoids re-querying the
 * same package). The cache is process-lifetime only — no disk persistence,
 * no TTL.
 */

import { severityFromOsvRecord } from "./osv-severity.js";

import type { Severity } from "../../core/types.js";

/** 10-second hard timeout for the entire OSV.dev round trip. */
const OSV_TIMEOUT_MS = 10_000;

/** OSV.dev batch query endpoint — no API key required. */
const OSV_QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch";

/** A single dependency to check, reduced to the only fields ever sent over the network. */
export interface OsvQuery {
  name: string;
  version: string;
  /** OSV ecosystem; defaults to npm. */
  ecosystem?: "npm" | "PyPI" | "Go";
}

/** A single OSV.dev vulnerability record, narrowed to the `id` field this detector consumes. */
export interface OsvVuln {
  id: string;
}

/** One result entry aligned by index to the corresponding `OsvQuery` in the request (OSV.dev querybatch contract). */
export interface OsvResult {
  vulns?: OsvVuln[];
}

/**
 * Thrown by `queryOsvBatch` on ANY failure mode (network error, non-2xx,
 * timeout, malformed response). The caller MUST catch this and fall back
 * to the offline list — this type exists so that fallback branch can be
 * distinguished from a programmer error via `instanceof`, without relying
 * on string-matching an error message.
 */
export class OsvUnavailableError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "OsvUnavailableError";
  }
}

/** In-memory session cache: `"name@version"` -> that query's OSV result. Process-lifetime only, no disk/TTL. */
const sessionCache = new Map<string, OsvResult>();

/** Builds the stable `name@version` cache key for a single query. */
function cacheKey(query: OsvQuery): string {
  return `${query.ecosystem ?? "npm"}:${query.name}@${query.version}`;
}

/**
 * Narrows an unknown parsed-JSON value to `OsvResult[]` defensively: OSV.dev
 * is an external, untrusted response source, so this
 * function trusts nothing about its shape beyond "is it an array" — any
 * entry that is not a plausible result object is left as `{}` (no vulns)
 * rather than crashing the whole batch on one malformed entry.
 */
function narrowOsvResults(parsed: unknown): OsvResult[] | undefined {
  if (!Array.isArray(parsed)) {
    return undefined;
  }

  return parsed.map((entry): OsvResult => {
    if (typeof entry !== "object" || entry === null) {
      return {};
    }
    const candidate = entry as { vulns?: unknown };
    if (!Array.isArray(candidate.vulns)) {
      return {};
    }
    const vulns = candidate.vulns
      .filter((vuln): vuln is { id: unknown } => typeof vuln === "object" && vuln !== null && "id" in vuln)
      .filter((vuln) => typeof vuln.id === "string")
      .map((vuln): OsvVuln => ({ id: vuln.id as string }));
    return { vulns };
  });
}

/** OSV.dev accepts at most this many queries per querybatch request. */
const OSV_MAX_BATCH = 1000;

/**
 * POSTs one querybatch request (at most OSV_MAX_BATCH queries) and stores
 * each aligned result in the session cache. Throws OsvUnavailableError on
 * any failure (see `queryOsvBatch`).
 */
async function queryOsvChunk(uncachedQueries: OsvQuery[]): Promise<void> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => {
    controller.abort();
  }, OSV_TIMEOUT_MS);

  try {
    const body = JSON.stringify({
      queries: uncachedQueries.map((query) => ({
        package: { name: query.name, ecosystem: query.ecosystem ?? "npm" },
        version: query.version,
      })),
    });

    const response = await fetch(OSV_QUERYBATCH_URL, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body,
      signal: controller.signal,
    });

    if (!response.ok) {
      throw new OsvUnavailableError(`OSV.dev responded with HTTP ${String(response.status)}`);
    }

    const parsedBody: unknown = await response.json();
    const resultsObject = parsedBody as { results?: unknown };
    const results = narrowOsvResults(resultsObject.results);
    if (results === undefined || results.length !== uncachedQueries.length) {
      throw new OsvUnavailableError("OSV.dev returned a response in an unexpected shape");
    }

    // Zips `uncachedQueries` with `results` into pairs up front (both
    // arrays were just verified to have equal length above), then
    // iterates the pairs directly — avoids indexing into `results` by a
    // loop counter entirely, sidestepping security/detect-object-injection
    // rather than just asserting the index is safe.
    const pairs: Array<[OsvQuery, OsvResult]> = uncachedQueries.map((query, index) => [
      query,
      results.at(index) ?? {},
    ]);
    for (const [query, result] of pairs) {
      sessionCache.set(cacheKey(query), result);
    }
  } catch (error) {
    if (error instanceof OsvUnavailableError) {
      throw error;
    }
    throw new OsvUnavailableError("OSV.dev query failed (network error, timeout, or malformed response)", {
      cause: error,
    });
  } finally {
    clearTimeout(timeoutId);
  }
}

/**
 * POSTs `queries` to OSV.dev's batch endpoint and returns the aligned
 * `OsvResult[]` (one entry per input query, same order). Queries already
 * present in the in-memory session cache short-circuit the network call
 * for that entry (avoids the OSV N+1 trap on repeated package names across
 * scans within the same process).
 *
 * The request body contains ONLY `{ package: { name, ecosystem: "npm" },
 * version }` per query — `queries` itself (the caller's input) already
 * carries nothing beyond `{ name, version }` (see `OsvQuery`), so there is
 * no other package.json field this function COULD serialize even if it
 * tried (privacy contract).
 *
 * On ANY failure (network error, non-2xx status, the AbortController
 * 10-second timeout firing, or a response that does not parse to the
 * expected shape) this function THROWS `OsvUnavailableError` — it never
 * returns a placeholder/empty result on failure.
 */
export async function queryOsvBatch(queries: OsvQuery[]): Promise<OsvResult[]> {
  const seen = new Set<string>();
  const uncachedQueries = queries.filter((query) => {
    const key = cacheKey(query);
    if (sessionCache.has(key) || seen.has(key)) {
      return false;
    }
    seen.add(key);
    return true;
  });

  // A lockfile can resolve thousands of packages: query in API-sized chunks.
  for (let start = 0; start < uncachedQueries.length; start += OSV_MAX_BATCH) {
    await queryOsvChunk(uncachedQueries.slice(start, start + OSV_MAX_BATCH));
  }

  return queries.map((query) => sessionCache.get(cacheKey(query)) ?? {});
}

/** OSV.dev single-vulnerability endpoint (full record, incl. severity). */
const OSV_VULN_URL = "https://api.osv.dev/v1/vulns/";

/** Concurrent record fetches per `fetchVulnSeverities` call. */
const SEVERITY_FETCH_CONCURRENCY = 8;

/** OSV advisory ids are short tokens like GHSA-xxxx-xxxx-xxxx, PYSEC-2023-1, GO-2023-1, CVE-2024-1. */
const OSV_ID_RE = /^[A-Za-z0-9._:-]{3,64}$/;

/** Session cache: advisory id -> its severity, or null when the record carries none. */
const severityCache = new Map<string, Severity | null>();

/**
 * Fetches the full OSV record for each advisory id and returns the
 * severities it could determine (see osv-severity.ts). Best-effort by
 * design: the batch query already established THAT a package is
 * vulnerable, so a failed or slow lookup here only loses the precise
 * rating — the id is simply absent from the result and the caller keeps
 * its default. Only public advisory ids are sent. Never throws.
 */
export async function fetchVulnSeverities(ids: string[]): Promise<Map<string, Severity>> {
  const pending = [...new Set(ids)].filter((id) => OSV_ID_RE.test(id) && !severityCache.has(id));
  if (pending.length > 0) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => {
      controller.abort();
    }, OSV_TIMEOUT_MS);
    try {
      const queue = [...pending];
      const worker = async (): Promise<void> => {
        for (let id = queue.shift(); id !== undefined; id = queue.shift()) {
          try {
            const response = await fetch(`${OSV_VULN_URL}${encodeURIComponent(id)}`, { signal: controller.signal });
            if (response.ok) {
              severityCache.set(id, severityFromOsvRecord(await response.json()) ?? null);
            }
          } catch {
            // Leave this id unrated; a later scan in the same process may retry it.
          }
        }
      };
      await Promise.all(Array.from({ length: Math.min(SEVERITY_FETCH_CONCURRENCY, pending.length) }, worker));
    } finally {
      clearTimeout(timeoutId);
    }
  }

  const severities = new Map<string, Severity>();
  for (const id of ids) {
    const severity = severityCache.get(id);
    if (severity !== undefined && severity !== null) {
      severities.set(id, severity);
    }
  }
  return severities;
}

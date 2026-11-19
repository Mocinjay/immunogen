/**
 * Shared HTTP helper for the dependency checks (OSV.dev, the npm and PyPI
 * registries): a per-attempt timeout plus a couple of retries with backoff
 * on network errors, timeouts, HTTP 429 and 5xx — one blip must not turn a
 * whole check into a degraded result.
 */

/** Default per-attempt timeout. */
const REQUEST_TIMEOUT_MS = 10_000;

/** Extra attempts after a transient failure (network error, timeout, HTTP 429 / 5xx). */
const RETRIES = 2;

/** Base backoff before a retry; doubled per attempt, or replaced by a (capped) Retry-After. */
const BACKOFF_MS = 400;

/** Longest Retry-After honored. */
const MAX_RETRY_AFTER_MS = 5_000;

/** True for responses worth retrying. */
function isTransientStatus(status: number): boolean {
  return status === 429 || status >= 500;
}

/** Waits `ms` milliseconds. */
async function sleep(ms: number): Promise<void> {
  await new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

/** Delay before retry `attempt` (0-based): Retry-After when the server sent one, else exponential backoff. */
function retryDelay(attempt: number, response?: Response): number {
  const header = response?.headers.get("retry-after");
  const seconds = header === null || header === undefined ? Number.NaN : Number.parseFloat(header);
  if (Number.isFinite(seconds) && seconds >= 0) {
    return Math.min(seconds * 1000, MAX_RETRY_AFTER_MS);
  }
  return BACKOFF_MS * 2 ** attempt;
}

/**
 * `fetch` with a per-attempt timeout and up to RETRIES retries on a
 * transient failure. Returns the last response (which may be a non-OK
 * status) or throws the last network error.
 */
export async function fetchWithRetry(url: string, init: RequestInit = {}, timeoutMs = REQUEST_TIMEOUT_MS): Promise<Response> {
  let lastError: unknown;
  for (let attempt = 0; attempt <= RETRIES; attempt += 1) {
    try {
      const response = await fetch(url, { ...init, signal: AbortSignal.timeout(timeoutMs) });
      if (!isTransientStatus(response.status) || attempt === RETRIES) {
        return response;
      }
      await response.body?.cancel().catch(() => undefined);
      await sleep(retryDelay(attempt, response));
    } catch (error) {
      lastError = error;
      if (attempt === RETRIES) {
        break;
      }
      await sleep(retryDelay(attempt));
    }
  }
  throw lastError instanceof Error ? lastError : new Error(String(lastError));
}


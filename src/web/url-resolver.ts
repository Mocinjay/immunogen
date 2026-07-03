/**
 * url-resolver — Pass 1 foundation for live URL / website screening.
 *
 * This module classifies and normalizes a caller-supplied string into an
 * absolute URL, then enforces the two hard gates a live-target screen must
 * pass before ANY network request is ever made against it:
 *
 *   1. Consent gate — live-URL screening probes a third party's running
 *      infrastructure, unlike the existing dir/git/zip inputs which only
 *      ever read bytes the caller already possesses. `resolveUrlTarget`
 *      refuses to proceed unless the caller explicitly opts in via
 *      `opts.authorize === true`, mirroring how a pentest requires signed
 *      authorization before any probe traffic is sent.
 *
 *   2. SSRF guard — refuses to resolve any target whose *hostname* names a
 *      loopback/private/link-local/metadata-service address, so a caller
 *      cannot point this tool at their own internal network (`localhost`,
 *      `10.0.0.0/8`, the AWS/GCP metadata IP `169.254.169.254`, etc.) and
 *      have it dutifully fetch internal-only content. `opts.allowPrivate`
 *      is an explicit escape hatch for local dev/test scenarios.
 *
 * Both functions are pure and synchronous — no network I/O happens in this
 * module at all (that is Task 3's `fetch-target.ts`). This keeps the whole
 * module trivially unit-testable and keeps the consent/SSRF decision fully
 * deterministic and independent of network conditions.
 *
 * Pass 1 scope note: this module is NOT wired into `resolveInput`, `scan()`,
 * or the CLI yet — it exists standalone so Pass 2 can wire it into the
 * pipeline without touching its internals.
 */

/** Options accepted by `resolveUrlTarget`. A subset of `ScanOptions` (src/core/types.ts) the URL branch reads. */
export interface ResolveUrlTargetOptions {
  /** Must be `true` for `resolveUrlTarget` to proceed at all — the consent gate. */
  authorize?: boolean;
  /** Escape hatch for the SSRF guard — `true` permits loopback/private/link-local/metadata hosts (local dev/test only). */
  allowPrivate?: boolean;
}

/** The normalized result of resolving a URL input: the caller-facing absolute URL plus its hostname (for logging/allowlisting downstream). */
export interface ResolvedUrlTarget {
  /** The normalized absolute URL, exactly as `normalizeUrl` produced it. */
  url: string;
  /** The URL's hostname (lowercased, no port, no brackets for IPv6). */
  host: string;
}

/** Exact, actionable error message thrown when `opts.authorize` is not `true`. */
export const AUTHORIZATION_REQUIRED_MESSAGE =
  "Live-URL screening requires explicit authorization (--authorize): only screen sites you own or are authorized to test.";

/**
 * True when `input` begins with the `http://` or `https://` scheme
 * (case-insensitive). This is the sole classification signal
 * `resolveInput` (Pass 2) will use to route a caller's input string to the
 * URL branch instead of the dir/git/zip branches — it deliberately does NOT
 * attempt to guess "looks like a domain" from a bare hostname (e.g.
 * `example.com` with no scheme), since that is ambiguous with a relative
 * directory name.
 */
export function isUrl(input: string): boolean {
  return /^https?:\/\//i.test(input);
}

/**
 * Parses `input` into a normalized absolute URL string via the built-in
 * `URL` constructor, rejecting anything that is not `http:`/`https:`.
 * Throws a clear, user-readable `Error` (never a raw `TypeError` from the
 * `URL` constructor) on any malformed or non-HTTP(S) input.
 */
export function normalizeUrl(input: string): string {
  let parsed: URL;
  try {
    parsed = new URL(input);
  } catch {
    throw new Error(`Invalid URL: "${input}"`);
  }

  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error(`Invalid URL: "${input}" — only http:// and https:// are supported`);
  }

  return parsed.toString();
}

/** True when `host` is exactly `localhost` or ends with the `.local` mDNS TLD (case-insensitive). */
function isLoopbackHostname(host: string): boolean {
  const lower = host.toLowerCase();
  return lower === "localhost" || lower.endsWith(".local");
}

/**
 * True when `host` is the literal IPv6 loopback address, written either
 * bracketed (as `URL.host` yields, e.g. `[::1]`) or unbracketed (as
 * `URL.hostname` yields, e.g. `::1`). Per the task spec, only the literal
 * `::1` loopback form is checked — no full IPv6 private-range parsing.
 */
function isIpv6Loopback(host: string): boolean {
  return host === "::1" || host === "[::1]";
}

/**
 * Parses `host` as a dotted-quad IPv4 literal, returning its four octets,
 * or `undefined` if `host` is not a syntactically valid IPv4 literal
 * (e.g. it is a hostname like `example.com`). Deliberately simple/strict:
 * exactly four dot-separated segments, each a base-10 integer 0-255 with no
 * leading-zero ambiguity concerns beyond what `Number` already rejects here
 * (this resolver only needs to classify address *ranges*, not fully
 * validate arbitrary IPv4 textual forms).
 */
function parseIpv4(host: string): [number, number, number, number] | undefined {
  const segments = host.split(".");
  if (segments.length !== 4) {
    return undefined;
  }

  const octets: number[] = [];
  for (const segment of segments) {
    if (!/^\d{1,3}$/.test(segment)) {
      return undefined;
    }
    const value = Number(segment);
    if (value > 255) {
      return undefined;
    }
    octets.push(value);
  }

  const [a, b, c, d] = octets;
  if (a === undefined || b === undefined || c === undefined || d === undefined) {
    return undefined;
  }
  return [a, b, c, d];
}

/**
 * True when `host` is an IPv4 literal falling in any blocked range: the
 * `127.0.0.0/8` loopback block, `10.0.0.0/8`, `172.16.0.0/12`,
 * `192.168.0.0/16` (RFC 1918 private ranges), `169.254.0.0/16` (link-local,
 * which also covers the `169.254.169.254` cloud-metadata address), or the
 * unspecified address `0.0.0.0`.
 */
function isBlockedIpv4(host: string): boolean {
  const octets = parseIpv4(host);
  if (octets === undefined) {
    return false;
  }
  const [a, b] = octets;

  if (host === "0.0.0.0") {
    return true;
  }
  if (a === 127) {
    return true;
  }
  if (a === 10) {
    return true;
  }
  if (a === 172 && b >= 16 && b <= 31) {
    return true;
  }
  if (a === 192 && b === 168) {
    return true;
  }
  if (a === 169 && b === 254) {
    return true;
  }
  return false;
}

/**
 * True when `hostname` (as returned by `URL.hostname` — lowercased, no
 * port, IPv6 literals unbracketed) names a loopback, private, link-local,
 * or cloud-metadata address that a live-URL screen must never probe absent
 * `opts.allowPrivate`.
 */
function isPrivateOrLoopbackHost(hostname: string): boolean {
  const lower = hostname.toLowerCase();
  return isLoopbackHostname(lower) || isIpv6Loopback(lower) || isBlockedIpv4(lower);
}

/**
 * Resolves a caller-supplied URL input to a `{ url, host }` pair, enforcing
 * the consent gate and the SSRF guard described in this file's header.
 * Throws before returning anything if either gate fails — there is no
 * partial/degraded success path for a rejected target.
 *
 * Order: the consent gate is checked BEFORE the URL is even parsed for the
 * SSRF check, so an unauthorized caller's error message never depends on
 * whether their input happened to be a valid URL — the “you need
 * --authorize” message is the single actionable next step regardless.
 */
export function resolveUrlTarget(input: string, opts: ResolveUrlTargetOptions = {}): ResolvedUrlTarget {
  if (opts.authorize !== true) {
    throw new Error(AUTHORIZATION_REQUIRED_MESSAGE);
  }

  const normalized = normalizeUrl(input);
  const parsed = new URL(normalized);
  const hostname = parsed.hostname;

  if (opts.allowPrivate !== true && isPrivateOrLoopbackHost(hostname)) {
    throw new Error(
      `Refusing to probe private/loopback host "${hostname}" — pass --allow-private to override for local dev/test.`,
    );
  }

  return {
    url: normalized,
    host: hostname,
  };
}

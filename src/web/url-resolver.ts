/**
 * url-resolver — input classification and gating for live URL / website screening.
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
 *   2. SSRF pre-flight — refuses a target whose hostname is a private name
 *      or a non-public IP literal (loopback, RFC 1918, CGNAT, link-local incl.
 *      `169.254.169.254`, IPv6 ULA/link-local, IPv4-mapped forms, ...).
 *      `opts.allowPrivate` is an explicit escape hatch for local dev/test.
 *      This is only the first, synchronous layer: `assertPublicUrl`
 *      (host-guard.ts) resolves DNS and re-checks before EVERY request,
 *      including each redirect hop, so a public name pointing at a private
 *      address or a redirect into the internal network is refused too.
 *
 * Both functions are pure and synchronous — no network I/O happens here.
 */

import { isIP } from "node:net";

import { isBlockedAddress, isPrivateName } from "./host-guard.js";

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
 * `scan()` uses to route a caller's input string to the
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

/**
 * True when `hostname` (as `URL.hostname` yields it — IPv6 bracketed) is a
 * private name or a non-public IP literal. This is the synchronous,
 * pre-flight half of the SSRF guard; `assertPublicUrl` (host-guard.ts) also
 * resolves DNS and runs before every request, including redirect hops.
 */
function isPrivateOrLoopbackHost(hostname: string): boolean {
  const host = hostname.replace(/^\[|\]$/g, "");
  return isPrivateName(host) || (isIP(host) !== 0 && isBlockedAddress(host));
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

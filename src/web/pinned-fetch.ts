/**
 * pinned-fetch — the `fetch` live-URL screening uses when the SSRF guard is
 * on. It closes the DNS-rebinding window left by checking a hostname and then
 * letting `fetch` resolve it again: the address check runs inside the socket's
 * own DNS lookup, so the connection goes to exactly the addresses that passed
 * `isBlockedAddress` and nothing else.
 *
 * `assertPublicUrl` (host-guard.ts) still runs before every request for its
 * clear error messages and name-based rules; this is the connect-time
 * backstop. IP-literal hosts never reach a lookup and are covered by
 * `assertPublicUrl` alone.
 */
import { lookup as dnsLookup } from "node:dns";

import { Agent, fetch as undiciFetch } from "undici";

import { isBlockedAddress } from "./host-guard.js";

import type { LookupAddress, LookupAllOptions, LookupOneOptions } from "node:dns";
import type { RequestInit as UndiciRequestInit } from "undici";

/** The `dns.lookup(hostname, { all: true }, cb)` shape this module resolves through. */
export type ResolveAll = (
  hostname: string,
  options: LookupAllOptions,
  callback: (error: NodeJS.ErrnoException | null, addresses: LookupAddress[]) => void,
) => void;

/** The lookup signature `net.connect` / `tls.connect` call (with or without `all`). */
type ConnectLookup = (
  hostname: string,
  options: LookupOneOptions | LookupAllOptions,
  callback: (error: NodeJS.ErrnoException | null, address: string | LookupAddress[], family?: number) => void,
) => void;

const defaultResolveAll: ResolveAll = (hostname, options, callback) => {
  dnsLookup(hostname, options, callback);
};

/**
 * Builds a socket `lookup` that resolves every address for `hostname` and
 * fails the connection if ANY of them is private / loopback / link-local /
 * reserved (same policy as `assertPublicUrl`). `resolveAll` is injectable so
 * tests never touch real DNS.
 */
export function createGuardedLookup(resolveAll: ResolveAll = defaultResolveAll): ConnectLookup {
  return (hostname, options, callback) => {
    resolveAll(hostname, { ...options, all: true, verbatim: true }, (error, addresses) => {
      if (error) {
        callback(error, []);
        return;
      }
      const blocked = addresses.find((entry) => isBlockedAddress(entry.address));
      const [first] = addresses;
      if (blocked !== undefined || first === undefined) {
        const refusal: NodeJS.ErrnoException = new Error(
          blocked === undefined
            ? `Could not resolve host "${hostname}".`
            : `Refusing to connect to private/loopback address ${blocked.address} (resolved from "${hostname}") — pass --allow-private to override for local dev/test.`,
        );
        refusal.code = blocked === undefined ? "ENOTFOUND" : "EBLOCKEDADDRESS";
        callback(refusal, []);
        return;
      }
      if (options.all === true) {
        callback(null, addresses);
      } else {
        callback(null, first.address, first.family);
      }
    });
  };
}

/**
 * Returns a `fetch` whose every connection is pinned to guard-approved
 * addresses (see the module comment). Each call site gets its own connection
 * pool; it holds no global state.
 */
export function createPinnedFetch(resolveAll?: ResolveAll): typeof fetch {
  const dispatcher = new Agent({ connect: { lookup: createGuardedLookup(resolveAll) } });
  // Node's global fetch types (undici-types) and the undici package's types
  // describe the same runtime objects but are nominally distinct, hence the
  // init cast. Callers pass URL strings; a Request is reduced to its URL.
  return (input, init) => {
    const url = typeof input === "string" || input instanceof URL ? input : input.url;
    return undiciFetch(url, { ...(init as UndiciRequestInit | undefined), dispatcher });
  };
}

/**
 * host-guard — the SSRF policy for live-URL screening.
 *
 * `assertPublicUrl(url, opts)` throws unless every address `url`'s host
 * resolves to is public, globally-routable unicast. It runs before EVERY
 * request a URL screen makes — the main document, each redirect hop, each
 * script, each probe — so neither a redirect (`302 -> 169.254.169.254`) nor a
 * public name that resolves to a private address (`127.0.0.1.nip.io`, an
 * internal CNAME) reaches an internal service.
 *
 * Blocked: loopback, RFC 1918 private, CGNAT (`100.64.0.0/10`, incl. the
 * Alibaba metadata address), link-local (incl. `169.254.169.254`), "this
 * network" (`0.0.0.0/8`), IETF/benchmark/documentation ranges, multicast and
 * reserved space; IPv6 loopback/unspecified, ULA `fc00::/7` (incl. AWS IMDS
 * `fd00:ec2::254`), link-local `fe80::/10`, multicast, documentation, and
 * any IPv4-mapped / NAT64 address whose embedded IPv4 is blocked; plus the
 * names `localhost`, `*.localhost`, `*.local`, `*.internal`.
 *
 * Residual risk (documented, not closed): the check resolves the name and
 * `fetch` then resolves it again, so a DNS-rebinding server can answer
 * differently between the two lookups. Closing that requires pinning the
 * connection to the checked address with a custom dispatcher.
 *
 * DNS resolution lives in dns-resolve.ts so tests can stub it at the module
 * boundary without touching the network.
 */
import { BlockList, isIP } from "node:net";

import { resolveHostAddresses } from "./dns-resolve.js";

/** Options for `assertPublicUrl`. */
export interface HostGuardOptions {
  /** `--allow-private`: skip the guard entirely (local dev/test only). */
  allowPrivate?: boolean;
}

const BLOCKED = new BlockList();
for (const [network, prefix] of [
  ["0.0.0.0", 8],
  ["10.0.0.0", 8],
  ["100.64.0.0", 10],
  ["127.0.0.0", 8],
  ["169.254.0.0", 16],
  ["172.16.0.0", 12],
  ["192.0.0.0", 24],
  ["192.0.2.0", 24],
  ["192.88.99.0", 24],
  ["192.168.0.0", 16],
  ["198.18.0.0", 15],
  ["198.51.100.0", 24],
  ["203.0.113.0", 24],
  ["224.0.0.0", 4],
  ["240.0.0.0", 4],
] as const) {
  BLOCKED.addSubnet(network, prefix, "ipv4");
}
for (const [network, prefix] of [
  ["::", 128],
  ["::1", 128],
  ["100::", 64],
  ["2001:db8::", 32],
  ["fc00::", 7],
  ["fe80::", 10],
  ["ff00::", 8],
] as const) {
  BLOCKED.addSubnet(network, prefix, "ipv6");
}

/** Expands an IPv6 literal (no brackets, no zone) to its eight 16-bit groups, or undefined. */
function ipv6Groups(address: string): number[] | undefined {
  let text = address.toLowerCase();
  // A trailing dotted-quad (`::ffff:1.2.3.4`) becomes two hex groups.
  const dotted = text.match(/^(.*:)(\d+\.\d+\.\d+\.\d+)$/);
  if (dotted !== null) {
    const octets = (dotted[2] ?? "").split(".").map(Number);
    const [a = 0, b = 0, c = 0, d = 0] = octets;
    text = `${dotted[1] ?? ""}${((a << 8) | b).toString(16)}:${((c << 8) | d).toString(16)}`;
  }
  const halves = text.split("::");
  if (halves.length > 2) {
    return undefined;
  }
  const head = halves[0] === undefined || halves[0] === "" ? [] : halves[0].split(":");
  const tail = halves.length === 2 && halves[1] !== undefined && halves[1] !== "" ? halves[1].split(":") : [];
  const missing = 8 - head.length - tail.length;
  if (missing < 0 || (halves.length === 1 && missing !== 0)) {
    return undefined;
  }
  const groups = [...head, ...Array.from({ length: missing }, () => "0"), ...tail].map((group) => Number.parseInt(group, 16));
  return groups.length === 8 && groups.every((group) => Number.isInteger(group) && group >= 0 && group <= 0xffff) ? groups : undefined;
}

/** The IPv4 address embedded in an IPv4-mapped (`::ffff:0:0/96`) or NAT64 (`64:ff9b::/96`) IPv6 address. */
function embeddedIpv4(address: string): string | undefined {
  const groups = ipv6Groups(address);
  if (groups === undefined) {
    return undefined;
  }
  const [g0, g1, g2, g3, g4, g5, g6 = 0, g7 = 0] = groups;
  const isMapped = g0 === 0 && g1 === 0 && g2 === 0 && g3 === 0 && g4 === 0 && g5 === 0xffff;
  const isNat64 = g0 === 0x64 && g1 === 0xff9b && g2 === 0 && g3 === 0 && g4 === 0 && g5 === 0;
  if (!isMapped && !isNat64) {
    return undefined;
  }
  return [g6 >> 8, g6 & 0xff, g7 >> 8, g7 & 0xff].join(".");
}

/** True when `address` (an IPv4 or IPv6 literal) is not public unicast. */
export function isBlockedAddress(address: string): boolean {
  const family = isIP(address);
  if (family === 4) {
    return BLOCKED.check(address, "ipv4");
  }
  if (family === 6) {
    const embedded = embeddedIpv4(address);
    if (embedded !== undefined) {
      return BLOCKED.check(embedded, "ipv4");
    }
    return BLOCKED.check(address, "ipv6");
  }
  // Not an IP literal at all — never treat it as safe.
  return true;
}

/** Hostnames that name the local machine or a private namespace, whatever DNS says. */
export function isPrivateName(hostname: string): boolean {
  const lower = hostname.toLowerCase().replace(/\.$/, "");
  return (
    lower === "localhost" ||
    lower.endsWith(".localhost") ||
    lower.endsWith(".local") ||
    lower.endsWith(".internal") ||
    lower.endsWith(".home.arpa")
  );
}

/**
 * Throws unless `url` is http(s) and every address its host resolves to is
 * public (see the module comment). A no-op when `opts.allowPrivate`.
 */
export async function assertPublicUrl(url: URL, opts: HostGuardOptions = {}): Promise<void> {
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error(`Refusing to fetch non-HTTP URL: ${url.toString()}`);
  }
  if (opts.allowPrivate === true) {
    return;
  }
  const hostname = url.hostname.replace(/^\[|\]$/g, "");
  const refuse = (detail: string): Error =>
    new Error(`Refusing to probe private/loopback host "${hostname}"${detail} — pass --allow-private to override for local dev/test.`);

  if (isPrivateName(hostname)) {
    throw refuse("");
  }
  if (isIP(hostname) !== 0) {
    if (isBlockedAddress(hostname)) {
      throw refuse("");
    }
    return;
  }

  let addresses: string[];
  try {
    addresses = await resolveHostAddresses(hostname);
  } catch {
    throw new Error(`Could not resolve host "${hostname}".`);
  }
  if (addresses.length === 0) {
    throw new Error(`Could not resolve host "${hostname}".`);
  }
  const blocked = addresses.find(isBlockedAddress);
  if (blocked !== undefined) {
    throw refuse(` (resolves to ${blocked})`);
  }
}

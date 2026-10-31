/**
 * DNS seam for the SSRF guard (host-guard.ts): every address a hostname
 * resolves to. Its own module so tests can replace it at the module boundary
 * (`vi.mock("./dns-resolve.js")`) and never touch real DNS.
 */
import { lookup } from "node:dns/promises";

export async function resolveHostAddresses(hostname: string): Promise<string[]> {
  const results = await lookup(hostname, { all: true, verbatim: true });
  return results.map((result) => result.address);
}

import { createServer } from "node:http";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { createGuardedLookup, createPinnedFetch } from "./pinned-fetch.js";

import type { ResolveAll } from "./pinned-fetch.js";
import type { LookupAddress } from "node:dns";
import type { AddressInfo, Server } from "node:net";

/** A fake resolver: answers from `table`, ENOTFOUND for anything else. */
function fakeResolver(table: Record<string, LookupAddress[]>): ResolveAll {
  const answers = new Map(Object.entries(table));
  return (hostname, _options, callback) => {
    const addresses = answers.get(hostname);
    if (addresses === undefined) {
      const error: NodeJS.ErrnoException = new Error(`getaddrinfo ENOTFOUND ${hostname}`);
      error.code = "ENOTFOUND";
      callback(error, []);
      return;
    }
    callback(null, addresses);
  };
}

/** Calls a guarded lookup and resolves with what it reported. */
function runLookup(
  resolveAll: ResolveAll,
  hostname: string,
  all: boolean,
): Promise<{ error: NodeJS.ErrnoException | null; address: unknown; family: unknown }> {
  return new Promise((resolve) => {
    createGuardedLookup(resolveAll)(hostname, { all }, (error, address, family) => {
      resolve({ error, address, family });
    });
  });
}

const PUBLIC = { address: "93.184.216.34", family: 4 };
const LOOPBACK = { address: "127.0.0.1", family: 4 };
const METADATA = { address: "169.254.169.254", family: 4 };
const ULA_V6 = { address: "fd00:ec2::254", family: 6 };

describe("createGuardedLookup — connect-time SSRF check", () => {
  it("returns the single public address for a public host", async () => {
    const result = await runLookup(fakeResolver({ "public.example": [PUBLIC] }), "public.example", false);

    expect(result.error).toBeNull();
    expect(result.address).toBe(PUBLIC.address);
    expect(result.family).toBe(4);
  });

  it("returns every address when the socket asks for all of them", async () => {
    const second = { address: "2606:2800:220:1::1", family: 6 };
    const result = await runLookup(fakeResolver({ "public.example": [PUBLIC, second] }), "public.example", true);

    expect(result.error).toBeNull();
    expect(result.address).toEqual([PUBLIC, second]);
  });

  it.each([
    ["loopback", LOOPBACK],
    ["cloud metadata", METADATA],
    ["IPv6 ULA (AWS IMDS)", ULA_V6],
  ])("refuses a host that resolves to a %s address", async (_label, address) => {
    const result = await runLookup(fakeResolver({ "evil.example": [address] }), "evil.example", false);

    expect(result.error?.code).toBe("EBLOCKEDADDRESS");
    expect(result.error?.message).toContain(address.address);
  });

  it("refuses a host whose answer mixes public and private addresses (rebinding / split answer)", async () => {
    const result = await runLookup(fakeResolver({ "rebind.example": [PUBLIC, LOOPBACK] }), "rebind.example", true);

    expect(result.error?.code).toBe("EBLOCKEDADDRESS");
  });

  it("passes resolver errors through and treats an empty answer as unresolvable", async () => {
    const missing = await runLookup(fakeResolver({}), "missing.example", false);
    const empty = await runLookup(fakeResolver({ "empty.example": [] }), "empty.example", false);

    expect(missing.error?.code).toBe("ENOTFOUND");
    expect(empty.error?.code).toBe("ENOTFOUND");
  });
});

describe("createPinnedFetch — the block happens on the real connection", () => {
  let server: Server;
  let port: number;

  beforeAll(async () => {
    server = createServer((_request, response) => {
      response.end("internal service");
    });
    await new Promise<void>((resolve) => {
      server.listen(0, "127.0.0.1", resolve);
    });
    port = (server.address() as AddressInfo).port;
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => {
      server.close(() => {
        resolve();
      });
    });
  });

  it("never connects to a loopback service, even when the name looked public to an earlier check", async () => {
    // The resolver plays a rebinding DNS server: at connect time the name points at loopback.
    const pinnedFetch = createPinnedFetch(fakeResolver({ "rebind.example": [LOOPBACK] }));

    const error = await pinnedFetch(`http://rebind.example:${String(port)}/`).then(
      () => undefined,
      (rejection: unknown) => rejection as Error & { cause?: NodeJS.ErrnoException },
    );

    expect(error).toBeDefined();
    expect(error?.cause?.code).toBe("EBLOCKEDADDRESS");
  });

  it("the same local service IS reachable through plain fetch (the refusal above comes from the pin, not the server)", async () => {
    const response = await fetch(`http://127.0.0.1:${String(port)}/`);

    expect(await response.text()).toBe("internal service");
  });
});

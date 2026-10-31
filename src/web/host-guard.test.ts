import { describe, expect, it, vi } from "vitest";

const resolved = new Map<string, string[]>([
  ["public.example", ["93.184.216.34"]],
  ["rebind.example", ["93.184.216.34", "127.0.0.1"]],
  ["metadata.example", ["169.254.169.254"]],
  ["v6private.example", ["fd00:ec2::254"]],
]);

vi.mock("./dns-resolve.js", () => ({
  resolveHostAddresses: (hostname: string) => {
    const addresses = resolved.get(hostname);
    return addresses === undefined ? Promise.reject(new Error("ENOTFOUND")) : Promise.resolve(addresses);
  },
}));

const { assertPublicUrl, isBlockedAddress } = await import("./host-guard.js");

describe("isBlockedAddress", () => {
  it.each([
    "127.0.0.1",
    "10.1.2.3",
    "172.16.0.1",
    "192.168.1.1",
    "169.254.169.254",
    "100.100.100.200",
    "0.0.0.0",
    "0.1.2.3",
    "198.18.0.1",
    "224.0.0.1",
    "255.255.255.255",
    "::",
    "::1",
    "fe80::1",
    "fd00:ec2::254",
    "fc00::1",
    "ff02::1",
    "::ffff:127.0.0.1",
    "::ffff:7f00:1",
    "::ffff:a9fe:a9fe",
    "64:ff9b::a00:1",
  ])("blocks %s", (address) => {
    expect(isBlockedAddress(address)).toBe(true);
  });

  it.each(["93.184.216.34", "8.8.8.8", "172.32.0.1", "2606:4700::1111", "::ffff:8.8.8.8"])("allows %s", (address) => {
    expect(isBlockedAddress(address)).toBe(false);
  });

  it("treats a non-IP string as blocked (fail closed)", () => {
    expect(isBlockedAddress("not-an-ip")).toBe(true);
  });
});

describe("assertPublicUrl", () => {
  it("allows a host that resolves only to public addresses", async () => {
    await expect(assertPublicUrl(new URL("https://public.example/"))).resolves.toBeUndefined();
  });

  it("refuses a public-looking name that resolves to a private address", async () => {
    await expect(assertPublicUrl(new URL("https://metadata.example/"))).rejects.toThrow(/169\.254\.169\.254/);
    await expect(assertPublicUrl(new URL("https://v6private.example/"))).rejects.toThrow(/private\/loopback/);
  });

  it("refuses when ANY resolved address is private", async () => {
    await expect(assertPublicUrl(new URL("https://rebind.example/"))).rejects.toThrow(/127\.0\.0\.1/);
  });

  it("refuses private names and bracketed IPv6 literals without resolving", async () => {
    await expect(assertPublicUrl(new URL("http://app.localhost/"))).rejects.toThrow(/private\/loopback/);
    await expect(assertPublicUrl(new URL("http://metadata.google.internal/"))).rejects.toThrow(/private\/loopback/);
    await expect(assertPublicUrl(new URL("http://[::ffff:127.0.0.1]/"))).rejects.toThrow(/private\/loopback/);
  });

  it("reports an unresolvable host clearly", async () => {
    await expect(assertPublicUrl(new URL("https://nowhere.example/"))).rejects.toThrow(/Could not resolve host/);
  });

  it("refuses non-HTTP schemes even with allowPrivate", async () => {
    await expect(assertPublicUrl(new URL("file:///etc/passwd"), { allowPrivate: true })).rejects.toThrow(/non-HTTP/);
  });

  it("is a no-op for http(s) when allowPrivate is set", async () => {
    await expect(assertPublicUrl(new URL("http://127.0.0.1:3000/"), { allowPrivate: true })).resolves.toBeUndefined();
  });
});

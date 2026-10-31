import { describe, expect, it } from "vitest";

import {
  AUTHORIZATION_REQUIRED_MESSAGE,
  isUrl,
  normalizeUrl,
  resolveUrlTarget,
} from "./url-resolver.js";

describe("isUrl", () => {
  it("returns true for an http:// input", () => {
    expect(isUrl("http://example.com")).toBe(true);
  });

  it("returns true for an https:// input", () => {
    expect(isUrl("https://example.com")).toBe(true);
  });

  it("returns true case-insensitively (HTTPS://)", () => {
    expect(isUrl("HTTPS://example.com")).toBe(true);
  });

  it("returns false for a local directory path", () => {
    expect(isUrl("./my-app")).toBe(false);
  });

  it("returns false for a git@ SSH URL", () => {
    expect(isUrl("git@github.com:foo/bar.git")).toBe(false);
  });

  it("returns false for a bare hostname with no scheme", () => {
    expect(isUrl("example.com")).toBe(false);
  });

  it("returns false for a .zip path", () => {
    expect(isUrl("/path/to/archive.zip")).toBe(false);
  });
});

describe("normalizeUrl", () => {
  it("returns an https URL unchanged (modulo URL normalization)", () => {
    expect(normalizeUrl("https://example.com")).toBe("https://example.com/");
  });

  it("preserves path, query, and fragment", () => {
    expect(normalizeUrl("https://example.com/a/b?x=1#y")).toBe("https://example.com/a/b?x=1#y");
  });

  it("throws a clear error for a malformed URL", () => {
    expect(() => normalizeUrl("not a url")).toThrow(/Invalid URL/);
  });

  it("throws a clear error for a non-http(s) scheme (ftp://)", () => {
    expect(() => normalizeUrl("ftp://example.com/file")).toThrow(/only http:\/\/ and https:\/\/ are supported/);
  });

  it("throws a clear error for a file:// scheme", () => {
    expect(() => normalizeUrl("file:///etc/passwd")).toThrow(/only http:\/\/ and https:\/\/ are supported/);
  });
});

describe("resolveUrlTarget — consent gate", () => {
  it("throws the exact actionable authorization error when opts.authorize is omitted", () => {
    expect(() => resolveUrlTarget("https://example.com")).toThrow(AUTHORIZATION_REQUIRED_MESSAGE);
  });

  it("throws the exact actionable authorization error when opts.authorize is false", () => {
    expect(() => resolveUrlTarget("https://example.com", { authorize: false })).toThrow(
      AUTHORIZATION_REQUIRED_MESSAGE,
    );
  });

  it("checks the consent gate before URL validity — a malformed URL with no authorize still surfaces the authorization error", () => {
    expect(() => resolveUrlTarget("not a url")).toThrow(AUTHORIZATION_REQUIRED_MESSAGE);
  });

  it("succeeds for a public host when authorize is true", () => {
    const result = resolveUrlTarget("https://example.com", { authorize: true });
    expect(result).toEqual({ url: "https://example.com/", host: "example.com" });
  });
});

describe("resolveUrlTarget — SSRF guard", () => {
  const AUTHORIZED = { authorize: true } as const;

  it("blocks localhost", () => {
    expect(() => resolveUrlTarget("http://localhost:3000", AUTHORIZED)).toThrow(
      /refusing to probe private\/loopback host/i,
    );
  });

  it("blocks a .local mDNS hostname", () => {
    expect(() => resolveUrlTarget("http://my-box.local", AUTHORIZED)).toThrow(
      /refusing to probe private\/loopback host/i,
    );
  });

  it("blocks 127.0.0.1 (127.0.0.0/8 loopback)", () => {
    expect(() => resolveUrlTarget("http://127.0.0.1", AUTHORIZED)).toThrow(
      /refusing to probe private\/loopback host/i,
    );
  });

  it("blocks another 127.0.0.0/8 address (127.1.2.3)", () => {
    expect(() => resolveUrlTarget("http://127.1.2.3", AUTHORIZED)).toThrow(
      /refusing to probe private\/loopback host/i,
    );
  });

  it("blocks a 10.0.0.0/8 address", () => {
    expect(() => resolveUrlTarget("http://10.1.2.3", AUTHORIZED)).toThrow(
      /refusing to probe private\/loopback host/i,
    );
  });

  it("blocks a 172.16.0.0/12 address", () => {
    expect(() => resolveUrlTarget("http://172.16.5.5", AUTHORIZED)).toThrow(
      /refusing to probe private\/loopback host/i,
    );
  });

  it("does not block a 172.x address outside the /12 range (172.32.0.1)", () => {
    expect(() => resolveUrlTarget("http://172.32.0.1", AUTHORIZED)).not.toThrow();
  });

  it("blocks a 192.168.0.0/16 address", () => {
    expect(() => resolveUrlTarget("http://192.168.1.1", AUTHORIZED)).toThrow(
      /refusing to probe private\/loopback host/i,
    );
  });

  it("blocks a 169.254.0.0/16 link-local address", () => {
    expect(() => resolveUrlTarget("http://169.254.1.1", AUTHORIZED)).toThrow(
      /refusing to probe private\/loopback host/i,
    );
  });

  it("blocks the cloud metadata IP 169.254.169.254 specifically", () => {
    expect(() => resolveUrlTarget("http://169.254.169.254", AUTHORIZED)).toThrow(
      /refusing to probe private\/loopback host/i,
    );
  });

  it("blocks 0.0.0.0", () => {
    expect(() => resolveUrlTarget("http://0.0.0.0", AUTHORIZED)).toThrow(/refusing to probe private\/loopback host/i);
  });

  it("blocks the IPv6 loopback ::1", () => {
    expect(() => resolveUrlTarget("http://[::1]", AUTHORIZED)).toThrow(/refusing to probe private\/loopback host/i);
  });

  it("allows a public IP address", () => {
    expect(() => resolveUrlTarget("http://93.184.216.34", AUTHORIZED)).not.toThrow();
  });

  it("allows a public hostname", () => {
    expect(() => resolveUrlTarget("https://example.com", AUTHORIZED)).not.toThrow();
  });

  it("allows localhost when opts.allowPrivate is true", () => {
    const result = resolveUrlTarget("http://localhost:3000", { authorize: true, allowPrivate: true });
    expect(result.host).toBe("localhost");
  });

  it("allows 127.0.0.1 when opts.allowPrivate is true", () => {
    expect(() =>
      resolveUrlTarget("http://127.0.0.1:8080", { authorize: true, allowPrivate: true }),
    ).not.toThrow();
  });
});

describe("resolveUrlTarget — SSRF pre-flight covers alternate address forms", () => {
  it.each([
    "http://[::ffff:127.0.0.1]/",
    "http://[::ffff:a9fe:a9fe]/latest/meta-data/",
    "http://[fd00:ec2::254]/",
    "http://[fe80::1]/",
    "http://100.100.100.200/",
    "http://2130706433/",
    "http://0x7f.1/",
    "http://admin.localhost/",
  ])("blocks %s", (url) => {
    expect(() => resolveUrlTarget(url, { authorize: true })).toThrow(/private\/loopback/);
  });
});

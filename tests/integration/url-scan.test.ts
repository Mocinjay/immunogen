/**
 * Live URL screening end-to-end test.
 *
 * Calls the real, public `scan()` (src/index.ts), which routes an
 * `http(s)://` input to `scanUrl()` (src/web/scan-url.ts). Since `scan()`'s
 * public signature takes no `deps` parameter, network isolation here is
 * achieved by stubbing `globalThis.fetch` for the duration of each test
 * (restored in `afterEach`) — the SAME injectable-IO seam `fetchTarget`/
 * `scanUrl` themselves default to (`deps.fetch ?? fetch`), just supplied at
 * the global boundary instead of a function parameter, since `scan()` gives
 * no other way to reach it. This is the one file in this suite that stubs
 * global `fetch` rather than injecting a `deps` object directly — every
 * other web/* test (fetch-target.test.ts, scan-url.test.ts, and every
 * src/web/detectors/*.test.ts) injects `deps.fetch` explicitly instead.
 *
 * NETWORK SAFETY: `globalThis.fetch` is replaced with a `vi.fn` stub before
 * every test in this file and restored via `vi.restoreAllMocks()` in
 * `afterEach` — no test in this file ever reaches the real network.
 *
 * Three scenarios, matching the task spec:
 *   1. Vulnerable site — missing headers, ACAO:* + credentials:true, a
 *      leaked /.env with a live-looking Stripe key, a bundle secret, and an
 *      insecure session cookie. Asserts every expected ruleId fires, that
 *      matched secrets are redacted, and that the score is blocked/low.
 *   2. Clean site — every header present, every probe 404s, no bundle
 *      secrets, a fully secure cookie. Asserts zero web findings and a
 *      passing score.
 *   3. Consent gate + SSRF guard — a URL scanned without `--authorize`
 *      (`options.authorize` unset) rejects with the actionable message;
 *      a private host is refused even with `authorize: true`.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Hermetic DNS: every test hostname resolves to a public documentation-free
// address, so the SSRF guard runs for real without touching the network.
vi.mock("../../src/web/dns-resolve.js", () => ({
  resolveHostAddresses: (hostname: string) =>
    Promise.resolve(hostname.endsWith(".internal-test") ? ["10.0.0.5"] : ["93.184.216.34"]),
}));

// Guarded scans normally connect through the pinned (connect-time checked)
// fetch; route it to the stubbed global so these tests stay hermetic. The
// pin itself is covered by src/web/pinned-fetch.test.ts.
vi.mock("../../src/web/pinned-fetch.js", () => ({
  createPinnedFetch: () => (input: string | URL | Request, init?: RequestInit) => globalThis.fetch(input, init),
}));

import { scan } from "../../src/index.js";

/** Builds a fake `Response`, mirroring fetch-target.test.ts's own helper. */
function makeResponse(
  body: string,
  init: { status?: number; headers?: Record<string, string>; url?: string } = {},
): Response {
  const headers = new Headers();
  for (const [key, value] of Object.entries(init.headers ?? {})) {
    headers.set(key, value);
  }
  const response = new Response(body, { status: init.status ?? 200, headers });
  Object.defineProperty(response, "url", { value: init.url ?? "https://vulnerable.example.com/", configurable: true });
  return response;
}

const VULNERABLE_INLINE_SCRIPT_LIVE_KEY = "sk_live_4eC39HqLyjWDarjtT1zdp7dc";
const VULNERABLE_ENV_BODY = `STRIPE_SECRET_KEY=${VULNERABLE_INLINE_SCRIPT_LIVE_KEY}\nDB_PASSWORD=hunter2\n`;

/** Stubs `globalThis.fetch` with `impl` for the duration of one test. */
function stubGlobalFetch(impl: (url: string | URL, init?: RequestInit) => Promise<Response> | Response): void {
  vi.stubGlobal("fetch", vi.fn(impl));
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("scan() — live URL screening: vulnerable site (e2e)", () => {
  beforeEach(() => {
    stubGlobalFetch((url) => {
      const urlStr = url.toString();

      if (urlStr === "https://vulnerable.example.com/") {
        return makeResponse(
          '<html><body><script>window.STRIPE_PK="sk_live_4eC39HqLyjWDarjtT1zdp7dc";</script></body></html>',
          {
            headers: {
              "access-control-allow-origin": "*",
              "access-control-allow-credentials": "true",
              "set-cookie": "session_id=abc123; Path=/",
            },
            url: urlStr,
          },
        );
      }
      if (urlStr.endsWith("/.env")) {
        return makeResponse(VULNERABLE_ENV_BODY, { status: 200, url: urlStr });
      }
      // Every other probe path (git, config.json, security.txt) 404s.
      return makeResponse("not found", { status: 404, url: urlStr });
    });
  });

  it("fires WEB-HDR, WEB-CORS, WEB-EXPOSED, WEB-SEC, and WEB-COOKIE, all redacted, with a blocked/low score", async () => {
    const result = await scan("https://vulnerable.example.com", { authorize: true });

    const ruleIds = new Set(result.findings.map((f) => f.ruleId));
    expect(ruleIds.has("WEB-HDR")).toBe(true);
    expect(ruleIds.has("WEB-CORS")).toBe(true);
    expect(ruleIds.has("WEB-EXPOSED")).toBe(true);
    expect(ruleIds.has("WEB-SEC")).toBe(true);
    expect(ruleIds.has("WEB-COOKIE")).toBe(true);

    // The CORS finding must be HIGH (wildcard + credentials:true combination).
    const corsFinding = result.findings.find((f) => f.ruleId === "WEB-CORS");
    expect(corsFinding?.severity).toBe("HIGH");

    // The /.env leak must be CRITICAL (corroborated by the KEY= snippet).
    const envFinding = result.findings.find((f) => f.ruleId === "WEB-EXPOSED" && f.file.endsWith("/.env"));
    expect(envFinding?.severity).toBe("CRITICAL");

    // Every finding's matchedText/message must never contain the raw live secret.
    for (const finding of result.findings) {
      expect(finding.matchedText ?? "").not.toContain(VULNERABLE_INLINE_SCRIPT_LIVE_KEY);
      expect(finding.message).not.toContain(VULNERABLE_INLINE_SCRIPT_LIVE_KEY);
    }
    const bundleSecretFinding = result.findings.find((f) => f.ruleId === "WEB-SEC");
    expect(bundleSecretFinding?.matchedText).toContain("REDACTED");

    expect(result.score.verdict).toBe("blocked");
    expect(result.score.score).toBeLessThanOrEqual(25);
    expect(result.llmEnriched).toBe(false);
    expect(result.target).toBe("https://vulnerable.example.com");
  });
});

describe("scan() — live URL screening: clean site (e2e)", () => {
  beforeEach(() => {
    stubGlobalFetch((url) => {
      const urlStr = url.toString();

      if (urlStr === "https://clean.example.com/") {
        return makeResponse("<html><body>Hello, world.</body></html>", {
          headers: {
            "content-security-policy": "default-src 'self'",
            "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
            "x-frame-options": "DENY",
            "x-content-type-options": "nosniff",
            "referrer-policy": "strict-origin-when-cross-origin",
            "set-cookie": "session_id=abc123; Secure; HttpOnly; SameSite=Strict; Path=/",
          },
          url: urlStr,
        });
      }
      // Every probe path 404s (clean).
      return makeResponse("not found", { status: 404, url: urlStr });
    });
  });

  it("yields zero web findings and a passing verdict", async () => {
    const result = await scan("https://clean.example.com", { authorize: true });

    expect(result.findings).toEqual([]);
    expect(result.score.verdict).toBe("pass");
    expect(result.score.score).toBeGreaterThanOrEqual(90);
    expect(result.scanIncomplete).toBe(false);
    expect(result.llmEnriched).toBe(false);
  });
});

describe("scan() — consent gate and SSRF guard (e2e)", () => {
  it("rejects a URL scanned without authorize, with the actionable message, and never calls fetch", async () => {
    const fetchSpy = vi.fn();
    stubGlobalFetch(fetchSpy as unknown as typeof fetch);

    await expect(scan("https://example.com")).rejects.toThrow(/authorization/i);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("refuses a private/loopback host even with authorize:true, and never calls fetch", async () => {
    const fetchSpy = vi.fn();
    stubGlobalFetch(fetchSpy as unknown as typeof fetch);

    await expect(scan("http://localhost", { authorize: true })).rejects.toThrow(/private|loopback/i);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("succeeds against a private host when both authorize and allowPrivate are set", async () => {
    stubGlobalFetch((url) => {
      const urlStr = url.toString();
      if (urlStr === "http://localhost/") {
        return makeResponse("<html></html>", { url: urlStr });
      }
      return makeResponse("not found", { status: 404, url: urlStr });
    });

    await expect(scan("http://localhost", { authorize: true, allowPrivate: true })).resolves.toBeDefined();
  });
});

/**
 * Live-URL screening e2e suite (Pass 2 Task 4) — exercises the real, public
 * `scan()` (src/index.ts) end to end for the `isUrl(path)` branch, proving
 * the whole pipeline (resolveUrlTarget -> fetchTarget -> exposed-file probes
 * -> WEB_DETECTORS -> computeScore) works together, not just each piece in
 * isolation.
 *
 * NETWORK SAFETY: `scan()`'s public signature does not expose a `deps`
 * parameter (that seam only exists on `scanUrl()` directly, used by
 * `src/web/scan-url.test.ts`). This suite instead stubs the GLOBAL `fetch`
 * via `vi.stubGlobal("fetch", ...)` before each test and restores it
 * afterward — `fetchTarget`'s default `deps = { fetch }` reads the global at
 * call time, so stubbing it here structurally prevents any real network
 * request from this suite, mirroring this project's other e2e suites'
 * mocked-module-boundary approach (tests/golden/golden.test.ts,
 * tests/integration/phase5-coverage.test.ts) adapted to fetch's
 * unconditional-global shape instead of a named export.
 */
import { afterEach, describe, expect, it, vi } from "vitest";

import { scan } from "../../src/index.js";

/** Builds a fake Response, mirroring src/web/fetch-target.test.ts's own helper. */
function makeResponse(
  body: string,
  init: { status?: number; headers?: Record<string, string | string[]>; url?: string } = {},
): Response {
  const headers = new Headers();
  const setCookies: string[] = [];
  for (const [key, value] of Object.entries(init.headers ?? {})) {
    if (key.toLowerCase() === "set-cookie" && Array.isArray(value)) {
      setCookies.push(...value);
      continue;
    }
    headers.set(key, Array.isArray(value) ? value.join(", ") : value);
  }

  const response = new Response(body, { status: init.status ?? 200, headers });
  Object.defineProperty(response, "url", { value: init.url ?? "https://example.com/", configurable: true });

  if (setCookies.length > 0) {
    Object.defineProperty(response.headers, "getSetCookie", {
      value: () => setCookies,
      configurable: true,
    });
  }

  return response;
}

const LIVE_STRIPE_KEY = "sk_live_51H8xyzABCDEFGHIJKLMNOP";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("scan() — vulnerable live-URL fixture (Pass 2 Task 4)", () => {
  it("fires WEB-HDR, WEB-CORS, WEB-EXPOSED, WEB-SEC, WEB-COOKIE, redacts the secret, and computes a blocked/low score", async () => {
    const fetchMock = vi.fn((url: string | URL) => {
      const urlStr = url.toString();

      if (urlStr === "https://vulnerable.example/") {
        return Promise.resolve(
          makeResponse(`<html><body><script src="/app.js"></script></body></html>`, {
            url: "https://vulnerable.example/",
            headers: {
              // No CSP, no HSTS, no X-Frame-Options, no X-Content-Type-Options, no Referrer-Policy -> WEB-HDR.
              "access-control-allow-origin": "*",
              "access-control-allow-credentials": "true", // -> WEB-CORS (HIGH)
              "set-cookie": ["session_id=abc123; Path=/"], // missing Secure + HttpOnly -> WEB-COOKIE
            },
          }),
        );
      }

      if (urlStr === "https://vulnerable.example/app.js") {
        return Promise.resolve(
          makeResponse(`const stripeKey = "${LIVE_STRIPE_KEY}";`, { url: urlStr }),
        );
      }

      if (urlStr === "https://vulnerable.example/.env") {
        return Promise.resolve(
          makeResponse("STRIPE_SECRET_KEY=sk_live_abcdefghijklmnop\n", { status: 200, url: urlStr }),
        );
      }

      // Every other probe path (.git/config, .git/HEAD, config.json, security.txt, app.js.map) 404s.
      return Promise.resolve(makeResponse("not found", { status: 404, url: urlStr }));
    });
    vi.stubGlobal("fetch", fetchMock);

    const result = await scan("https://vulnerable.example", { authorize: true });

    const ruleIds = new Set(result.findings.map((f) => f.ruleId));
    expect(ruleIds).toContain("WEB-HDR");
    expect(ruleIds).toContain("WEB-CORS");
    expect(ruleIds).toContain("WEB-EXPOSED");
    expect(ruleIds).toContain("WEB-SEC");
    expect(ruleIds).toContain("WEB-COOKIE");

    // The raw secret must never appear anywhere in the JSON-serialized result.
    const serialized = JSON.stringify(result);
    expect(serialized).not.toContain(LIVE_STRIPE_KEY);

    // A CRITICAL-bearing scan is hard-floored at a low score and a blocked verdict.
    expect(result.score.verdict).toBe("blocked");
    expect(result.score.score).toBeLessThanOrEqual(25);

    expect(result.llmEnriched).toBe(false);
  });
});

describe("scan() — clean live-URL fixture (Pass 2 Task 4)", () => {
  it("yields zero web findings and a passing/high score for a fully hardened target", async () => {
    const fetchMock = vi.fn((url: string | URL) => {
      const urlStr = url.toString();

      if (urlStr === "https://clean.example/") {
        return Promise.resolve(
          makeResponse("<html><body><script src=\"/app.js\"></script></body></html>", {
            url: "https://clean.example/",
            headers: {
              "content-security-policy": "default-src 'self'",
              "strict-transport-security": "max-age=31536000; includeSubDomains",
              "x-frame-options": "DENY",
              "x-content-type-options": "nosniff",
              "referrer-policy": "strict-origin-when-cross-origin",
              "set-cookie": ["session_id=abc123; Path=/; Secure; HttpOnly; SameSite=Strict"],
            },
          }),
        );
      }

      if (urlStr === "https://clean.example/app.js") {
        return Promise.resolve(makeResponse("console.log('no secrets here');", { url: urlStr }));
      }

      // Every probe path 404s.
      return Promise.resolve(makeResponse("not found", { status: 404, url: urlStr }));
    });
    vi.stubGlobal("fetch", fetchMock);

    const result = await scan("https://clean.example", { authorize: true });

    expect(result.findings).toEqual([]);
    expect(result.score.verdict).toBe("pass");
    expect(result.score.score).toBeGreaterThanOrEqual(70);
    expect(result.scanIncomplete).toBe(false);
  });
});

describe("scan() — consent gate (Pass 2 Task 4)", () => {
  it("rejects with an actionable authorization error when --authorize is not passed", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    await expect(scan("https://example.com", {})).rejects.toThrow(
      /Live-URL screening requires explicit authorization/i,
    );
    // The consent gate is checked BEFORE any fetch attempt.
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe("scan() — SSRF guard (Pass 2 Task 4)", () => {
  it("refuses a private/internal host even with authorize:true when allowPrivate is not set", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    await expect(scan("http://127.0.0.1", { authorize: true })).rejects.toThrow(
      /refusing to probe private\/loopback host/i,
    );
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("refuses http://localhost with authorize:true and no allowPrivate", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    await expect(scan("http://localhost:3000", { authorize: true })).rejects.toThrow(
      /refusing to probe private\/loopback host/i,
    );
  });
});

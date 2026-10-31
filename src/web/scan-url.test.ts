import { describe, expect, it, vi } from "vitest";

// Hermetic DNS: every test hostname resolves to a public documentation-free
// address, so the SSRF guard runs for real without touching the network.
vi.mock("./dns-resolve.js", () => ({
  resolveHostAddresses: (hostname: string) =>
    Promise.resolve(hostname.endsWith(".internal-test") ? ["10.0.0.5"] : ["93.184.216.34"]),
}));

import { scanUrl } from "./scan-url.js";

import type { FetchDeps } from "./fetch-target.js";

/** Builds a fake Response, mirroring fetch-target.test.ts's own helper. */
function makeResponse(
  body: string,
  init: { status?: number; headers?: Record<string, string>; url?: string } = {},
): Response {
  const headers = new Headers();
  for (const [key, value] of Object.entries(init.headers ?? {})) {
    headers.set(key, value);
  }
  const response = new Response(body, { status: init.status ?? 200, headers });
  Object.defineProperty(response, "url", { value: init.url ?? "https://example.com/", configurable: true });
  return response;
}

function makeDeps(impl: (url: string | URL, init?: RequestInit) => Promise<Response> | Response): FetchDeps {
  return { fetch: vi.fn(impl) as unknown as typeof fetch };
}

describe("scanUrl — success path", () => {
  it("returns a ScanResult with llmEnriched:false and findings from a clean healthy target", async () => {
    const deps = makeDeps((url) => {
      const urlStr = url.toString();
      if (urlStr === "https://example.com/") {
        return makeResponse("<html></html>", {
          headers: {
            "content-security-policy": "default-src 'self'",
            "strict-transport-security": "max-age=31536000",
            "x-frame-options": "DENY",
            "x-content-type-options": "nosniff",
            "referrer-policy": "strict-origin-when-cross-origin",
          },
          url: "https://example.com/",
        });
      }
      // Every probe path returns 404 (clean).
      return makeResponse("not found", { status: 404, url: urlStr });
    });

    const result = await scanUrl("https://example.com", { authorize: true }, deps);

    expect(result.target).toBe("https://example.com");
    expect(result.llmEnriched).toBe(false);
    expect(result.scanIncomplete).toBe(false);
    expect(result.findings).toEqual([]);
    expect(result.score.verdict).toBe("pass");
  });
});

describe("scanUrl — non-2xx main page marks scanIncomplete", () => {
  it("sets scanIncomplete:true when the main document returns 500", async () => {
    const deps = makeDeps((url) => {
      const urlStr = url.toString();
      if (urlStr === "https://example.com/") {
        return makeResponse("Internal Server Error", { status: 500, url: urlStr });
      }
      return makeResponse("not found", { status: 404, url: urlStr });
    });

    const result = await scanUrl("https://example.com", { authorize: true }, deps);

    expect(result.scanIncomplete).toBe(true);
  });
});

describe("scanUrl — probe failure marks scanIncomplete", () => {
  it("sets scanIncomplete:true when an exposed-file probe rejects", async () => {
    const deps = makeDeps((url) => {
      const urlStr = url.toString();
      if (urlStr === "https://example.com/") {
        return makeResponse("<html></html>", { url: urlStr });
      }
      if (urlStr.includes(".env")) {
        return Promise.reject(new Error("network error"));
      }
      return makeResponse("not found", { status: 404, url: urlStr });
    });

    const result = await scanUrl("https://example.com", { authorize: true }, deps);

    expect(result.scanIncomplete).toBe(true);
  });
});

describe("scanUrl — consent gate / SSRF propagation", () => {
  it("rejects with the actionable authorization error when authorize is not set", async () => {
    const deps = makeDeps(() => makeResponse("<html></html>"));

    await expect(scanUrl("https://example.com", {}, deps)).rejects.toThrow(/authorization/i);
  });

  it("rejects for a private host without allowPrivate", async () => {
    const deps = makeDeps(() => makeResponse("<html></html>"));

    await expect(scanUrl("http://127.0.0.1", { authorize: true }, deps)).rejects.toThrow(
      /refusing to probe private\/loopback host/i,
    );
  });

  it("never calls fetch at all when the consent gate rejects", async () => {
    const fetchSpy = vi.fn() as unknown as typeof fetch;
    const deps: FetchDeps = { fetch: fetchSpy };

    await expect(scanUrl("https://example.com", {}, deps)).rejects.toThrow();
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});

describe("scanUrl — probes do not follow redirects", () => {
  it("reports no exposure when /.env redirects to the home page", async () => {
    const deps = makeDeps((url, init) => {
      const urlStr = url.toString();
      expect(init?.redirect).toBe("manual");
      if (urlStr === "https://example.com/") {
        return makeResponse("<html></html>", { url: urlStr });
      }
      if (urlStr === "https://example.com/.env") {
        return makeResponse("", { status: 302, headers: { location: "/" }, url: urlStr });
      }
      return makeResponse("not found", { status: 404, url: urlStr });
    });

    const result = await scanUrl("https://example.com/", { authorize: true }, deps);

    expect(result.findings.filter((finding) => finding.ruleId === "WEB-EXPOSED")).toEqual([]);
    expect(result.diagnostics).toEqual([]);
  });
});

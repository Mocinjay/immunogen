import { describe, expect, it, vi } from "vitest";

import { fetchTarget } from "./fetch-target.js";

import type { FetchDeps } from "./fetch-target.js";

/**
 * Builds a fake `Response` for injection into `deps.fetch`. Never touches
 * the network — every test in this file constructs its own in-memory
 * `Response`/`Headers` pair, per the project's offline-deterministic test
 * mandate (mirrors src/detectors/deps/osv-detector.test.ts's
 * `vi.mock("./osv-client.js", ...)` pattern, adapted here to this module's
 * explicit `deps` parameter instead of a module-boundary mock).
 */
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

  const response = new Response(body, {
    status: init.status ?? 200,
    headers,
  });

  // `Response`'s `url` property is normally read-only and set by the fetch
  // implementation itself; tests need to control it directly to exercise
  // the "finalUrl" fallback/redirect-target logic.
  Object.defineProperty(response, "url", { value: init.url ?? "https://example.com/", configurable: true });

  if (setCookies.length > 0) {
    // Real undici Headers expose `getSetCookie()`; the global Headers
    // polyfill in this Node version does too, but we set it explicitly so
    // the test is not dependent on a particular Node/undici version's
    // support for multi-value set-cookie.
    Object.defineProperty(response.headers, "getSetCookie", {
      value: () => setCookies,
      configurable: true,
    });
  }

  return response;
}

function makeDeps(impl: (url: string | URL, init?: RequestInit) => Promise<Response> | Response): FetchDeps {
  return { fetch: vi.fn(impl) as unknown as typeof fetch };
}

describe("fetchTarget — header lowercasing", () => {
  it("lowercases every response header key", async () => {
    const deps = makeDeps(() => makeResponse("<html></html>", { headers: { "Content-Type": "text/html", "X-Foo": "Bar" } }));

    const result = await fetchTarget("https://example.com", {}, deps);

    expect(result.headers["content-type"]).toBe("text/html");
    expect(result.headers["x-foo"]).toBe("Bar");
    expect(Object.keys(result.headers)).not.toContain("Content-Type");
  });
});

describe("fetchTarget — body size cap", () => {
  it("truncates the main document body to maxBodyBytes", async () => {
    const bigBody = "a".repeat(1000);
    const deps = makeDeps(() => makeResponse(bigBody));

    const result = await fetchTarget("https://example.com", { maxBodyBytes: 100 }, deps);

    expect(result.body.length).toBeLessThanOrEqual(100);
    expect(result.body).toBe("a".repeat(100));
  });

  it("returns the full body when it is under the cap", async () => {
    const deps = makeDeps(() => makeResponse("hello world"));

    const result = await fetchTarget("https://example.com", { maxBodyBytes: 1024 }, deps);

    expect(result.body).toBe("hello world");
  });
});

describe("fetchTarget — same-origin script filtering + count cap", () => {
  it("follows a same-origin script and fetches its body", async () => {
    const html = `<html><body><script src="/app.js"></script></body></html>`;
    const deps = makeDeps((url) => {
      const urlStr = url.toString();
      if (urlStr === "https://example.com") {
        return makeResponse(html, { url: "https://example.com/" });
      }
      if (urlStr === "https://example.com/app.js") {
        return makeResponse("console.log('hi');", { url: urlStr });
      }
      throw new Error(`unexpected fetch: ${urlStr}`);
    });

    const result = await fetchTarget("https://example.com", {}, deps);

    expect(result.scripts).toHaveLength(1);
    expect(result.scripts[0]).toEqual({ url: "https://example.com/app.js", body: "console.log('hi');" });
  });

  it("skips a cross-origin script", async () => {
    const html = `<html><body><script src="https://evil.example/x.js"></script></body></html>`;
    const deps = makeDeps((url) => {
      const urlStr = url.toString();
      if (urlStr === "https://example.com") {
        return makeResponse(html, { url: "https://example.com/" });
      }
      throw new Error(`unexpected fetch: ${urlStr}`);
    });

    const result = await fetchTarget("https://example.com", {}, deps);

    expect(result.scripts).toHaveLength(0);
  });

  it("caps the number of scripts followed at maxScripts", async () => {
    const scriptTags = Array.from({ length: 5 }, (_, i) => `<script src="/s${String(i)}.js"></script>`).join("");
    const html = `<html><body>${scriptTags}</body></html>`;
    const fetchedScriptUrls: string[] = [];
    const deps = makeDeps((url) => {
      const urlStr = url.toString();
      if (urlStr === "https://example.com") {
        return makeResponse(html, { url: "https://example.com/" });
      }
      fetchedScriptUrls.push(urlStr);
      return makeResponse("// script", { url: urlStr });
    });

    const result = await fetchTarget("https://example.com", { maxScripts: 2 }, deps);

    expect(result.scripts).toHaveLength(2);
    expect(fetchedScriptUrls).toHaveLength(2);
  });

  it("resolves relative script src against the final document URL", async () => {
    const html = `<html><body><script src='relative.js'></script></body></html>`;
    const deps = makeDeps((url) => {
      const urlStr = url.toString();
      if (urlStr === "https://example.com/dir/page") {
        return makeResponse(html, { url: "https://example.com/dir/page" });
      }
      if (urlStr === "https://example.com/dir/relative.js") {
        return makeResponse("// relative", { url: urlStr });
      }
      throw new Error(`unexpected fetch: ${urlStr}`);
    });

    const result = await fetchTarget("https://example.com/dir/page", {}, deps);

    expect(result.scripts).toHaveLength(1);
    expect(result.scripts[0]?.url).toBe("https://example.com/dir/relative.js");
  });
});

describe("fetchTarget — a failing script fetch is skipped gracefully", () => {
  it("omits a script whose fetch rejects, without throwing", async () => {
    const html = `<html><body><script src="/ok.js"></script><script src="/broken.js"></script></body></html>`;
    const deps = makeDeps((url) => {
      const urlStr = url.toString();
      if (urlStr === "https://example.com") {
        return makeResponse(html, { url: "https://example.com/" });
      }
      if (urlStr === "https://example.com/ok.js") {
        return makeResponse("// ok", { url: urlStr });
      }
      if (urlStr === "https://example.com/broken.js") {
        return Promise.reject(new Error("network error"));
      }
      throw new Error(`unexpected fetch: ${urlStr}`);
    });

    const result = await fetchTarget("https://example.com", {}, deps);

    expect(result.scripts).toHaveLength(1);
    expect(result.scripts[0]?.url).toBe("https://example.com/ok.js");
  });

  it("omits a script whose fetch returns non-2xx", async () => {
    const html = `<html><body><script src="/missing.js"></script></body></html>`;
    const deps = makeDeps((url) => {
      const urlStr = url.toString();
      if (urlStr === "https://example.com") {
        return makeResponse(html, { url: "https://example.com/" });
      }
      return makeResponse("not found", { status: 404, url: urlStr });
    });

    const result = await fetchTarget("https://example.com", {}, deps);

    expect(result.scripts).toHaveLength(0);
  });
});

describe("fetchTarget — non-2xx main response returns partial result instead of throwing", () => {
  it("returns status/headers/body for a 500 response without throwing", async () => {
    const deps = makeDeps(() => makeResponse("Internal Server Error", { status: 500 }));

    const result = await fetchTarget("https://example.com", {}, deps);

    expect(result.status).toBe(500);
    expect(result.body).toBe("Internal Server Error");
    expect(result.scripts).toHaveLength(0);
  });

  it("does not attempt to follow scripts from a non-2xx response body", async () => {
    const html = `<html><script src="/x.js"></script></html>`;
    const deps = makeDeps((url) => {
      const urlStr = url.toString();
      if (urlStr === "https://example.com") {
        return makeResponse(html, { status: 403, url: urlStr });
      }
      throw new Error(`should not fetch scripts on a non-2xx main response: ${urlStr}`);
    });

    const result = await fetchTarget("https://example.com", {}, deps);

    expect(result.status).toBe(403);
    expect(result.scripts).toHaveLength(0);
  });
});

describe("fetchTarget — cookies", () => {
  it("surfaces raw set-cookie header values", async () => {
    const deps = makeDeps(() =>
      makeResponse("<html></html>", {
        headers: { "set-cookie": ["a=1; Path=/", "b=2; HttpOnly"] },
      }),
    );

    const result = await fetchTarget("https://example.com", {}, deps);

    expect(result.cookies).toEqual(["a=1; Path=/", "b=2; HttpOnly"]);
  });

  it("returns an empty cookies array when no set-cookie header is present", async () => {
    const deps = makeDeps(() => makeResponse("<html></html>"));

    const result = await fetchTarget("https://example.com", {}, deps);

    expect(result.cookies).toEqual([]);
  });
});

describe("fetchTarget — timeout/abort surfaced sanely", () => {
  it("propagates a rejected main-document fetch (e.g. an abort) as a thrown error, not a swallowed empty result", async () => {
    const deps = makeDeps(() => Promise.reject(new DOMException("The operation was aborted.", "AbortError")));

    await expect(fetchTarget("https://example.com", { timeoutMs: 5 }, deps)).rejects.toThrow();
  });

  it("passes an AbortSignal on the main request", async () => {
    let sawSignal: AbortSignal | undefined;
    const deps = makeDeps((_url, init) => {
      sawSignal = init?.signal ?? undefined;
      return makeResponse("<html></html>");
    });

    await fetchTarget("https://example.com", {}, deps);

    expect(sawSignal).toBeInstanceOf(AbortSignal);
  });
});

describe("fetchTarget — user agent", () => {
  it("sends a descriptive User-Agent header on the main request", async () => {
    let sawHeaders: RequestInit["headers"];
    const deps = makeDeps((_url, init) => {
      sawHeaders = init?.headers;
      return makeResponse("<html></html>");
    });

    await fetchTarget("https://example.com", {}, deps);

    const headerRecord = sawHeaders as Record<string, string>;
    expect(headerRecord["user-agent"]).toContain("immunogen/0.1");
  });
});

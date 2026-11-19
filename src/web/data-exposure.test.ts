import { describe, expect, it, vi } from "vitest";

import { extractBackendConfig, hasBackend, probeDataExposure, rowCount } from "./data-exposure.js";

import type { FetchDeps, FetchedTarget } from "./fetch-target.js";

const REF = "abcdefghijklmnopqrst";
const b64 = (value: unknown): string => Buffer.from(JSON.stringify(value)).toString("base64url");
const jwt = (payload: unknown): string => `${b64({ alg: "HS256", typ: "JWT" })}.${b64(payload)}.c2lnbmF0dXJlLXNpZ25hdHVyZQ`;
const ANON = jwt({ iss: "supabase", ref: REF, role: "anon" });
const SERVICE = jwt({ iss: "supabase", ref: REF, role: "service_role" });

function target(bundle: string): FetchedTarget {
  return { url: "https://app.example.com/", status: 200, headers: {}, body: "<html></html>", scripts: [{ url: "https://app.example.com/a.js", body: bundle }], cookies: [] };
}

describe("extractBackendConfig", () => {
  it("finds the Supabase URL, the anon key (never a service key) and the tables the client queries", () => {
    const config = extractBackendConfig(
      target(`createClient("https://${REF}.supabase.co","${SERVICE}");x="${ANON}";s.from("orders").select();s.from('profiles')`),
    );
    expect(config.supabase).toEqual({ url: `https://${REF}.supabase.co`, key: ANON });
    expect(config.tables).toEqual(["orders", "profiles"]);
  });

  it("finds a Firebase database URL, project id and Firestore collections", () => {
    const config = extractBackendConfig(
      target('const c={projectId:"my-app-123",databaseURL:"https://my-app-123-default-rtdb.europe-west1.firebasedatabase.app"};getDocs(collection(db,"users"));'),
    );
    expect(config.firebaseDatabaseUrl).toBe("https://my-app-123-default-rtdb.europe-west1.firebasedatabase.app");
    expect(config.firestoreProjectId).toBe("my-app-123");
    expect(config.collections).toEqual(["users"]);
    expect(hasBackend(config)).toBe(true);
  });

  it("finds nothing on a site without a Supabase / Firebase client", () => {
    expect(hasBackend(extractBackendConfig(target("console.log('hello')")))).toBe(false);
  });
});

describe("rowCount", () => {
  it("reads PostgREST Content-Range totals", () => {
    expect(rowCount("0-0/42")).toBe(42);
    expect(rowCount("*/0")).toBe(0);
    expect(rowCount("0-0/*")).toBeUndefined();
    expect(rowCount(null)).toBeUndefined();
  });
});

describe("probeDataExposure", () => {
  function deps(handler: (url: string, init: RequestInit) => Response): FetchDeps & { assertAllowed: ReturnType<typeof vi.fn> } {
    const assertAllowed = vi.fn(() => Promise.resolve());
    return {
      assertAllowed,
      fetch: vi.fn((input: string | URL | Request, init?: RequestInit) =>
        Promise.resolve(handler(input instanceof Request ? input.url : input.toString(), init ?? {})),
      ),
    };
  }

  it("reports a readable Supabase table from the row count alone, and skips protected or empty ones", async () => {
    const seen: string[] = [];
    const d = deps((url, init) => {
      seen.push(`${init.method ?? "GET"} ${url}`);
      if (url.endsWith("/rest/v1/")) return new Response(JSON.stringify({ paths: { "/": {}, "/invoices": {} } }), { status: 200 });
      if (url.includes("/orders")) return new Response(null, { status: 206, headers: { "content-range": "0-0/42" } });
      if (url.includes("/profiles")) return new Response(null, { status: 200, headers: { "content-range": "*/0" } });
      return new Response(null, { status: 401 });
    });
    const { findings, failed } = await probeDataExposure(
      { supabase: { url: `https://${REF}.supabase.co`, key: ANON }, tables: ["orders", "profiles"], collections: [] },
      d,
      1000,
    );
    expect(findings.map((f) => `${f.ruleId} ${f.severity} ${f.matchedText ?? ""}`)).toEqual(["WEB-DATA-01 CRITICAL orders"]);
    expect(findings[0]?.message).toContain("42 row(s)");
    expect(failed).toEqual([]);
    // Table names from the project's OpenAPI root are checked too, with HEAD only.
    expect(seen).toContain(`HEAD https://${REF}.supabase.co/rest/v1/invoices?select=*`);
    expect(seen.filter((line) => line.includes("/rest/v1/orders")).every((line) => line.startsWith("HEAD"))).toBe(true);
    expect(d.assertAllowed).toHaveBeenCalled();
  });

  it("reports an open Realtime Database and a readable Firestore collection, but not closed ones", async () => {
    const open = deps((url) =>
      url.includes("firebasedatabase")
        ? new Response('{"users":true}', { status: 200 })
        : new Response(JSON.stringify({ documents: [{ name: "projects/p/databases/(default)/documents/users/1" }] }), { status: 200 }),
    );
    const closed = deps((url) => (url.includes("firebasedatabase") ? new Response("null", { status: 200 }) : new Response("{}", { status: 403 })));
    const config = { firebaseDatabaseUrl: "https://p-default-rtdb.europe-west1.firebasedatabase.app", firestoreProjectId: "p", tables: [], collections: ["users"] };

    expect((await probeDataExposure(config, open, 1000)).findings.map((f) => f.ruleId)).toEqual(["WEB-DATA-02", "WEB-DATA-03"]);
    expect((await probeDataExposure(config, closed, 1000)).findings).toEqual([]);
  });

  it("records a probe that errors as failed instead of throwing", async () => {
    const broken: FetchDeps = { fetch: vi.fn(() => Promise.reject(new Error("boom"))) };
    const result = await probeDataExposure({ firebaseDatabaseUrl: "https://p.firebaseio.com", tables: [], collections: [] }, broken, 1000);
    expect(result).toEqual({ findings: [], failed: ["firebase-rtdb"] });
  });
});

import { afterEach, describe, expect, it, vi } from "vitest";

import { fetchVulnSeverities, queryOsvBatch } from "./osv-client.js";

afterEach(() => {
  vi.restoreAllMocks();
});

/** A fetch stub that serves OSV records by id from `records`, 404 otherwise. */
function stubFetch(records: Record<string, unknown>) {
  return vi.spyOn(globalThis, "fetch").mockImplementation((input) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    const id = decodeURIComponent(url.split("/").at(-1) ?? "");
    const record = new Map(Object.entries(records)).get(id);
    return Promise.resolve(
      record === undefined ? new Response("not found", { status: 404 }) : new Response(JSON.stringify(record), { status: 200 }),
    );
  });
}

describe("fetchVulnSeverities", () => {
  it("rates each advisory from its OSV record and caches the result", async () => {
    const fetchSpy = stubFetch({
      "GHSA-test-aaaa-0001": { database_specific: { severity: "HIGH" } },
      "PYSEC-test-0002": { severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }] },
      "GO-test-0003": { summary: "no rating" },
    });

    const first = await fetchVulnSeverities(["GHSA-test-aaaa-0001", "PYSEC-test-0002", "GO-test-0003"]);
    const second = await fetchVulnSeverities(["GHSA-test-aaaa-0001"]);

    expect([...first.entries()]).toEqual([
      ["GHSA-test-aaaa-0001", "HIGH"],
      ["PYSEC-test-0002", "CRITICAL"],
    ]);
    expect(second.get("GHSA-test-aaaa-0001")).toBe("HIGH");
    expect(fetchSpy).toHaveBeenCalledTimes(3);
  });

  it("never throws: failed lookups and malformed ids are simply left unrated", async () => {
    vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("offline"));

    await expect(fetchVulnSeverities(["GHSA-test-bbbb-0004", "../../etc/passwd", ""])).resolves.toEqual(new Map());
  });
});

describe("queryOsvBatch", () => {
  it("splits more than 1000 queries into API-sized requests and keeps results aligned", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation((_input, init) => {
      const body = JSON.parse(typeof init?.body === "string" ? init.body : "{}") as { queries: Array<{ package: { name: string } }> };
      const results = body.queries.map((query) => (query.package.name === "pkg-1200" ? { vulns: [{ id: "GHSA-1200" }] } : {}));
      return Promise.resolve(new Response(JSON.stringify({ results }), { status: 200 }));
    });
    const queries = Array.from({ length: 1500 }, (_, index) => ({ name: `pkg-${String(index)}`, version: "9.9.9-chunk-test" }));

    const results = await queryOsvBatch(queries);

    expect(fetchSpy).toHaveBeenCalledTimes(2);
    expect(results).toHaveLength(1500);
    expect(results.at(1200)).toEqual({ vulns: [{ id: "GHSA-1200" }] });
    expect(results.at(0)).toEqual({});
  });
});

describe("OSV client — transient failures and fix versions", () => {
  it("retries a querybatch that first answers 503, instead of falling back offline", async () => {
    let calls = 0;
    vi.spyOn(globalThis, "fetch").mockImplementation(() => {
      calls += 1;
      return Promise.resolve(
        calls === 1
          ? new Response("busy", { status: 503, headers: { "retry-after": "0" } })
          : new Response(JSON.stringify({ results: [{ vulns: [{ id: "GHSA-retry-0001" }] }] }), { status: 200 }),
      );
    });

    const [result] = await queryOsvBatch([{ name: "retry-pkg", version: "1.0.0" }]);

    expect(calls).toBe(2);
    expect(result?.vulns?.map((vuln) => vuln.id)).toEqual(["GHSA-retry-0001"]);
  });

  it("returns each advisory's fixed versions with its severity", async () => {
    const { fetchVulnDetails } = await import("./osv-client.js");
    stubFetch({
      "GHSA-fix-0001": {
        database_specific: { severity: "HIGH" },
        affected: [{ package: { ecosystem: "npm", name: "fixme" }, ranges: [{ events: [{ introduced: "0" }, { fixed: "2.3.1" }] }] }],
      },
    });

    const details = await fetchVulnDetails(["GHSA-fix-0001"]);

    expect(details.get("GHSA-fix-0001")).toEqual({ severity: "HIGH", fixes: [{ ecosystem: "npm", name: "fixme", fixed: ["2.3.1"] }] });
  });
});

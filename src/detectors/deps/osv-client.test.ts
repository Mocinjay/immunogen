import { afterEach, describe, expect, it, vi } from "vitest";

import { fetchVulnSeverities } from "./osv-client.js";

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

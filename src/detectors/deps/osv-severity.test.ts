import { describe, expect, it } from "vitest";

import { cvss3BaseScore, severityForScore, severityFromOsvRecord, worstSeverity } from "./osv-severity.js";

describe("cvss3BaseScore", () => {
  // Reference scores from the FIRST CVSS v3.1 calculator.
  it.each([
    ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8],
    ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10],
    ["CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1],
    ["CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.9],
    ["CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8],
    ["CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:N/A:N", 5],
    ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0],
  ])("scores %s as %d", (vector, expected) => {
    expect(cvss3BaseScore(vector)).toBe(expected);
  });

  it("rejects malformed and non-v3 vectors", () => {
    expect(cvss3BaseScore("AV:N/AC:L/Au:N/C:P/I:P/A:P")).toBeUndefined();
    expect(cvss3BaseScore("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")).toBeUndefined();
    expect(cvss3BaseScore("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")).toBeUndefined();
  });
});

describe("severityForScore", () => {
  it("bands scores like the CVSS qualitative scale", () => {
    expect([9.0, 8.9, 7.0, 6.9, 4.0, 3.9, 0.1, 0].map(severityForScore)).toEqual([
      "CRITICAL",
      "HIGH",
      "HIGH",
      "MEDIUM",
      "MEDIUM",
      "LOW",
      "LOW",
      undefined,
    ]);
  });
});

describe("severityFromOsvRecord", () => {
  it("prefers GitHub's database severity (MODERATE -> MEDIUM)", () => {
    expect(
      severityFromOsvRecord({
        database_specific: { severity: "MODERATE" },
        severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }],
      }),
    ).toBe("MEDIUM");
  });

  it("falls back to scoring a CVSS v3 vector", () => {
    expect(severityFromOsvRecord({ severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }] })).toBe(
      "CRITICAL",
    );
  });

  it("returns undefined for records without a usable rating", () => {
    expect(severityFromOsvRecord({ severity: [{ type: "CVSS_V4", score: "CVSS:4.0/AV:N" }] })).toBeUndefined();
    expect(severityFromOsvRecord({ database_specific: { severity: "UNKNOWN" } })).toBeUndefined();
    expect(severityFromOsvRecord(null)).toBeUndefined();
    expect(severityFromOsvRecord("nope")).toBeUndefined();
  });
});

describe("worstSeverity", () => {
  it("picks the most severe", () => {
    expect(worstSeverity(["LOW", "CRITICAL", "MEDIUM"])).toBe("CRITICAL");
    expect(worstSeverity([])).toBeUndefined();
  });
});

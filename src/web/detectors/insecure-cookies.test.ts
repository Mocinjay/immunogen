import { describe, expect, it } from "vitest";

import { insecureCookiesDetector } from "./insecure-cookies.js";

import type { FetchedTarget } from "../fetch-target.js";
import type { WebContext } from "../types.js";

function makeTarget(cookies: string[]): FetchedTarget {
  return {
    url: "https://example.com/",
    status: 200,
    headers: {},
    body: "<html></html>",
    scripts: [],
    cookies,
  };
}

function makeCtx(cookies: string[]): WebContext {
  return { target: makeTarget(cookies), probes: [] };
}

describe("insecureCookiesDetector — WEB-COOKIE (vulnerable)", () => {
  it("flags a session cookie missing Secure and HttpOnly with two MEDIUM findings", () => {
    const findings = insecureCookiesDetector.detect(makeCtx(["session_id=abc123; Path=/; SameSite=Lax"]));

    expect(findings).toHaveLength(2);
    for (const finding of findings) {
      expect(finding.ruleId).toBe("WEB-COOKIE");
      expect(finding.severity).toBe("MEDIUM");
    }
  });

  it("flags a session cookie with no SameSite attribute as LOW", () => {
    const findings = insecureCookiesDetector.detect(makeCtx(["auth_token=xyz; Secure; HttpOnly"]));

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ ruleId: "WEB-COOKIE", severity: "LOW" });
  });

  it("flags all three attributes missing on a completely bare session cookie", () => {
    const findings = insecureCookiesDetector.detect(makeCtx(["sid=deadbeef"]));

    expect(findings).toHaveLength(3);
    const severities = findings.map((f) => f.severity).sort();
    expect(severities).toEqual(["LOW", "MEDIUM", "MEDIUM"]);
  });
});

describe("insecureCookiesDetector — WEB-COOKIE (clean)", () => {
  it("yields zero findings for a session cookie with Secure, HttpOnly, and SameSite=Strict", () => {
    const findings = insecureCookiesDetector.detect(makeCtx(["session=abc123; Secure; HttpOnly; SameSite=Strict"]));

    expect(findings).toEqual([]);
  });

  it("ignores a non-session-shaped cookie name entirely, even with no attributes", () => {
    const findings = insecureCookiesDetector.detect(makeCtx(["cookie_consent=accepted"]));

    expect(findings).toEqual([]);
  });

  it("yields zero findings when there are no cookies at all", () => {
    expect(insecureCookiesDetector.detect(makeCtx([]))).toEqual([]);
  });
});

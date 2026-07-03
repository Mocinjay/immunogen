import { describe, expect, it } from "vitest";

import { securityHeadersDetector } from "./security-headers.js";

import type { FetchedTarget } from "../fetch-target.js";
import type { WebContext } from "../types.js";

/** Builds a minimal FetchedTarget for a given status/headers/url, with empty scripts/cookies. */
function makeTarget(headers: Record<string, string>, url = "https://example.com/", status = 200): FetchedTarget {
  return { url, status, headers, body: "<html></html>", scripts: [], cookies: [] };
}

function makeCtx(target: FetchedTarget): WebContext {
  return { target, probes: [] };
}

const ALL_HEADERS_PRESENT: Record<string, string> = {
  "content-security-policy": "default-src 'self'",
  "strict-transport-security": "max-age=31536000; includeSubDomains",
  "x-frame-options": "DENY",
  "x-content-type-options": "nosniff",
  "referrer-policy": "strict-origin-when-cross-origin",
};

describe("securityHeadersDetector — WEB-HDR (vulnerable)", () => {
  it("flags all five headers as missing on a bare 2xx https response with no headers", () => {
    const findings = securityHeadersDetector.detect(makeCtx(makeTarget({})));

    expect(findings.length).toBe(5);
    for (const finding of findings) {
      expect(finding.ruleId).toBe("WEB-HDR");
      expect(finding.category).toBe("web");
    }

    const cspFinding = findings.find((f) => f.matchedText?.includes("content-security-policy"));
    expect(cspFinding?.severity).toBe("HIGH");

    const hstsFinding = findings.find((f) => f.matchedText?.includes("strict-transport-security"));
    expect(hstsFinding?.severity).toBe("HIGH");

    const xfoFinding = findings.find((f) => f.matchedText?.includes("x-frame-options"));
    expect(xfoFinding?.severity).toBe("MEDIUM");

    const xctoFinding = findings.find((f) => f.matchedText?.includes("x-content-type-options"));
    expect(xctoFinding?.severity).toBe("MEDIUM");

    const referrerFinding = findings.find((f) => f.matchedText?.includes("referrer-policy"));
    expect(referrerFinding?.severity).toBe("LOW");
  });

  it("does NOT flag missing HSTS on a plain http:// target (scheme-gated)", () => {
    const findings = securityHeadersDetector.detect(
      makeCtx(makeTarget({ "content-security-policy": "default-src 'self'" }, "http://example.com/")),
    );

    expect(findings.some((f) => f.matchedText?.includes("strict-transport-security"))).toBe(false);
  });

  it("does not fire at all on a non-2xx main response (e.g. 404)", () => {
    const findings = securityHeadersDetector.detect(makeCtx(makeTarget({}, "https://example.com/", 404)));

    expect(findings).toEqual([]);
  });
});

describe("securityHeadersDetector — WEB-HDR (clean)", () => {
  it("yields zero findings when all five headers are present on an https 2xx response", () => {
    const findings = securityHeadersDetector.detect(makeCtx(makeTarget(ALL_HEADERS_PRESENT)));

    expect(findings).toEqual([]);
  });
});
